package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/config"
	"github.com/redstone/customapi/internal/metering"
	"github.com/redstone/customapi/internal/policy"
	"github.com/redstone/customapi/internal/protocol"
)

// ---------------------------------------------------------------------------
// Failover
// ---------------------------------------------------------------------------

// failureClass maps a transport or status failure onto the retry vocabulary
// used by routing.retry_on.
//
// body may be nil, in which case only the status is available. When the body is
// present it is consulted for one specific case: a 4xx that means "this
// provider cannot serve anyone right now" rather than "this request is
// invalid". Exhausted credit is exactly that - the caller's request is fine,
// this provider is out of money - and it must move to the next provider, which
// is the whole reason several providers are configured.
func failureClass(status int, err error, body []byte) string {
	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
			return "timeout"
		}
		return "network"
	}
	switch {
	case status == http.StatusTooManyRequests:
		return "429"
	case status >= 500:
		return "5xx"
	case status == http.StatusForbidden, status == http.StatusPaymentRequired:
		// 403 is normally deliberate and terminal (a bad key, a banned model),
		// and retrying it everywhere would multiply failures across providers.
		// It is retryable only when the provider says the reason is its own
		// account state, never on a bare 403.
		if providerOutOfCredit(body) {
			return "quota"
		}
		return ""
	case status >= 400:
		// Any other 4xx is the client's fault or a per-model failure; retrying
		// another provider would most likely fail the same way and would still
		// be billed when it does not.
		return ""
	}
	return ""
}

// creditProbeBytes bounds how much of a 403/402 body is read to decide whether
// the provider is out of credit. An error body is short; a provider that sends
// something enormous does not get to make the gateway read it.
const creditProbeBytes = 8192

// providerOutOfCredit reports whether an error body says the provider's own
// account cannot pay for the request.
//
// The check is deliberately narrow and text-based: these bodies come from
// aggregators running software this project does not control, and the field
// names differ (new-api uses code "insufficient_user_quota", others say
// "insufficient_quota", "exceeded your current quota", or "余额不足"). A false
// positive costs one wasted attempt on the next provider; a false negative
// means a dead provider is never skipped, which is the failure the operator
// actually notices.
func providerOutOfCredit(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	// Only scan a bounded prefix: an error body is short, and this runs on the
	// request path.
	if len(body) > 4096 {
		body = body[:4096]
	}
	text := strings.ToLower(string(body))
	for _, marker := range []string{
		"insufficient_user_quota",
		"insufficient_quota",
		"insufficient balance",
		"insufficient_balance",
		"insufficient credit",
		"no credit",
		"exceeded your current quota",
		"quota exhausted",
		"credit_limit",
		"余额不足",
		"预扣费额度失败",
		"余额为",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// switchChannel moves the context to the next candidate after a failure.
//
// It returns false when no further attempt should be made. Every attempt is a
// real upstream call that may be billed, so the attempt budget is honoured
// strictly.
func (s *Server) switchChannel(pc *proxyContext, attempt int) bool {
	pol := s.Config().Routing
	if attempt >= pol.Attempts() {
		return false
	}
	// Find the current channel in the ranking and take the next one that has
	// not been tried yet.
	next := -1
	for i, c := range pc.ranked {
		if c.Channel.Name == pc.channel.Name {
			if i+1 < len(pc.ranked) {
				next = i + 1
			}
			break
		}
	}
	if next < 0 {
		return false
	}
	cand := pc.ranked[next]
	if pc.tried == nil {
		pc.tried = map[string]bool{}
	}
	// Skip anything already attempted, so a degraded channel revisited by the
	// ranker cannot cause a loop.
	for next < len(pc.ranked) && pc.tried[pc.ranked[next].Channel.Name] {
		next++
	}
	if next >= len(pc.ranked) {
		return false
	}
	cand = pc.ranked[next]

	if pc.tried == nil {
		pc.tried = map[string]bool{}
	}
	pc.tried[pc.channel.Name] = true

	previous := pc.channel.Name
	pc.channel = cand.Channel
	pc.upstreamModel = cand.UpstreamModel
	// The channel identity is part of the audit record and it must follow the
	// switch: a record naming the channel that answered while naming the
	// provider that failed is worse than useless when the question is "which
	// provider do I stop paying for?". Deriving it here rather than at
	// selection time is what keeps the two in step.
	pc.provider, pc.key = providerOf(s.Config(), pc.channel.Name)
	pc.failoverNote = fmt.Sprintf("failed over from %q to %q after attempt %d", previous, cand.Channel.Name, attempt)
	s.log.Info("channel failover", "id", pc.id, "from", previous, "to", cand.Channel.Name, "attempt", attempt+1)

	// The new channel may speak a different protocol, so the body has to be
	// re-derived from the original request rather than reused.
	if err := s.rebuildForwardBody(pc); err != nil {
		return false
	}
	return true
}

// rebuildForwardBody recomputes the forwarded body for the current channel,
// applying model renaming and any required protocol translation.
func (s *Server) rebuildForwardBody(pc *proxyContext) error {
	body := pc.body
	upstreamProtocol := channelProtocol(pc.channel)

	// Step 1: bring the payload into the protocol the channel speaks.
	//
	// The router has already decided that this channel may serve the request:
	// either it speaks the client's protocol, or it declared the surface (in
	// which case sending the body unchanged is the whole point of the
	// declaration), or conversion is permitted. So the payload is converted
	// whenever the two protocols differ, and a request that cannot be expressed
	// in the target protocol fails here with a 400 naming the field rather than
	// being forwarded in a shape the upstream will misread.
	if upstreamProtocol == pc.protocol {
		pc.translated = false
		pc.upstreamProtocol = upstreamProtocol
	} else if pc.channel.DeclaresProtocol(pc.protocol) {
		// The provider serves this surface itself, so the body is already in
		// the right shape. Nothing to convert, and nothing to present back.
		pc.translated = false
		pc.upstreamProtocol = pc.protocol
	} else {
		if !s.Config().Routing.TranslationAllowed() {
			return fmt.Errorf("channel %q speaks %s but the request is %s, and translation is disabled",
				pc.channel.Name, upstreamProtocol, pc.protocol)
		}
		translated, err := protocol.TranslateRequestBody(pc.protocol, upstreamProtocol, body)
		if err != nil {
			return err
		}
		body = translated
		pc.translated = true
		pc.upstreamProtocol = upstreamProtocol
	}

	// Step 2: rename the model in place, on whichever body shape we now hold.
	if pc.upstreamModel != "" && pc.upstreamModel != pc.canonical {
		body = protocol.ReplaceTopLevelString(body, "model", pc.upstreamModel)
	}
	pc.forwardBody = body
	return nil
}

// channelProtocol resolves the wire protocol a channel speaks.
func channelProtocol(ch config.Channel) string {
	if ch.Protocol == "" {
		return "openai"
	}
	return ch.Protocol
}

// ---------------------------------------------------------------------------
// Per-protocol request preparation
// ---------------------------------------------------------------------------

// prepareRequest parses the client body for its protocol, recounts the prompt
// and builds the outbound audit payload.
func (s *Server) prepareRequest(pc *proxyContext) error {
	switch pc.protocol {
	case "anthropic":
		var req protocol.AnthropicRequest
		if err := json.Unmarshal(pc.body, &req); err != nil {
			return &routeError{status: http.StatusBadRequest, code: "invalid_request", msg: "malformed JSON body"}
		}
		pc.promptTokens, pc.tokenizerFamily = metering.CountRequestAnthropic(pc.canonical, &req)
	case "responses":
		var req protocol.ResponsesRequest
		if err := json.Unmarshal(pc.body, &req); err != nil {
			return &routeError{status: http.StatusBadRequest, code: "invalid_request", msg: "malformed JSON body"}
		}
		pc.promptTokens, pc.tokenizerFamily = metering.CountRequestResponses(pc.canonical, &req)
		// Server-side conversation state means the gateway cannot see the whole
		// prompt, so its recount and its input audit would both be partial.
		// Record it rather than let that pass silently.
		if req.UsesServerState() {
			pc.serverState = true
		}
	default:
		var req protocol.ChatRequest
		if err := json.Unmarshal(pc.body, &req); err != nil {
			return &routeError{status: http.StatusBadRequest, code: "invalid_request", msg: "malformed JSON body"}
		}
		pc.promptTokens, pc.tokenizerFamily = metering.CountRequest(pc.canonical, &req)
	}
	return nil
}

// buildInspectRequestFor extracts the outbound audit surface for the protocol.
func (s *Server) buildInspectRequestFor(pc *proxyContext) *policy.InspectRequest {
	trusted := pc.user.TrustLevel() == config.TrustTrusted
	base := &policy.InspectRequest{
		Protocol: pc.protocol, Model: pc.canonical, Actor: pc.user.Name, Trusted: trusted,
	}
	switch pc.protocol {
	case "anthropic":
		var req protocol.AnthropicRequest
		if err := json.Unmarshal(pc.body, &req); err != nil {
			return base
		}
		return policy.InspectRequestFromAnthropic(pc.user.Name, pc.canonical, trusted, &req)
	case "responses":
		var req protocol.ResponsesRequest
		if err := json.Unmarshal(pc.body, &req); err != nil {
			return base
		}
		out := &policy.InspectRequest{
			Protocol: "responses", Model: pc.canonical, Actor: pc.user.Name, Trusted: trusted,
		}
		for _, item := range req.InputText() {
			out.Text = append(out.Text, policy.Labelled(item.Field, item.Text))
		}
		out.Tools = req.ToolNames()
		// Tool schemas are part of the prompt and can carry dangerous paths, so
		// they go through the same argument rules as the chat path.
		for i, t := range req.Tools {
			if schema := t.ToolSchema(); len(schema) > 0 {
				out.ToolArgs = append(out.ToolArgs,
					policy.Labelled(fmt.Sprintf("tools[%d].parameters", i), string(schema)))
			}
		}
		return out
	default:
		var req protocol.ChatRequest
		if err := json.Unmarshal(pc.body, &req); err != nil {
			return base
		}
		return policy.InspectRequestFromOpenAI(pc.user.Name, pc.canonical, trusted, &req)
	}
}

// ---------------------------------------------------------------------------
// Per-protocol inbound inspection and metering
// ---------------------------------------------------------------------------

// inspectInboundFor runs the response-side audit for the protocol the upstream
// actually replied in.
func (s *Server) inspectInboundFor(pc *proxyContext, body []byte) {
	trusted := pc.channel.TrustLevel() == config.TrustTrusted
	// The reply is presented in the client's protocol before it is inspected, so
	// the rules always see the shape the user will receive. That holds whether
	// the protocol difference was bridged by conversion or by the provider
	// serving the client's surface itself - a client that asked for Responses
	// must not be handed a chat body just because the provider happened to
	// prefer chat.
	if pc.replyNeedsConversion() {
		converted, err := protocol.TranslateResponseBody(pc.upstreamProtocol, pc.protocol, body)
		if err == nil {
			body = converted
		} else {
			s.log.Warn("response translation failed", "id", pc.id,
				"from", pc.upstreamProtocol, "to", pc.protocol, "err", err)
		}
	}
	switch pc.protocol {
	case "anthropic":
		var pr protocol.AnthropicResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			pc.inboundDecision = s.engine.CheckInbound(&policy.InspectResponse{
				Protocol: "anthropic", Channel: pc.channel.Name, Trusted: trusted})
			return
		}
		if u := pr.Usage; u != nil {
			pc.usage.UpstreamPromptTokens = u.InputTokens + u.CacheReadInputTokens + u.CacheCreationInputTokens
			pc.usage.UpstreamCompletionTokens = u.OutputTokens
			pc.usage.UpstreamTotalTokens = pc.usage.UpstreamPromptTokens + pc.usage.UpstreamCompletionTokens
			pc.usage.UpstreamReported = true
		}
		if pr.Model != "" {
			pc.observeUpstreamModel(pr.Model)
		}
		pc.inboundDecision = s.engine.CheckInbound(
			policy.InspectResponseFromAnthropic(pc.channel.Name, trusted, &pr))
	case "responses":
		var pr protocol.ResponsesResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			pc.inboundDecision = s.engine.CheckInbound(&policy.InspectResponse{
				Protocol: "responses", Channel: pc.channel.Name, Trusted: trusted})
			return
		}
		if u := pr.Usage; u != nil {
			converted := u.ToUsage()
			pc.usage.UpstreamPromptTokens = converted.PromptTokens
			pc.usage.UpstreamCompletionTokens = converted.CompletionTokens
			pc.usage.UpstreamTotalTokens = converted.TotalTokens
			pc.usage.UpstreamReported = true
		}
		if pr.Model != "" {
			pc.observeUpstreamModel(pr.Model)
		}
		pc.inboundDecision = s.engine.CheckInbound(inspectResponses(pc.channel.Name, trusted, &pr))
	default:
		var pr protocol.ChatResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			pc.inboundDecision = s.engine.CheckInbound(&policy.InspectResponse{
				Protocol: "openai", Channel: pc.channel.Name, Trusted: trusted})
			return
		}
		if pr.Usage != nil {
			pc.usage.UpstreamPromptTokens = pr.Usage.PromptTokens
			pc.usage.UpstreamCompletionTokens = pr.Usage.CompletionTokens
			pc.usage.UpstreamTotalTokens = pr.Usage.TotalTokens
			pc.usage.UpstreamReported = true
		}
		if pr.Model != "" {
			pc.observeUpstreamModel(pr.Model)
		}
		pc.inboundDecision = s.engine.CheckInbound(
			policy.InspectResponseFromOpenAI(pc.channel.Name, trusted, &pr))
	}
	if pc.inboundDecision.Degraded {
		s.stats.Degraded.Add(1)
	}
}

// inspectResponses builds the inbound audit payload for a Responses reply.
//
// There is no constructor in the policy package for this protocol because the
// Responses shape is the only one whose function calls live in a flat output
// array rather than inside a message, so the mapping is expressed here.
func inspectResponses(channel string, trusted bool, resp *protocol.ResponsesResponse) *policy.InspectResponse {
	ir := &policy.InspectResponse{Protocol: "responses", Channel: channel, Trusted: trusted}
	if resp == nil {
		return ir
	}
	for i, item := range resp.Output {
		switch item.Type {
		case "message":
			for j, part := range item.Content {
				if part.Text != "" {
					ir.Text = append(ir.Text, policy.Labelled(
						fmt.Sprintf("output[%d].content[%d]", i, j), part.Text))
				}
			}
		case "reasoning":
			for j, part := range item.Summary {
				if part.Text != "" {
					ir.Text = append(ir.Text, policy.Labelled(
						fmt.Sprintf("output[%d].summary[%d]", i, j), part.Text))
				}
			}
		case "function_call":
			ir.ToolCalls = append(ir.ToolCalls, policy.ToolCallRequest{
				Name: item.Name, Arguments: item.Arguments, Kind: "function_call",
			})
			if item.Arguments != "" {
				ir.Text = append(ir.Text, policy.Labelled(
					fmt.Sprintf("output[%d].arguments", i), item.Arguments))
			}
		}
	}
	return ir
}

// meterResponseFor recounts the response for the protocol in use.
func (s *Server) meterResponseFor(pc *proxyContext, body []byte) {
	// Recount in the client's protocol: the number the user is charged for
	// should match the response they receive, and a translated reply may carry
	// slightly different framing from the upstream's own shape.
	measured := body
	if pc.replyNeedsConversion() {
		if converted, err := protocol.TranslateResponseBody(pc.upstreamProtocol, pc.protocol, measured); err == nil {
			measured = converted
		}
	}
	var completion int
	switch pc.protocol {
	case "anthropic":
		var pr protocol.AnthropicResponse
		if err := json.Unmarshal(measured, &pr); err == nil {
			completion = metering.CountResponseAnthropic(pc.canonical, &pr)
		}
	case "responses":
		var pr protocol.ResponsesResponse
		if err := json.Unmarshal(measured, &pr); err == nil {
			completion = metering.CountResponseResponses(pc.canonical, &pr)
		}
	default:
		var pr protocol.ChatResponse
		if err := json.Unmarshal(measured, &pr); err == nil {
			completion = metering.CountResponse(pc.canonical, &pr)
		}
	}
	pc.completionTokens = completion
	if pc.usage.UpstreamReported {
		pc.usage.Method = "upstream"
	}
	s.finalizeMetering(pc)
}

// ---------------------------------------------------------------------------
// Stream accumulation per protocol
// ---------------------------------------------------------------------------

// newStreamAccumulator builds an accumulator for the protocol the upstream is
// expected to speak.
//
// That is deliberately NOT the client's protocol: when the request was
// translated, the upstream replies in its own dialect, so the accumulator has
// to parse that dialect while the translator converts each event for the
// client. Rendering still happens in the client's shape.
func newStreamAccumulator(pc *proxyContext) streamAccumulator {
	upstream := pc.upstreamProtocol
	if upstream == "" {
		upstream = channelProtocol(pc.channel)
	}
	switch upstream {
	case "responses":
		return &responsesAccumulator{state: protocol.NewResponsesStreamState()}
	default:
		return &chatAccumulator{acc: protocol.NewStreamAccumulator(upstream)}
	}
}

// streamAccumulator abstracts the per-protocol streaming bookkeeping so the
// proxy's streaming loop stays protocol-agnostic.
type streamAccumulator interface {
	// Observe folds one SSE event into the accumulated state.
	Observe(ev *protocol.SSEEvent)
	// Text returns the assistant text seen so far.
	Text() string
	// Reasoning returns any chain-of-thought or reasoning summary seen so far.
	// It is accounted separately because it is generated and billed, but it is
	// not assistant-visible text.
	Reasoning() string
	// ToolCalls returns the accumulated tool calls as name/argument pairs.
	ToolCalls() []ToolCallParts
	// Model returns the model the upstream reported, if any.
	Model() string
	// Usage returns the upstream's usage claim.
	Usage() (protocol.Usage, bool)
	// Completed reports whether the stream reached a terminal event.
	Completed() bool
	// TerminalError returns a failure the stream carried, if any.
	TerminalError() *protocol.APIError
	// Render converts the accumulated stream into a JSON body for the audit
	// path, in the client's protocol.
	Render() []byte
	// Upstream is the protocol the accumulator parsed.
	Upstream() string
	// ToolCallCount reports how many tool calls were accumulated.
	ToolCallCount() int
}

// ToolCallParts is the metering-relevant part of a streamed tool call.
type ToolCallParts struct {
	Name      string
	Arguments string
}

// chatAccumulator adapts protocol.StreamAccumulator (chat and Messages).
type chatAccumulator struct{ acc *protocol.StreamAccumulator }

func (c *chatAccumulator) Upstream() string { return c.acc.Provider() }

func (c *chatAccumulator) Observe(ev *protocol.SSEEvent) { c.acc.Observe(ev) }
func (c *chatAccumulator) Text() string                  { return c.acc.Text.String() }
func (c *chatAccumulator) Reasoning() string             { return c.acc.Reasoning.String() }

func (c *chatAccumulator) ToolCalls() []ToolCallParts {
	calls := c.acc.ToolCallsInOrder()
	out := make([]ToolCallParts, 0, len(calls))
	for _, call := range calls {
		out = append(out, ToolCallParts{Name: call.Function.Name, Arguments: call.Function.Arguments})
	}
	return out
}
func (c *chatAccumulator) Model() string                 { return c.acc.Model }
func (c *chatAccumulator) ToolCallCount() int            { return len(c.acc.ToolCalls) }
func (c *chatAccumulator) Usage() (protocol.Usage, bool) { return c.acc.Usage, c.acc.HasUsage }
func (c *chatAccumulator) TerminalError() *protocol.APIError {
	return nil
}

// Completed reports whether a chat-style stream saw its terminator.
//
// Only the [DONE] sentinel is authoritative here; a finish_reason is not
// enough, because servers emit it on a chunk that may be followed by a usage
// chunk.
func (c *chatAccumulator) Completed() bool { return c.acc.SawDone }

func (c *chatAccumulator) Render() []byte { return renderStream(c.acc, "") }

// responsesAccumulator adapts protocol.ResponsesStreamState.
type responsesAccumulator struct {
	state *protocol.ResponsesStreamState
}

func (r *responsesAccumulator) Upstream() string { return "responses" }

func (r *responsesAccumulator) Observe(ev *protocol.SSEEvent) { r.state.Observe(ev) }
func (r *responsesAccumulator) Text() string                  { return r.state.Text.String() }
func (r *responsesAccumulator) Reasoning() string             { return r.state.Reasoning.String() }

func (r *responsesAccumulator) ToolCalls() []ToolCallParts {
	calls := r.state.CallsInOrder()
	out := make([]ToolCallParts, 0, len(calls))
	for _, call := range calls {
		out = append(out, ToolCallParts{Name: call.Name, Arguments: call.Arguments})
	}
	return out
}
func (r *responsesAccumulator) Model() string      { return r.state.Model }
func (r *responsesAccumulator) ToolCallCount() int { return len(r.state.Calls) }

func (r *responsesAccumulator) Usage() (protocol.Usage, bool) {
	if !r.state.HasUsage {
		return protocol.Usage{}, false
	}
	return r.state.Usage.ToUsage(), true
}

// Completed reports whether a terminal Responses event arrived.
func (r *responsesAccumulator) Completed() bool { return r.state.Terminal() }

func (r *responsesAccumulator) TerminalError() *protocol.APIError { return r.state.Error }

func (r *responsesAccumulator) Render() []byte {
	body, err := json.Marshal(r.state.AsResponse())
	if err != nil {
		return nil
	}
	return body
}

// ---------------------------------------------------------------------------
// Audit enrichment
// ---------------------------------------------------------------------------

// providerOf resolves the provider and key an audit record belongs to.
func providerOf(cfg *config.Config, channel string) (provider, key string) {
	if p, ok := cfg.ProviderByChannelName(channel); ok {
		provider = p.Name
		if rest, found := strings.CutPrefix(channel, p.Name+"/"); found {
			key = rest
		}
		return provider, key
	}
	if meta := channelMetadata(cfg, channel); meta != nil {
		return meta["provider"], meta["key"]
	}
	return "", ""
}

// channelMetadata returns a channel's metadata map, if it has one.
func channelMetadata(cfg *config.Config, channel string) map[string]string {
	for _, ch := range cfg.AllChannels() {
		if ch.Name == channel {
			return ch.Metadata
		}
	}
	return nil
}

// recordLatency stamps the audit latency breakdown, in milliseconds.
func recordLatency(pc *proxyContext) audit.Latency {
	return audit.Latency{
		Total:           time.Since(pc.start).Milliseconds(),
		OutboundAuditMS: pc.outboundNS / int64(time.Millisecond),
		InboundAuditMS:  pc.inboundNS / int64(time.Millisecond),
		UpstreamMS:      pc.upstreamMS,
		TTFBMS:          pc.ttfbMS,
	}
}

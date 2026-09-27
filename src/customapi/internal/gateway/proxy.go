package gateway

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/config"
	"github.com/redstone/customapi/internal/meter"
	"github.com/redstone/customapi/internal/metering"
	"github.com/redstone/customapi/internal/policy"
	"github.com/redstone/customapi/internal/protocol"
	"github.com/redstone/customapi/internal/route"
	"github.com/redstone/customapi/internal/store"
)

// maxBodyBytes bounds a request body. 32 MiB comfortably covers a long
// conversation with inline images.
const maxBodyBytes = 32 << 20

// usPerQuotaUnit converts a currency amount into quota units.
//
// The gateway keeps quota in integer units so that accounting is exact and
// survives JSON round-trips. new-api calls these "quota"; the convention here
// is 1 unit = 1e-6 of the catalogue currency.
const usPerQuotaUnit = 1e-6

// proxyContext carries everything the pipeline learns about one exchange.
type proxyContext struct {
	start time.Time
	id    string

	user    config.User
	channel config.Channel

	body          []byte
	forwardBody   []byte
	endpoint      string
	protocol      string
	canonical     string
	upstreamModel string
	stream        bool

	promptTokens     int
	completionTokens int
	tokenizerFamily  metering.TokenizerFamily

	// streamAcc reassembles a streamed response for auditing.
	streamAcc *protocol.StreamAccumulator
	// streamDetector inspects inbound text while it streams.
	streamDetector *policy.StreamDetector

	usage       metering.Usage
	deviation   metering.Deviation
	fingerprint audit.Fingerprint
	cost        audit.Cost

	outboundDecision policy.Decision
	inboundDecision  policy.Decision

	outboundNS int64
	inboundNS  int64
	upstreamMS int64
	ttfbMS     int64

	statusCode int
	decision   audit.Decision
	errText    string
	routeNote  string

	responseHash string
	requestHash  string

	quotaAfter int64

	// reportedModels collects the model names the upstream claimed, so a
	// substitution can be recorded even when no probe was run.
	reportedModels []string

	// ranked holds every admissible channel in preference order so a
	// transport failure can fail over to the next one.
	ranked []route.Candidate
	// tried records channels already attempted, so failover cannot loop.
	tried map[string]bool
	// attempt counts upstream calls made for this request.
	attempt int
	// failoverNote explains a channel switch in the audit record.
	failoverNote string

	// provider and key identify the credential that served the request, which
	// is what makes per-key accounting possible.
	provider string
	key      string

	// upstreamProtocol is the protocol the chosen channel speaks; translated
	// reports whether the body had to be converted to reach it.
	//
	// The two differ in one important case: a provider that declared the
	// client's protocol among its surfaces (supports=[openai, responses] with
	// protocol=openai) is sent the request unchanged, so translated is false -
	// yet the upstream still speaks a different protocol from the client, so
	// the reply must be presented in the client's shape. Every use of
	// "translated" that concerns the *reply* should ask replyNeedsConversion
	// instead; "translated" going into the audit record answers the narrower
	// question "was the request body rewritten?".
	upstreamProtocol string
	translated       bool

	// serverState records that the request depends on provider-side
	// conversation state, so the gateway can neither audit the full prompt nor
	// confirm its token count.
	serverState bool

	// acc is the per-protocol streaming accumulator.
	acc streamAccumulator
}

// handleProxy is the single entry point for every proxied endpoint.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	pc := &proxyContext{start: time.Now(), id: newRequestID(), endpoint: r.URL.Path}
	s.stats.Requests.Add(1)

	// ---------------------------------------------------------------- auth
	cfg := s.Config()
	token := bearerToken(r)
	user, ok := cfg.UserByToken(token)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid_api_key",
			"the provided API key is not valid for this gateway")
		return
	}
	pc.user = user
	if !user.IsEnabled() {
		writeJSONError(w, http.StatusForbidden, "user_suspended", "this API key is suspended")
		return
	}

	// ------------------------------------------------------- rate limiting
	if user.RateLimit > 0 && !s.allow(user) {
		writeJSONError(w, http.StatusTooManyRequests, "rate_limit_exceeded",
			"request rate limit exceeded; slow down")
		return
	}
	if user.MaxConcurrent > 0 {
		release, ok := s.acquire(user.Name, user.MaxConcurrent)
		if !ok {
			writeJSONError(w, http.StatusTooManyRequests, "concurrency_limit_exceeded",
				"too many concurrent requests for this key")
			return
		}
		defer release()
	}

	// ---------------------------------------------------------------- body
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "body_read_error", "could not read request body")
		return
	}
	if len(body) > maxBodyBytes {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "body_too_large",
			fmt.Sprintf("request body exceeds %d bytes", maxBodyBytes))
		return
	}
	pc.body = body
	s.stats.BytesIn.Add(int64(len(body)))

	// -------------------------------------------------------------- model
	pc.canonical = protocol.Model(body)
	if pc.canonical == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_model",
			"the request body must contain a model field")
		return
	}
	if !user.AllowsModel(pc.canonical) {
		writeJSONError(w, http.StatusForbidden, "model_not_allowed",
			fmt.Sprintf("model %q is not enabled for this API key", pc.canonical))
		return
	}
	pc.protocol = protocol.DetectProtocol(r.URL.Path, body)
	pc.stream = protocol.IsStreaming(body)

	// -------------------------------------------------------------- quota
	if err := s.store.Check(user, pc.canonical); err != nil {
		// A suspended key is an authorisation failure, not a rate problem;
		// only an exhausted allowance is a 429.
		status, code := http.StatusTooManyRequests, "insufficient_quota"
		if errors.Is(err, store.ErrUserSuspended) {
			status, code = http.StatusForbidden, "user_suspended"
		} else if errors.Is(err, store.ErrModelNotAllowed) {
			status, code = http.StatusForbidden, "model_not_allowed"
		}
		s.refuse(w, pc, status, code, err.Error())
		return
	}

	// ------------------------------------------ tokenize, route, audit
	if err := s.prepare(pc, r); err != nil {
		var re *routeError
		if errorsAs(err, &re) {
			s.finishAudit(pc, audit.DecisionUpstreamError, re.status, re.msg)
			writeAuditError(w, re.status, re.code, re.msg, pc.id)
			return
		}
		s.finishAudit(pc, audit.DecisionUpstreamError, http.StatusBadGateway, err.Error())
		writeJSONError(w, http.StatusBadGateway, "gateway_error", err.Error())
		return
	}

	// --------------------------------------------------- outbound policy
	if pc.outboundDecision.Blocked() {
		s.stats.BlockedOutbound.Add(1)
		s.refuse(w, pc, http.StatusForbidden, "content_policy_violation",
			s.blockMessage(pc.outboundDecision, true))
		return
	}

	// ----------------------------------------------------------- forward
	s.forward(w, r, pc)
}

// refuse meters and audits a request the gateway itself rejected.
//
// A refusal still goes through accounting. The project plan requires that
// quota deduction and audit recording are never skipped, for any subject and
// any outcome, so that the ledger is a complete record of what the gateway was
// asked to do - not just of what it forwarded. Charging one quota unit makes
// the refusal visible in a user's usage statement without pretending that
// upstream tokens were spent.
func (s *Server) refuse(w http.ResponseWriter, pc *proxyContext, status int, code, message string) {
	pc.usage.PromptTokens = pc.promptTokens
	pc.usage.TotalTokens = pc.promptTokens
	pc.usage.Family = pc.tokenizerFamily
	pc.usage.Method = "local_only"
	pc.cost = audit.Cost{Basis: "not_billed"}
	if st, err := s.store.Commit(pc.user.Name, 1, 0, "", time.Now()); err == nil {
		pc.quotaAfter = st.Remaining()
	}
	s.finishAudit(pc, audit.DecisionBlockUser, status, message)
	writeAuditError(w, status, code, message, pc.id)
}

// blockMessage builds a user-facing explanation from a decision.
func (s *Server) blockMessage(d policy.Decision, outbound bool) string {
	side := "request"
	if !outbound {
		side = "response"
	}
	if f, ok := d.Highest(); ok {
		return fmt.Sprintf("the %s was blocked by the customs gateway (rule %s, severity %s)",
			side, f.Rule, f.Severity)
	}
	return fmt.Sprintf("the %s was blocked by the customs gateway", side)
}

// ---------------------------------------------------------------------------
// Pipeline stages
// ---------------------------------------------------------------------------

// prepare runs metering, routing and outbound auditing.
func (s *Server) prepare(pc *proxyContext, r *http.Request) error {
	cfg := s.Config()

	// --- metering the request -------------------------------------------
	if err := s.prepareRequest(pc); err != nil {
		return err
	}

	// --- routing ---------------------------------------------------------
	// The token mix of *this* request determines the price, so the router
	// receives the real counts rather than an average.
	req := route.Request{
		Model:              pc.canonical,
		Tokens:             meter.Tokens{Input: int64(pc.promptTokens)},
		At:                 time.Now(),
		Unhealthy:          s.health.Unhealthy(),
		ClientProtocol:     pc.protocol,
		PreferSameProtocol: cfg.Routing.SameProtocolPreferred(),
		AllowTranslation:   cfg.Routing.TranslationAllowed(),
		Groups:             cfg.Routing.Groups,
		ExcludeProviders:   cfg.Routing.ExcludeProviders,
	}
	if pinned := pinHeaderOf(r); pinned != "" {
		req.Pin = pinned
	}
	dec, err := s.selector.Select(cfg.AllChannels(), req)
	if err != nil {
		return &routeError{status: http.StatusServiceUnavailable, code: "no_channel", msg: err.Error()}
	}
	pc.channel = dec.Chosen.Channel
	pc.upstreamModel = dec.Chosen.UpstreamModel
	pc.routeNote = dec.Reason
	// Keep the full ranked list so a transport failure can fail over.
	pc.ranked = dec.Ranked
	pc.tried = map[string]bool{pc.channel.Name: true}
	pc.provider, pc.key = providerOf(cfg, pc.channel.Name)

	// --- body construction: model rename, then translation ---------------
	if err := s.rebuildForwardBody(pc); err != nil {
		var te *protocol.TranslationError
		if errors.As(err, &te) {
			// A feature the target protocol cannot express is a client-visible
			// problem, not a gateway fault, so it gets a 400 naming the field.
			return &routeError{status: http.StatusBadRequest, code: "translation_unsupported", msg: err.Error()}
		}
		return &routeError{status: http.StatusServiceUnavailable, code: "no_channel", msg: err.Error()}
	}
	pc.requestHash = hashBytes(redactBytes(s.redactor, pc.body))

	// --- outbound policy --------------------------------------------------
	t0 := time.Now()
	ir := s.buildInspectRequestFor(pc)
	pc.outboundDecision = s.engine.CheckOutbound(ir)
	pc.outboundNS = time.Since(t0).Nanoseconds()
	if pc.outboundDecision.Degraded {
		s.stats.Degraded.Add(1)
	}
	return nil
}

// buildInspectRequest extracts the audit surface of the outgoing request.
//
// It is a thin wrapper over the protocol-aware builder so that existing callers
// and tests keep working.
func (s *Server) buildInspectRequest(pc *proxyContext) *policy.InspectRequest {
	return s.buildInspectRequestFor(pc)
}

// replyNeedsConversion reports whether the upstream's reply is in a protocol
// other than the one the client used, and therefore has to be presented in the
// client's shape before it is returned.
//
// It is not the same question as translated: a request served on a surface the
// provider declared natively travels unchanged, but its reply still arrives in
// that surface's shape.
func (pc *proxyContext) replyNeedsConversion() bool {
	return pc.upstreamProtocol != "" && pc.protocol != "" && pc.upstreamProtocol != pc.protocol
}

// routeError carries an HTTP-shaped failure out of the pipeline.
type routeError struct {
	status int
	code   string
	msg    string
}

func (e *routeError) Error() string { return e.msg }

// ---------------------------------------------------------------------------
// Upstream interaction
// ---------------------------------------------------------------------------

// buildUpstreamRequest constructs the request sent to the channel.
func (s *Server) buildUpstreamRequest(r *http.Request, pc *proxyContext) (*http.Request, error) {
	target := config.UpstreamURL(pc.channel.BaseURL, s.upstreamPath(pc))

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("gateway: bad channel base_url %q: %w", pc.channel.BaseURL, err)
	}
	if r.URL.RawQuery != "" {
		u.RawQuery = r.URL.RawQuery
	}

	ctx, _ := s.contextWithDeadline(r)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(pc.forwardBody))
	if err != nil {
		return nil, err
	}

	for k, vs := range r.Header {
		if isHopByHop(k) || isCredentialHeader(k) {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, sanitizeHeaderValue(v))
		}
	}
	// Content-Length must describe the body actually being sent. The gateway
	// rewrites the model name, so the forwarded body can differ in length from
	// what the client sent; copying the client's Content-Length would make the
	// upstream wait for bytes that never arrive. NewRequestWithContext has
	// already derived the correct value from the reader.
	req.Header.Del("Content-Length")
	req.ContentLength = int64(len(pc.forwardBody))
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	applyChannelAuth(req, pc.channel)
	for k, v := range pc.channel.Headers {
		req.Header.Set(k, sanitizeHeaderValue(v))
	}
	req.Header.Set("X-Customs-Gateway", "customapi/"+versionShort())
	return req, nil
}

// upstreamPath maps the inbound endpoint onto the surface that will serve it.
//
// Two different things can put a request on a surface other than the channel's
// preferred one:
//
//   - the provider declared the client's protocol among the surfaces it serves,
//     in which case the request goes to that endpoint unchanged;
//   - the payload was converted, in which case it must go to the endpoint that
//     accepts the converted protocol, because sending a chat body to
//     /v1/messages is simply rejected.
//
// Treating the first case as the second is what made a Responses request for an
// aggregator that declares both surfaces arrive on the chat endpoint: the body
// was correct for Responses and the URL was not.
func (s *Server) upstreamPath(pc *proxyContext) string {
	if pc.protocol != "" && pc.upstreamProtocol == "" && pc.channel.DeclaresProtocol(pc.protocol) {
		return endpointForProtocol(pc.protocol, pc.endpoint)
	}
	target := pc.upstreamProtocol
	if target == "" {
		target = channelProtocol(pc.channel)
	}
	if target == pc.protocol {
		return pc.endpoint
	}
	return endpointForProtocol(target, pc.endpoint)
}

// endpointForProtocol maps a protocol onto the endpoint that serves it.
//
// This is only consulted when the request must change surface - either because
// the provider declared a different protocol for it, or because the payload was
// converted. A request that stays on the protocol the caller used keeps the
// caller's own path, so endpoints the gateway does not model (and the legacy
// /v1/completions) are still forwarded verbatim rather than being rewritten.
func endpointForProtocol(protocol, clientPath string) string {
	switch protocol {
	case "anthropic":
		return "/v1/messages"
	case "responses":
		return "/v1/responses"
	case "openai":
		return "/v1/chat/completions"
	default:
		if clientPath != "" {
			return clientPath
		}
		return "/v1/chat/completions"
	}
}

// applyChannelAuth attaches the upstream credential.
//
// The header differs per protocol, and a provider may require both an
// Authorization bearer and an x-api-key, so the Anthropic path sets the key
// header and leaves any Authorization the caller's own provider headers
// specified alone.
func applyChannelAuth(req *http.Request, ch config.Channel) {
	if ch.APIKey == "" {
		return
	}
	if channelProtocol(ch) == "anthropic" {
		req.Header.Set("x-api-key", ch.APIKey)
		if req.Header.Get("anthropic-version") == "" {
			req.Header.Set("anthropic-version", "2023-06-01")
		}
		return
	}
	req.Header.Set("Authorization", "Bearer "+ch.APIKey)
}

// forward performs the upstream exchange and writes the client response.
//
// Failures that another candidate might survive (5xx, 429, timeout, network)
// cause a failover to the next ranked channel, up to routing.max_attempts.
// Each attempt is a real upstream call that may be billed, so the budget is
// enforced strictly and a client-side error (4xx other than 429) never retries:
// another provider would fail the same way, or would succeed and charge for a
// request the user did not want.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, pc *proxyContext) {
	pol := s.Config().Routing
	for {
		pc.attempt++
		upReq, err := s.buildUpstreamRequest(r, pc)
		if err != nil {
			s.health.Failure(pc.channel.Name)
			if s.retryAfterFailure(pc, nil, err) {
				continue
			}
			s.finishAudit(pc, audit.DecisionUpstreamError, http.StatusBadGateway, err.Error())
			writeAuditError(w, http.StatusBadGateway, "upstream_request_error", err.Error(), pc.id)
			return
		}

		upStart := time.Now()
		resp, err := s.client.Do(upReq)
		if err != nil {
			s.health.Failure(pc.channel.Name)
			s.stats.UpstreamErrors.Add(1)
			if s.retryAfterFailure(pc, nil, err) {
				continue
			}
			msg := "upstream request failed: " + upstreamErrText(err)
			s.finishAudit(pc, audit.DecisionUpstreamError, http.StatusBadGateway, msg)
			writeAuditError(w, http.StatusBadGateway, "upstream_unavailable", msg, pc.id)
			return
		}
		pc.upstreamMS = time.Since(upStart).Milliseconds()

		// A retryable status is decided before the body is consumed, so a
		// failing channel is abandoned without paying to read its error page.
		//
		// The exception is the credit case below, which cannot be classified
		// from the status alone: a 403 may mean "your key is banned" (terminal,
		// do not retry) or "this account is out of money" (move to the next
		// provider). Only the latter is worth reading a body for, so only that
		// status is read here.
		if resp.StatusCode >= 400 && pol.ShouldRetry(failureClass(resp.StatusCode, nil, nil)) {
			if s.retryAfterFailure(pc, resp, nil) {
				resp.Body.Close()
				continue
			}
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusPaymentRequired {
			// Read once, bounded, and hand the bytes to both the classifier and
			// the client - the body the client sees must be the provider's own
			// explanation, not a reconstruction.
			peek, _ := io.ReadAll(io.LimitReader(resp.Body, creditProbeBytes))
			body := io.NopCloser(io.MultiReader(bytes.NewReader(peek), resp.Body))
			if providerOutOfCredit(peek) && pol.ShouldRetry("quota") {
				if s.retryForClass(pc, "quota") {
					resp.Body.Close()
					continue
				}
			}
			resp.Body = body
		}
		s.health.Success(pc.channel.Name)
		defer resp.Body.Close()

		if pc.stream && resp.StatusCode == http.StatusOK {
			s.stats.StreamedReqs.Add(1)
			s.forwardStream(w, r, pc, resp)
			return
		}
		s.forwardBuffered(w, r, pc, resp)
		return
	}
}

// retryAfterFailure decides whether to move to the next channel.
//
// resp may be nil when the failure is a transport error; the status is then
// taken as zero and only the error is classified.
func (s *Server) retryAfterFailure(pc *proxyContext, resp *http.Response, err error) bool {
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	return s.retryForClass(pc, failureClass(status, err, nil))
}

// retryForClass moves to the next channel when the given failure class is
// retryable.
//
// It exists so a caller that has already classified a failure - the credit check
// has to read the body to know the class - does not have to reconstruct a
// response object just to have it re-derived.
func (s *Server) retryForClass(pc *proxyContext, class string) bool {
	if class == "" || !s.Config().Routing.ShouldRetry(class) {
		return false
	}
	if !s.switchChannel(pc, pc.attempt) {
		return false
	}
	// Clear per-attempt accounting so the audit record describes the attempt
	// that actually succeeded, not the sum of the failures before it.
	pc.responseHash = ""
	pc.usage = metering.Usage{}
	pc.deviation = metering.Deviation{}
	return true
}

// forwardBuffered handles a non-streaming (or failed) upstream response.
func (s *Server) forwardBuffered(w http.ResponseWriter, r *http.Request, pc *proxyContext, resp *http.Response) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		s.finishAudit(pc, audit.DecisionUpstreamError, http.StatusBadGateway, "upstream body read failed")
		writeAuditError(w, http.StatusBadGateway, "upstream_read_error", "upstream body read failed", pc.id)
		return
	}
	pc.statusCode = resp.StatusCode
	pc.responseHash = hashBytes(redactBytes(s.redactor, body))

	if resp.StatusCode >= 400 {
		s.stats.UpstreamErrors.Add(1)
		// Even a failed response is audited and metered: the upstream may
		// still bill for a partial generation.
		s.inspectInbound(pc, body)
		s.meterResponse(pc, body)
		s.finishAudit(pc, audit.DecisionUpstreamError, resp.StatusCode, upstreamStatusText(resp.StatusCode))
		copyResponseHeaders(w, resp)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return
	}

	s.inspectInbound(pc, body)
	s.meterResponse(pc, body)

	if pc.inboundDecision.Blocked() {
		s.stats.BlockedInbound.Add(1)
		msg := s.blockMessage(pc.inboundDecision, false)
		s.finishAudit(pc, audit.DecisionBlockUpstream, http.StatusBadGateway, msg)
		writeAuditError(w, http.StatusBadGateway, "upstream_content_blocked", msg, pc.id)
		return
	}

	// Present the reply in the client's protocol whenever the upstream speaks a
	// different one. The audit and metering above already ran on that view, so
	// what the user receives and what was accounted for are the same bytes.
	out := body
	if pc.replyNeedsConversion() {
		converted, cerr := protocol.TranslateResponseBody(pc.upstreamProtocol, pc.protocol, body)
		if cerr != nil {
			// A reply that cannot be converted is a gateway-side failure, not
			// something to hand to the client in the wrong shape.
			msg := fmt.Sprintf("the upstream reply could not be converted from %s to %s: %v",
				pc.upstreamProtocol, pc.protocol, cerr)
			s.finishAudit(pc, audit.DecisionUpstreamError, http.StatusBadGateway, msg)
			writeAuditError(w, http.StatusBadGateway, "translation_failed", msg, pc.id)
			return
		}
		out = converted
	}

	copyResponseHeaders(w, resp)
	// The converted body has a different length, so the upstream's
	// Content-Length would truncate or hang the client.
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	if pc.replyNeedsConversion() {
		w.Header().Set("X-Customs-Translated", pc.upstreamProtocol+"->"+pc.protocol)
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(out); err != nil {
		s.log.Debug("client write failed", "id", pc.id, "err", err)
	}
	s.stats.BytesOut.Add(int64(len(out)))
	s.finishAudit(pc, audit.DecisionAllow, resp.StatusCode, "")
}

// inspectInbound runs the response-side policy checks on a buffered body.
func (s *Server) inspectInbound(pc *proxyContext, body []byte) {
	t0 := time.Now()
	defer func() { pc.inboundNS = time.Since(t0).Nanoseconds() }()
	s.inspectInboundFor(pc, body)
}

// meterResponse recomputes usage from a buffered response body.
func (s *Server) meterResponse(pc *proxyContext, body []byte) {
	s.meterResponseFor(pc, body)
}

// finalizeMetering assembles the usage verdict, price and quota update.
func (s *Server) finalizeMetering(pc *proxyContext) {
	cfg := s.Config()
	pc.usage.PromptTokens = pc.promptTokens
	pc.usage.CompletionTokens = pc.completionTokens
	pc.usage.TotalTokens = pc.promptTokens + pc.completionTokens
	pc.usage.Family = pc.tokenizerFamily
	if pc.usage.Method == "" {
		pc.usage.Method = "local_only"
	}
	pc.deviation = pc.usage.CompareWith(cfg.Policy.Metering.Tolerance,
		cfg.Policy.Metering.MinAbsoluteDelta)
	if pc.deviation.OverThreshold {
		s.stats.OverBilled.Add(1)
		// A channel that inflates usage is untrustworthy regardless of how
		// good its price looks.
		s.selector.DegradeChannel(pc.channel.Name, route.Deviation{
			Worst: pc.deviation.Worst, OverThreshold: pc.deviation.OverThreshold,
			Direction: pc.deviation.Direction,
		})
	}

	quote := s.pricer.Quote(pc.channel.Name, pc.canonical,
		meter.Tokens{Input: int64(pc.usage.PromptTokens), Output: int64(pc.usage.CompletionTokens)},
		time.Now())
	pc.cost = audit.Cost{
		Currency:    quote.Currency,
		InputCost:   quote.InputCost,
		OutputCost:  quote.OutputCost,
		TotalCost:   quote.Cost,
		ListCost:    quote.ListCost,
		DiscountPct: quote.DiscountPct,
		Basis:       quote.Basis,
		PriceModel:  pc.canonical,
	}
	units := int64(quote.Cost / usPerQuotaUnit)
	if units < 1 {
		units = 1 // every metered request costs at least one unit
	}
	if st, err := s.store.Commit(pc.user.Name, units, quote.Cost, quote.Currency, time.Now()); err == nil {
		pc.quotaAfter = st.Remaining()
	}
}

// observeUpstreamModel records the model name an upstream claimed.
func (pc *proxyContext) observeUpstreamModel(reported string) {
	if reported == "" {
		return
	}
	if len(pc.reportedModels) < 8 {
		pc.reportedModels = append(pc.reportedModels, reported)
	}
}

// ---------------------------------------------------------------------------
// Audit finalisation
// ---------------------------------------------------------------------------

// finishAudit writes the audit record and records outcome counters.
//
// Called on every terminal path, including blocked requests, because the plan
// requires accounting and audit to be unskippable.
func (s *Server) finishAudit(pc *proxyContext, d audit.Decision, status int, errText string) {
	pc.decision = d
	if status == 0 {
		status = http.StatusOK
	}
	pc.statusCode = status
	pc.errText = errText

	rec := &audit.Record{
		ID:               pc.id,
		Time:             pc.start,
		EndTime:          time.Now(),
		Actor:            pc.user.Name,
		Channel:          pc.channel.Name,
		Provider:         pc.provider,
		Key:              pc.key,
		Model:            pc.canonical,
		UpstreamModel:    pc.upstreamModel,
		Protocol:         pc.protocol,
		UpstreamProtocol: pc.upstreamProtocol,
		Translated:       pc.translated,
		ServerState:      pc.serverState,
		Stream:           pc.stream,
		Endpoint:         pc.endpoint,
		Decision:         d,
		StatusCode:       status,
		Error:            errText,
		Usage: audit.UsageSummary{
			PromptTokens:             pc.usage.PromptTokens,
			CompletionTokens:         pc.usage.CompletionTokens,
			TotalTokens:              pc.usage.TotalTokens,
			UpstreamPromptTokens:     pc.usage.UpstreamPromptTokens,
			UpstreamCompletionTokens: pc.usage.UpstreamCompletionTokens,
			UpstreamTotalTokens:      pc.usage.UpstreamTotalTokens,
			UpstreamReported:         pc.usage.UpstreamReported,
			TokenizerFamily:          string(pc.usage.Family),
			Method:                   pc.usage.Method,
			PromptDelta:              pc.deviation.PromptDelta,
			CompletionDelta:          pc.deviation.CompletionDelta,
			Verdict:                  verdictOf(pc),
			Tolerance:                s.Config().Policy.Metering.Tolerance,
			MinAbsoluteDelta:         s.Config().Policy.Metering.MinAbsoluteDelta,
			WorstAbs:                 pc.deviation.WorstAbs,
		},
		Cost:         pc.cost,
		Fingerprint:  pc.fingerprint,
		RequestHash:  pc.requestHash,
		ResponseHash: pc.responseHash,
		RouteReason:  pc.routeNote,
		Attempts:     pc.attempt,
		FailoverNote: pc.failoverNote,
		QuotaAfter:   pc.quotaAfter,
		LatencyMS:    recordLatency(pc),
	}
	rec.OutboundFindings = toFindingRefs(pc.outboundDecision.Findings)
	rec.InboundFindings = toFindingRefs(pc.inboundDecision.Findings)
	// Samples are only ever attached to exchanges that were *allowed*
	// through. A blocked request's payload is exactly the content the audit
	// ledger must not retain, and a finding's excerpt hash is sufficient
	// evidence that a specific input was seen.
	if pc.decision != audit.DecisionBlockUser && pc.decision != audit.DecisionBlockUpstream && s.sampleWanted(pc) {
		rec.Sample = s.buildSample(pc)
	}
	if _, _, err := s.ledger.Append(rec); err != nil {
		s.log.Error("audit append failed", "id", pc.id, "err", err)
	}
}

// verdictOf classifies the usage comparison.
func verdictOf(pc *proxyContext) string {
	if !pc.usage.UpstreamReported {
		return "not_reported"
	}
	if !pc.deviation.Verifiable {
		return "not_verifiable"
	}
	if !pc.deviation.OverThreshold {
		return "consistent"
	}
	if pc.deviation.Direction == "over" {
		return "over_billed"
	}
	return "under_billed"
}

func toFindingRefs(in []policy.Finding) []audit.FindingRef {
	if len(in) == 0 {
		return nil
	}
	out := make([]audit.FindingRef, 0, len(in))
	for _, f := range in {
		out = append(out, audit.FindingRef{
			Rule:        f.Rule,
			Severity:    string(f.Severity),
			Field:       f.Field,
			ExcerptHash: f.ExcerptHash,
			TrustExempt: f.TrustExempt,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// copyResponseHeaders forwards the upstream headers that matter to clients.
func copyResponseHeaders(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, sanitizeHeaderValue(v))
		}
	}
}

// hopByHop headers must not be forwarded by a proxy.
var hopByHop = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

func isHopByHop(k string) bool { return hopByHop[strings.ToLower(k)] }

// credentialHeaders are stripped from the client request because the gateway
// substitutes the channel's own credential.
func isCredentialHeader(k string) bool {
	switch strings.ToLower(k) {
	case "authorization", "x-api-key", "api-key", "x-goog-api-key":
		return true
	}
	return false
}

func hashBytes(b []byte) string {
	sum := sha256Sum(b)
	return hex.EncodeToString(sum)
}

func redactBytes(r *policy.Redactor, b []byte) []byte {
	if r == nil || len(b) == 0 {
		return b
	}
	return []byte(r.Redact(string(b)))
}

// upstreamErrText renders a transport error without leaking query details.
func upstreamErrText(err error) string {
	var ue *url.Error
	if errorsAs(err, &ue) {
		return ue.Op + " failed: " + ue.Err.Error()
	}
	return err.Error()
}

func upstreamStatusText(code int) string {
	return "upstream returned HTTP " + strconv.Itoa(code)
}

// newRequestID makes a sortable, unique audit identifier.
func newRequestID() string {
	var b [12]byte
	now := time.Now().UTC().UnixNano()
	for i := 0; i < 8; i++ {
		b[i] = byte(now >> (8 * (7 - i)))
	}
	fillRandom(b[8:])
	return "req_" + hex.EncodeToString(b[:])
}

func versionShort() string { return "0.1" }

// pinHeader lets a client request a specific channel, which the plan requires
// so users can hand-pick a channel they trust for a given task.
const pinHeader = "X-Customs-Channel"

func pinHeaderOf(r *http.Request) string { return strings.TrimSpace(r.Header.Get(pinHeader)) }

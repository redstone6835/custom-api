package gateway

import (
	"bufio"
	"encoding/json"
	"net/http"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/config"
	"github.com/redstone/customapi/internal/meter"
	"github.com/redstone/customapi/internal/metering"
	"github.com/redstone/customapi/internal/policy"
	"github.com/redstone/customapi/internal/protocol"
)

// streamDecision is the head-of-stream verdict.
type streamDecision int

const (
	// streamLive forwards events as they arrive without buffering.
	streamLive streamDecision = iota
	// streamBufferDeep collects the whole response so a blocking rule can be
	// applied before anything reaches the client.
	streamBufferDeep
)

// forwardStream proxies a server-sent-event response.
//
// Two strategies exist because of an inherent trade-off the project plan calls
// out:
//
//   - live  - forward each event immediately for minimum latency, inspect the
//     text as it flows and abort mid-stream if a critical rule fires.
//     A match is only noticed after the offending bytes have
//     already been forwarded, so the client may see them.
//   - buffer - hold the whole response, audit it, then replay. Zero leak, but
//     the user loses streaming latency. Chosen automatically when
//     the channel is untrusted or the response side is in enforce
//     mode with a channel that has previously produced findings.
func (s *Server) forwardStream(w http.ResponseWriter, r *http.Request, pc *proxyContext, resp *http.Response) {
	mode := s.chooseStreamMode(pc)
	flusher, _ := w.(http.Flusher)

	acc := newStreamAccumulator(pc)
	det := policy.NewStreamDetector(s.engine, "stream")
	pc.acc = acc
	pc.streamDetector = det

	// A streamed reply in a foreign protocol must be rewritten event by event.
	// When the direction is not implemented, live forwarding would hand the
	// client a dialect it cannot parse, so the stream is buffered and converted
	// as a whole instead. Correctness first, latency second.
	upstream := acc.Upstream()
	var translator protocol.StreamTranslator
	if pc.protocol != upstream {
		translator = protocol.NewStreamTranslator(upstream, pc.protocol)
		if translator == nil {
			mode = streamBufferDeep
		}
	}

	if mode == streamBufferDeep {
		s.forwardStreamBuffered(w, pc, resp, acc, det)
		return
	}

	// --- live mode -------------------------------------------------------
	// The status line is committed before the first chunk is forwarded, which
	// is the whole point of live streaming: the client sees bytes as they are
	// produced. A rule that fires mid-stream therefore ends the stream with an
	// explicit error event rather than an error status.
	copyResponseHeaders(w, resp)
	w.Header().Set("X-Customs-Stream-Mode", "live")
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}

	sse := protocol.NewSSEWriter(w)
	reader := protocol.NewSSEReader(resp.Body)
	var (
		firstByte = true
		aborted   bool
		abortMsg  string
		seenText  int
	)

	for {
		ev, err := reader.Next()
		if err != nil {
			break
		}
		if firstByte {
			pc.ttfbMS = time.Since(pc.start).Milliseconds()
			firstByte = false
		}
		acc.Observe(ev)
		if full := acc.Text(); len(full) > seenText {
			// Feed only the new text: the detector keeps its own overlap
			// window so a pattern split across chunks is still caught, but
			// re-scanning the whole generation on every chunk would make a
			// long response quadratic.
			det.Observe(full[seenText:])
			seenText = len(full)
		}
		if m := protocol.DetectStreamModel(ev.Raw); m != "" {
			pc.observeUpstreamModel(m)
		}

		// Forward the event, rewritten when the client speaks a different
		// protocol from the upstream.
		out := []*protocol.SSEEvent{ev}
		if translator != nil {
			out = translator.Observe(ev)
		}
		for _, o := range out {
			if err := sse.WriteEvent(o); err != nil {
				s.log.Debug("stream write failed", "id", pc.id, "err", err)
				break
			}
			s.stats.BytesOut.Add(int64(len(o.Raw)))
		}

		// Termination is protocol-specific: chat-style streams end with the
		// [DONE] sentinel, the Responses API ends with a named terminal event.
		// The upstream's signal decides, because that is what it will send.
		if ev.IsDone() || acc.Completed() {
			break
		}
		if dec := det.Decision(); dec.Blocked() {
			aborted = true
			abortMsg = s.blockMessage(dec, false)
			pc.inboundDecision = dec
			// Terminate the stream explicitly so a well-behaved client stops
			// instead of waiting for a completion that will never arrive. The
			// [DONE] sentinel is harmless for a Responses client, which
			// ignores data it does not recognise.
			_ = sse.WriteEvent(errorEvent(abortMsg))
			_ = sse.WriteEvent(&protocol.SSEEvent{Data: []byte("[DONE]")})
			break
		}
	}

	// Flush any events the translation still owes, so a client is never left
	// waiting for a terminator the rewriter would have produced.
	if translator != nil {
		for _, o := range translator.Finish() {
			if err := sse.WriteEvent(o); err != nil {
				break
			}
		}
	}

	pc.statusCode = http.StatusOK
	pc.inboundDecision = det.Decision()
	s.meterStream(pc, acc)
	if aborted {
		s.stats.BlockedInbound.Add(1)
		s.finishAudit(pc, audit.DecisionBlockUpstream, http.StatusOK, abortMsg)
		return
	}
	s.finishAudit(pc, audit.DecisionAllow, http.StatusOK, "")
}

// forwardStreamBuffered audits a complete stream before delivering any of it.
//
// Nothing is written to the client until the whole response has been
// accumulated and inspected, which is what makes a blocking rule able to
// withhold the response with a proper error status. The cost is the loss of
// incremental delivery, so this mode is reserved for untrusted channels whose
// content rules are enforced (see chooseStreamMode).
func (s *Server) forwardStreamBuffered(w http.ResponseWriter, pc *proxyContext, resp *http.Response,
	acc streamAccumulator, det *policy.StreamDetector) {

	var (
		events    []*protocol.SSEEvent
		seenText  int
		firstByte = true
	)
	reader := protocol.NewSSEReader(resp.Body)
	for {
		ev, err := reader.Next()
		if err != nil {
			break
		}
		if firstByte {
			pc.ttfbMS = time.Since(pc.start).Milliseconds()
			firstByte = false
		}
		events = append(events, ev)
		acc.Observe(ev)
		if full := acc.Text(); len(full) > seenText {
			det.Observe(full[seenText:])
			seenText = len(full)
		}
		if m := protocol.DetectStreamModel(ev.Raw); m != "" {
			pc.observeUpstreamModel(m)
		}
	}

	pc.inboundDecision = det.Decision()
	// The rendered body is in the client's protocol, so the same non-streaming
	// audit rules apply and no protocol-specific constructor is needed here.
	full := acc.Render()
	if full != nil {
		if policyDecision := s.engine.CheckInbound(inboundFromBody(pc, full)); len(policyDecision.Findings) > len(pc.inboundDecision.Findings) {
			pc.inboundDecision = policyDecision
		}
	}
	s.meterStream(pc, acc)

	if pc.inboundDecision.Blocked() {
		s.stats.BlockedInbound.Add(1)
		msg := s.blockMessage(pc.inboundDecision, false)
		s.finishAudit(pc, audit.DecisionBlockUpstream, http.StatusBadGateway, msg)
		writeAuditError(w, http.StatusBadGateway, "upstream_content_blocked", msg, pc.id)
		return
	}

	// A buffered stream still has to reach the client in its own protocol.
	// When the direction has no event rewriter, the accumulated reply is
	// converted as a single body and delivered as one event, which is correct
	// but not incremental.
	outEvents := events
	upstream := acc.Upstream()
	if pc.protocol != upstream {
		if translator := protocol.NewStreamTranslator(upstream, pc.protocol); translator != nil {
			rewritten := make([]*protocol.SSEEvent, 0, len(events))
			for _, ev := range events {
				rewritten = append(rewritten, translator.Observe(ev)...)
			}
			rewritten = append(rewritten, translator.Finish()...)
			outEvents = rewritten
		} else {
			converted, err := protocol.TranslateResponseBody(upstream, pc.protocol, full)
			if err != nil {
				msg := "the streamed reply could not be converted: " + err.Error()
				s.finishAudit(pc, audit.DecisionUpstreamError, http.StatusBadGateway, msg)
				writeAuditError(w, http.StatusBadGateway, "translation_failed", msg, pc.id)
				return
			}
			outEvents = []*protocol.SSEEvent{{Data: converted}}
		}
	}

	copyResponseHeaders(w, resp)
	w.Header().Set("X-Customs-Stream-Mode", "buffered")
	if pc.replyNeedsConversion() {
		w.Header().Set("X-Customs-Translated", upstream+"->"+pc.protocol)
	}
	w.WriteHeader(http.StatusOK)
	sse := protocol.NewSSEWriter(w)
	for _, ev := range outEvents {
		if err := sse.WriteEvent(ev); err != nil {
			break
		}
		s.stats.BytesOut.Add(int64(len(ev.Raw)))
	}
	pc.statusCode = http.StatusOK
	s.finishAudit(pc, audit.DecisionAllow, http.StatusOK, "")
}

// inboundFromBody builds the response-side inspection payload for a rendered
// stream, so the buffered path can reuse the non-streaming inspectors.
func inboundFromBody(pc *proxyContext, body []byte) *policy.InspectResponse {
	trusted := pc.channel.TrustLevel() == config.TrustTrusted
	switch pc.protocol {
	case "anthropic":
		var pr protocol.AnthropicResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			return &policy.InspectResponse{Protocol: "anthropic", Channel: pc.channel.Name, Trusted: trusted}
		}
		return policy.InspectResponseFromAnthropic(pc.channel.Name, trusted, &pr)
	case "responses":
		var pr protocol.ResponsesResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			return &policy.InspectResponse{Protocol: "responses", Channel: pc.channel.Name, Trusted: trusted}
		}
		return inspectResponses(pc.channel.Name, trusted, &pr)
	default:
		var pr protocol.ChatResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			return &policy.InspectResponse{Protocol: "openai", Channel: pc.channel.Name, Trusted: trusted}
		}
		return policy.InspectResponseFromOpenAI(pc.channel.Name, trusted, &pr)
	}
}

// chooseStreamMode decides between live and deep-buffered streaming.
func (s *Server) chooseStreamMode(pc *proxyContext) streamDecision {
	cfg := s.Config()
	if cfg.Policy.Inbound.Mode == "report" {
		return streamLive
	}
	// Deep buffering costs latency, so it is reserved for the cases where
	// leaking a hostile response is unacceptable: an untrusted channel whose
	// content rules are enforced.
	if pc.channel.TrustLevel() != config.TrustTrusted {
		return streamBufferDeep
	}
	return streamLive
}

func modeName(m streamDecision) string {
	if m == streamBufferDeep {
		return "buffered"
	}
	return "live"
}

// renderStream serialises a chat/Messages accumulator back to a single JSON
// body so the buffered response path can reuse the non-streaming inspectors.
//
// The protocol comes from the accumulator itself rather than a parameter, so a
// caller cannot accidentally render an Anthropic stream as a chat response.
func renderStream(acc *protocol.StreamAccumulator, _ string) []byte {
	if acc.Provider() == "anthropic" {
		b, err := json.Marshal(acc.AsAnthropicResponse())
		if err != nil {
			return nil
		}
		return b
	}
	b, err := json.Marshal(acc.AsResponse())
	if err != nil {
		return nil
	}
	return b
}

// meterStream finalises metering for a streamed response.
//
// The local recount is derived from the accumulated stream, because that is the
// number the gateway can defend. When the upstream also reported usage (most do
// on the final event) the two are compared exactly as in the buffered path.
func (s *Server) meterStream(pc *proxyContext, acc streamAccumulator) {
	// The accumulator knows the real model only after the first event, so the
	// tokenizer family is chosen from what the upstream disclosed rather than
	// from the canonical name.
	model := acc.Model()
	if model == "" {
		model = pc.canonical
	}
	est := metering.NewEstimatorForModel(model)
	completion := est.Estimate(acc.Text()) + est.Estimate(acc.Reasoning())
	for _, tool := range acc.ToolCalls() {
		completion += est.Estimate(tool.Name) + est.Estimate(tool.Arguments)
	}
	if upstream, reported := acc.Usage(); reported {
		pc.usage.UpstreamPromptTokens = upstream.PromptTokens
		pc.usage.UpstreamCompletionTokens = upstream.CompletionTokens
		pc.usage.UpstreamTotalTokens = upstream.TotalTokens
		pc.usage.UpstreamReported = true
		pc.usage.Method = "stream_chunks"
	} else {
		pc.usage.Method = "local_only"
	}
	pc.completionTokens = completion
	s.finalizeMetering(pc)
}

// errorEvent builds an SSE event carrying an error payload.
func errorEvent(msg string) *protocol.SSEEvent {
	b, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"message": msg,
			"type":    "upstream_content_blocked",
			"code":    "upstream_content_blocked",
		},
	})
	return &protocol.SSEEvent{Data: b}
}

// ensure bufio stays referenced for the reader used above.
var _ = bufio.NewReader
var _ = metering.Usage{}
var _ = meter.Tokens{}
var _ = time.Now

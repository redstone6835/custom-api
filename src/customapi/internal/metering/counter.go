package metering

import (
	"encoding/json"
	"math"

	"github.com/redstone/customapi/internal/protocol"
)

// Usage is the gateway's own accounting for one exchange.
type Usage struct {
	// PromptTokens is the gateway's recount of the request side.
	PromptTokens int `json:"prompt_tokens"`
	// CompletionTokens is the gateway's recount of the response side.
	CompletionTokens int `json:"completion_tokens"`
	// TotalTokens is PromptTokens + CompletionTokens.
	TotalTokens int `json:"total_tokens"`
	// UpstreamPromptTokens is what the upstream claimed (0 when it
	// reported nothing, e.g. some streaming responses).
	UpstreamPromptTokens int `json:"upstream_prompt_tokens"`
	// UpstreamCompletionTokens is what the upstream claimed.
	UpstreamCompletionTokens int `json:"upstream_completion_tokens"`
	// UpstreamTotalTokens is the upstream's total, when reported.
	UpstreamTotalTokens int `json:"upstream_total_tokens"`
	// UpstreamReported is false when the upstream omitted usage entirely.
	UpstreamReported bool `json:"upstream_reported"`
	// Method records how the completion count was obtained:
	// "upstream" (non-streaming upstream usage), "stream_chunks"
	// (accumulated from SSE deltas) or "local_only".
	Method string `json:"method"`
	// Family is the tokenizer family used for the recount.
	Family TokenizerFamily `json:"family"`
}

// Deviation describes how far the upstream's claim is from the recount.
type Deviation struct {
	// PromptDelta and CompletionDelta are relative deviations in [-1, +inf).
	PromptDelta     float64 `json:"prompt_delta"`
	CompletionDelta float64 `json:"completion_delta"`
	// Worst is the larger absolute deviation of the two.
	Worst float64 `json:"worst"`
	// WorstAbs is the larger absolute (token-count) deviation of the two.
	WorstAbs int `json:"worst_abs"`
	// MinAbsolute is the absolute floor that was applied.
	MinAbsolute int `json:"min_absolute,omitempty"`
	// OverThreshold reports whether the deviation is both relatively beyond
	// the tolerance and absolutely beyond the floor.
	OverThreshold bool `json:"over_threshold"`
	// Verifiable is false when the upstream reported nothing to compare
	// against, in which case OverThreshold is always false.
	Verifiable bool `json:"verifiable"`
	// Direction is "over" when the upstream charged for more tokens than the
	// gateway counted (inflation), "under" when it charged fewer.
	Direction string `json:"direction,omitempty"`
}

// maxFiniteDelta bounds a relative deviation so it stays JSON-representable.
const maxFiniteDelta = 1e6

// clampFinite replaces infinities and NaNs with representable values.
func clampFinite(v float64) float64 {
	if math.IsNaN(v) {
		return 0
	}
	if math.IsInf(v, 1) {
		return maxFiniteDelta
	}
	if math.IsInf(v, -1) {
		return -maxFiniteDelta
	}
	return v
}

// absInt is an integer absolute value.
func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// relativeDelta returns (claimed-actual)/actual, guarding actual == 0.
func relativeDelta(claimed, actual int) float64 {
	if actual <= 0 {
		if claimed <= 0 {
			return 0
		}
		return math.Inf(1)
	}
	return float64(claimed-actual) / float64(actual)
}

// minAbsoluteDelta is the default absolute floor, in tokens, below which a
// deviation is treated as estimator noise rather than as evidence.
//
// Why a floor is necessary: the recount is an estimate, and for a short
// response a single token of disagreement is already a large *relative*
// deviation. A 5-token reply claimed as 8 tokens is +60%, which a purely
// relative check would call fraud. Without a floor a legitimate upstream gets
// flagged on exactly the shortest, cheapest requests - the ones most likely to
// be health checks and benchmark probes - and the integrity score becomes
// noise-driven.
const minAbsoluteDelta = 8

// Compare measures the upstream's claim against the gateway's recount.
//
// A deviation is only reported when it is BOTH beyond the relative tolerance
// and beyond the absolute floor, which is how "close enough" comparisons are
// normally implemented for quantities with a known measurement error.
func (u Usage) Compare(tolerance float64) Deviation {
	return u.CompareWith(tolerance, minAbsoluteDelta)
}

// CompareWith is Compare with an explicit absolute floor.
func (u Usage) CompareWith(tolerance float64, minAbsolute int) Deviation {
	var d Deviation
	if !u.UpstreamReported {
		return d
	}
	d.Verifiable = true
	d.MinAbsolute = minAbsolute
	// An infinite relative deviation means the upstream billed for something
	// the gateway saw no content for. It is clamped to a large finite number
	// so that the value survives JSON round-trips and downstream arithmetic;
	// an infinity here would make the audit ledger unwritable.
	d.PromptDelta = clampFinite(relativeDelta(u.UpstreamPromptTokens, u.PromptTokens))
	d.CompletionDelta = clampFinite(relativeDelta(u.UpstreamCompletionTokens, u.CompletionTokens))

	worst := math.Abs(d.PromptDelta)
	if v := math.Abs(d.CompletionDelta); v > worst {
		worst = v
	}
	promptAbs := absInt(u.UpstreamPromptTokens - u.PromptTokens)
	completionAbs := absInt(u.UpstreamCompletionTokens - u.CompletionTokens)
	worstAbs := promptAbs
	if completionAbs > worstAbs {
		worstAbs = completionAbs
	}
	d.Worst = worst
	d.WorstAbs = worstAbs
	// Two conditions, not one: a deviation is evidence only when it is large
	// in relative terms AND large in absolute terms. See minAbsoluteDelta.
	d.OverThreshold = worst > tolerance && worstAbs >= minAbsolute
	if d.OverThreshold {
		if d.CompletionDelta > 0 || d.PromptDelta > 0 {
			d.Direction = "over"
		} else {
			d.Direction = "under"
		}
	}
	return d
}

// Counter accumulates a Usage across a request/response pair.
//
// It is used both for non-streaming responses (where the whole body is
// available at once) and for SSE streams (where deltas arrive incrementally).
type Counter struct {
	est      *Estimator
	prompt   int
	comp     int
	method   string
	upstrm   protocol.Usage
	hasUp    bool
	overhead int
}

// NewCounter creates a counter for a model.
func NewCounter(model string) *Counter {
	return &Counter{est: NewEstimatorForModel(model), method: "local_only"}
}

// Family returns the tokenizer family in use.
func (c *Counter) Family() TokenizerFamily { return c.est.Family }

// AddPromptText adds one piece of request text.
func (c *Counter) AddPromptText(s string) { c.prompt += c.est.Estimate(s) }

// AddPromptTokens adds an explicit token count (e.g. upstream prompt count
// when it is the only signal available).
func (c *Counter) AddPromptTokens(n int) { c.prompt += n }

// AddCompletionText adds one piece of response text.
func (c *Counter) AddCompletionText(s string) { c.comp += c.est.Estimate(s) }

// AddOverhead accounts for protocol scaffolding (role markers, message
// separators) that real tokenizers charge for.
func (c *Counter) AddOverhead(n int) { c.overhead += n }

// SetUpstream records the usage block reported by the upstream.
func (c *Counter) SetUpstream(u protocol.Usage, present bool) {
	c.upstrm = u
	c.hasUp = present
	if present {
		c.method = "upstream"
	}
}

// MarkStreamAccumulated switches the method to stream accounting.
func (c *Counter) MarkStreamAccumulated() {
	if c.method != "upstream" {
		c.method = "stream_chunks"
	}
}

// Usage finalises the accounting.
func (c *Counter) Usage() Usage {
	prompt := c.prompt + c.overhead
	comp := c.comp
	if comp == 0 && c.hasUp && c.upstrm.CompletionTokens > 0 {
		// The response body carried no countable text (for example a
		// tool-call-only reply that the parser did not extract) but the
		// upstream did report a count; keep the upstream figure to avoid
		// manufacturing a false inflation signal.
		comp = c.upstrm.CompletionTokens
	}
	if prompt == 0 && c.hasUp && c.upstrm.PromptTokens > 0 {
		prompt = c.upstrm.PromptTokens
	}
	u := Usage{
		PromptTokens:     prompt,
		CompletionTokens: comp,
		TotalTokens:      prompt + comp,
		Method:           c.method,
		Family:           c.est.Family,
		UpstreamReported: c.hasUp,
	}
	if c.hasUp {
		u.UpstreamPromptTokens = c.upstrm.PromptTokens
		u.UpstreamCompletionTokens = c.upstrm.CompletionTokens
		if c.upstrm.TotalTokens > 0 {
			u.UpstreamTotalTokens = c.upstrm.TotalTokens
		} else {
			u.UpstreamTotalTokens = c.upstrm.PromptTokens + c.upstrm.CompletionTokens
		}
	}
	return u
}

// ---------------------------------------------------------------------------
// Request / response accounting helpers
// ---------------------------------------------------------------------------

// messageOverhead is the per-message framing cost real tokenizers add
// (role marker, separators).
const messageOverhead = 4

// CountRequest estimates the prompt tokens of an OpenAI-style chat request.
func CountRequest(model string, req *protocol.ChatRequest) (int, TokenizerFamily) {
	c := NewCounter(model)
	if req == nil {
		return 0, c.Family()
	}
	for _, m := range req.Messages {
		c.AddPromptText(m.Role)
		for _, part := range m.Content.TextAndToolInput() {
			c.AddPromptText(part)
		}
		if m.Name != "" {
			c.AddPromptText(m.Name)
		}
		for _, tc := range m.ToolCalls {
			c.AddPromptText(tc.Function.Name)
			c.AddPromptText(tc.Function.Arguments)
		}
		c.AddOverhead(messageOverhead)
	}
	for _, t := range req.Tools {
		// Tool schemas are part of the prompt and are usually the single
		// largest contributor after the messages themselves.
		raw, err := json.Marshal(t)
		if err == nil {
			c.AddOverhead(c.est.Estimate(string(raw)))
		}
	}
	if req.ResponseFormat != nil && len(req.ResponseFormat.Schema) > 0 {
		c.AddOverhead(c.est.Estimate(string(req.ResponseFormat.Schema)))
	}
	c.AddOverhead(3) // assistant priming
	return c.prompt + c.overhead, c.Family()
}

// CountRequestAnthropic estimates the prompt tokens of a Messages API request.
func CountRequestAnthropic(model string, req *protocol.AnthropicRequest) (int, TokenizerFamily) {
	c := NewCounter(model)
	if req == nil {
		return 0, c.Family()
	}
	if req.System != nil {
		for _, part := range req.System.TextAndToolInput() {
			c.AddPromptText(part)
		}
	}
	for _, m := range req.Messages {
		c.AddPromptText(m.Role)
		for _, part := range m.Content.TextAndToolInput() {
			c.AddPromptText(part)
		}
		c.AddOverhead(messageOverhead)
	}
	for _, t := range req.Tools {
		if raw, err := json.Marshal(t); err == nil {
			c.AddOverhead(c.est.Estimate(string(raw)))
		}
	}
	c.AddOverhead(3)
	return c.prompt + c.overhead, c.Family()
}

// CountResponse estimates the completion tokens of a non-streaming response.
func CountResponse(model string, resp *protocol.ChatResponse) int {
	c := NewCounter(model)
	if resp == nil {
		return 0
	}
	for _, ch := range resp.Choices {
		c.AddCompletionText(ch.Message.Content.Plain())
		c.AddCompletionText(ch.Message.ReasoningContent)
		for _, tc := range ch.Message.ToolCalls {
			c.AddCompletionText(tc.Function.Name)
			c.AddCompletionText(tc.Function.Arguments)
		}
	}
	return c.comp
}

// CountResponseAnthropic estimates completion tokens for a Messages response.
func CountResponseAnthropic(model string, resp *protocol.AnthropicResponse) int {
	c := NewCounter(model)
	if resp == nil {
		return 0
	}
	for _, blk := range resp.Content {
		switch blk.Type {
		case "text":
			c.AddCompletionText(blk.Text)
		case "thinking":
			c.AddCompletionText(blk.Thinking)
		case "tool_use":
			c.AddCompletionText(blk.Name)
			if raw, err := json.Marshal(blk.Input); err == nil {
				c.AddCompletionText(string(raw))
			}
		}
	}
	return c.comp
}

// ---------------------------------------------------------------------------
// Responses API accounting
// ---------------------------------------------------------------------------

// CountRequestResponses estimates the input tokens of a /v1/responses request.
//
// The prompt is assembled from `instructions` plus every text-bearing part of
// `input`, including function-call arguments and outputs, because all of those
// are sent to the model and are billed.
func CountRequestResponses(model string, req *protocol.ResponsesRequest) (int, TokenizerFamily) {
	c := NewCounter(model)
	if req == nil {
		return 0, c.Family()
	}
	if req.Instructions != "" {
		c.AddPromptText(req.Instructions)
	}
	for _, item := range req.InputText() {
		c.AddPromptText(item.Text)
	}
	for _, t := range req.Tools {
		if t.Description != "" {
			c.AddPromptText(t.Description)
		}
		if schema := t.ToolSchema(); len(schema) > 0 {
			c.AddOverhead(c.est.Estimate(string(schema)))
		}
	}
	// The Responses API bills a fixed framing cost per input item, similar to
	// the chat message overhead.
	c.AddOverhead(3)
	return c.prompt + c.overhead, c.Family()
}

// CountResponseResponses estimates the output tokens of a /v1/responses reply.
//
// Reasoning summaries and function-call arguments are generated tokens and are
// billed, so they count toward the completion side.
func CountResponseResponses(model string, resp *protocol.ResponsesResponse) int {
	c := NewCounter(model)
	if resp == nil {
		return 0
	}
	for _, item := range resp.Output {
		switch item.Type {
		case "message":
			for _, part := range item.Content {
				c.AddCompletionText(part.Text)
			}
		case "reasoning":
			for _, part := range item.Summary {
				c.AddCompletionText(part.Text)
			}
		case "function_call":
			c.AddCompletionText(item.Name)
			c.AddCompletionText(item.Arguments)
		}
	}
	return c.comp
}

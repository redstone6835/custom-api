package metering

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/redstone/customapi/internal/protocol"
)

// ---------------------------------------------------------------------------
// Tokenizer calibration
// ---------------------------------------------------------------------------

// TestEstimatorAccuracy checks the estimator against token counts produced by
// real tokenizers (recorded offline with tiktoken o200k_base / cl100k_base and
// the Anthropic tokenizer). The tolerance is deliberately generous because the
// estimator is an approximation; what matters for the customs check is that a
// deviation large enough to be worth an upstream's while to fake is far larger
// than the estimator's error.
func TestEstimatorAccuracy(t *testing.T) {
	cases := []struct {
		name   string
		model  string
		text   string
		actual int
	}{
		{
			name:   "english prose",
			model:  "gpt-4o",
			text:   "The quick brown fox jumps over the lazy dog. This sentence is used to test tokenizer behaviour across many implementations.",
			actual: 26,
		},
		{
			name:   "chinese prose",
			model:  "gpt-4o",
			text:   "哈希函数是一种把任意长度的输入映射为固定长度输出的函数。它在密码学和数据结构中有广泛的应用。",
			actual: 40,
		},
		{
			name:   "python code",
			model:  "gpt-4o",
			text:   "def reverse(s: str) -> str:\n    return s[::-1]\n\nif __name__ == '__main__':\n    print(reverse('hello'))\n",
			actual: 34,
		},
		{
			name:   "json payload",
			model:  "gpt-4o",
			text:   `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":0.7}`,
			actual: 22,
		},
		{
			name:   "numbers",
			model:  "gpt-4o",
			text:   "1234567890 9876543210 3.14159265358979 2.718281828459045",
			actual: 22,
		},
		{
			name:   "cl100k english",
			model:  "gpt-4",
			text:   "The quick brown fox jumps over the lazy dog. This sentence is used to test tokenizer behaviour across many implementations.",
			actual: 27,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			est := NewEstimatorForModel(tc.model)
			got := est.Estimate(tc.text)
			err := math.Abs(float64(got-tc.actual)) / float64(tc.actual)
			t.Logf("%s: estimated=%d actual=%d error=%.1f%%", tc.name, got, tc.actual, err*100)
			// 50% is the acceptance bound. The worst measured case is a
			// digit-dense string at ~46%; ordinary prose stays under 20%.
			// The bound is deliberately loose because the estimator is
			// vocabulary-free by design - what matters is that it is far
			// tighter than the deviation the metering check must catch.
			if err > 0.50 {
				t.Fatalf("estimate %d too far from actual %d (%.1f%%)", got, tc.actual, err*100)
			}
		})
	}
}

func TestEstimatorMonotonic(t *testing.T) {
	est := NewEstimatorForModel("gpt-4o")
	prev := 0
	for _, n := range []int{1, 10, 100, 1000, 10000} {
		got := est.Estimate(strings.Repeat("word ", n))
		if got < prev {
			t.Fatalf("estimate decreased with more input: %d < %d at n=%d", got, prev, n)
		}
		prev = got
	}
}

func TestEstimatorEmptyAndSmall(t *testing.T) {
	est := NewEstimatorForModel("gpt-4o")
	if got := est.Estimate(""); got != 0 {
		t.Fatalf("empty text should be 0 tokens, got %d", got)
	}
	if got := est.Estimate("a"); got < 1 {
		t.Fatalf("single character should be at least 1 token, got %d", got)
	}
	if got := est.Estimate("中"); got < 1 {
		t.Fatalf("single CJK character should be at least 1 token, got %d", got)
	}
}

// TestFamilyForModel verifies model-to-tokenizer mapping.
func TestFamilyForModel(t *testing.T) {
	cases := map[string]TokenizerFamily{
		"gpt-4o":                 FamilyO200k,
		"gpt-4o-mini":            FamilyO200k,
		"gpt-4.1":                FamilyO200k,
		"o3-mini":                FamilyO200k,
		"gpt-4":                  FamilyCl100k,
		"gpt-3.5-turbo":          FamilyCl100k,
		"text-embedding-3-small": FamilyCl100k,
		"claude-3-5-sonnet":      FamilyClaude,
		"claude-opus-4":          FamilyClaude,
		"gemini-2.0-flash":       FamilyGemini,
		"deepseek-chat":          FamilyGeneric,
		"qwen-max":               FamilyGeneric,
		"some-unknown-model":     FamilyGeneric,
	}
	for model, want := range cases {
		if got := FamilyFor(model); got != want {
			t.Fatalf("FamilyFor(%q) = %s, want %s", model, got, want)
		}
	}
}

// TestCJKCostsMoreThanLatin documents the property the metering check relies
// on: the estimator must not treat byte length as a proxy for token count.
func TestCJKCostsMoreThanLatin(t *testing.T) {
	est := NewEstimatorForModel("gpt-4o")
	latin := est.Estimate(strings.Repeat("a", 30)) // 30 bytes
	cjk := est.Estimate(strings.Repeat("中", 10))   // 30 bytes, 10 chars
	if latin >= cjk {
		t.Fatalf("CJK text (30 bytes/10 chars) should cost more tokens than Latin (30 bytes): %d vs %d", cjk, latin)
	}
}

// ---------------------------------------------------------------------------
// Request counting
// ---------------------------------------------------------------------------

func TestCountRequestBasic(t *testing.T) {
	req := &protocol.ChatRequest{
		Model: "gpt-4o",
		Messages: []protocol.ChatMessage{
			{Role: "system", Content: protocol.Content{Parts: []protocol.ContentPart{{Type: "text", Text: "You are a helpful assistant."}}}},
			{Role: "user", Content: protocol.Content{Parts: []protocol.ContentPart{{Type: "text", Text: "What is 2+2?"}}}},
		},
	}
	n, fam := CountRequest("gpt-4o", req)
	if n <= 0 {
		t.Fatalf("expected a positive prompt count, got %d", n)
	}
	if fam != FamilyO200k {
		t.Fatalf("family = %s", fam)
	}
	// Two messages plus system text should be well under 40 tokens.
	if n > 40 {
		t.Fatalf("prompt count suspiciously high: %d", n)
	}
}

func TestCountRequestNil(t *testing.T) {
	if n, _ := CountRequest("gpt-4o", nil); n != 0 {
		t.Fatalf("nil request should count 0, got %d", n)
	}
	if n, _ := CountRequestAnthropic("claude-3", nil); n != 0 {
		t.Fatalf("nil request should count 0, got %d", n)
	}
}

func TestCountRequestToolsAddTokens(t *testing.T) {
	base := &protocol.ChatRequest{
		Model:    "gpt-4o",
		Messages: []protocol.ChatMessage{{Role: "user", Content: protocol.Content{Parts: []protocol.ContentPart{{Type: "text", Text: "hi"}}}}},
	}
	withTools := &protocol.ChatRequest{
		Model:    base.Model,
		Messages: base.Messages,
		Tools: []protocol.Tool{{
			Type: "function",
			Function: protocol.ToolFunction{
				Name:        "get_weather",
				Description: "Get the current weather for a city, returning temperature, humidity and conditions.",
				Parameters:  json.RawMessage(`{"type":"object","properties":{"city":{"type":"string","description":"The city name"}},"required":["city"]}`),
			},
		}},
	}
	n1, _ := CountRequest("gpt-4o", base)
	n2, _ := CountRequest("gpt-4o", withTools)
	if n2 <= n1 {
		t.Fatalf("tool schema should increase the prompt count: %d -> %d", n1, n2)
	}
}

func TestCountRequestAnthropic(t *testing.T) {
	req := &protocol.AnthropicRequest{
		Model:     "claude-3-5-sonnet",
		MaxTokens: 100,
		System:    &protocol.Content{Parts: []protocol.ContentPart{{Type: "text", Text: "You are terse."}}},
		Messages: []protocol.AnthropicMessage{
			{Role: "user", Content: protocol.Content{Raw: json.RawMessage(`"Explain hashing."`)}},
		},
	}
	n, fam := CountRequestAnthropic("claude-3-5-sonnet", req)
	if n <= 0 {
		t.Fatalf("expected a positive count, got %d", n)
	}
	if fam != FamilyClaude {
		t.Fatalf("family = %s", fam)
	}
}

func TestCountResponse(t *testing.T) {
	resp := &protocol.ChatResponse{
		Choices: []protocol.Choice{{
			Message: protocol.ChatMessage{
				Content: protocol.Content{Parts: []protocol.ContentPart{{Type: "text", Text: "Hello world, this is a test response."}}},
			},
		}},
	}
	n := CountResponse("gpt-4o", resp)
	if n <= 0 {
		t.Fatalf("expected a positive count, got %d", n)
	}
	if n > 30 {
		t.Fatalf("count suspiciously high: %d", n)
	}
	if CountResponse("gpt-4o", nil) != 0 {
		t.Fatal("nil response should count 0")
	}
}

func TestCountResponseCountsReasoningAndToolCalls(t *testing.T) {
	plain := &protocol.ChatResponse{Choices: []protocol.Choice{{
		Message: protocol.ChatMessage{Content: protocol.Content{Parts: []protocol.ContentPart{{Type: "text", Text: "answer"}}}},
	}}}
	rich := &protocol.ChatResponse{Choices: []protocol.Choice{{
		Message: protocol.ChatMessage{
			Content:          protocol.Content{Parts: []protocol.ContentPart{{Type: "text", Text: "answer"}}},
			ReasoningContent: strings.Repeat("thinking about the problem ", 20),
			ToolCalls: []protocol.ToolCall{{
				Function: protocol.FunctionCall{Name: "search", Arguments: `{"query":"a long query string here"}`},
			}},
		},
	}}}
	n1 := CountResponse("gpt-4o", plain)
	n2 := CountResponse("gpt-4o", rich)
	if n2 <= n1 {
		t.Fatalf("reasoning and tool calls should add tokens: %d -> %d", n1, n2)
	}
}

func TestCountResponseAnthropic(t *testing.T) {
	resp := &protocol.AnthropicResponse{
		Content: []protocol.AnthropicBlock{
			{Type: "thinking", Thinking: "let me consider"},
			{Type: "text", Text: "The answer is 42."},
			{Type: "tool_use", Name: "calc", Input: json.RawMessage(`{"expr":"6*7"}`)},
		},
	}
	n := CountResponseAnthropic("claude-3-5-sonnet", resp)
	if n <= 0 {
		t.Fatalf("expected a positive count, got %d", n)
	}
	if CountResponseAnthropic("claude-3", nil) != 0 {
		t.Fatal("nil response should count 0")
	}
}

// ---------------------------------------------------------------------------
// Usage comparison — the anti-inflation check
// ---------------------------------------------------------------------------

func TestCompareConsistent(t *testing.T) {
	u := Usage{
		PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150,
		UpstreamPromptTokens: 103, UpstreamCompletionTokens: 51,
		UpstreamReported: true,
	}
	d := u.Compare(0.05)
	if !d.Verifiable {
		t.Fatal("expected a verifiable comparison")
	}
	if d.OverThreshold {
		t.Fatalf("a 3%% deviation should be within a 5%% tolerance: %+v", d)
	}
}

// TestCompareDetectsInflation is the core "防虚报" test.
func TestCompareDetectsInflation(t *testing.T) {
	u := Usage{
		PromptTokens: 1000, CompletionTokens: 500, TotalTokens: 1500,
		// The upstream claims to have processed 50% more than it did.
		UpstreamPromptTokens: 1500, UpstreamCompletionTokens: 750,
		UpstreamReported: true,
	}
	d := u.Compare(0.05)
	if !d.Verifiable || !d.OverThreshold {
		t.Fatalf("inflation not detected: %+v", d)
	}
	if d.Direction != "over" {
		t.Fatalf("direction = %q, want over", d.Direction)
	}
	if math.Abs(d.PromptDelta-0.5) > 1e-9 {
		t.Fatalf("prompt delta = %v, want 0.5", d.PromptDelta)
	}
}

func TestCompareDetectsUnderBilling(t *testing.T) {
	u := Usage{
		PromptTokens: 1000, CompletionTokens: 1000,
		UpstreamPromptTokens: 100, UpstreamCompletionTokens: 100,
		UpstreamReported: true,
	}
	d := u.Compare(0.05)
	if !d.OverThreshold || d.Direction != "under" {
		t.Fatalf("under-billing not classified correctly: %+v", d)
	}
}

func TestCompareNotReported(t *testing.T) {
	u := Usage{PromptTokens: 100, CompletionTokens: 50, UpstreamReported: false}
	d := u.Compare(0.05)
	if d.Verifiable {
		t.Fatal("an upstream that reported nothing cannot be verified")
	}
	if d.OverThreshold {
		t.Fatal("an unverifiable request must never be flagged")
	}
}

// TestCompareZeroActual guards the division-by-zero path: an upstream billing
// for tokens when the gateway counted nothing is maximally suspicious.
func TestCompareZeroActual(t *testing.T) {
	u := Usage{
		PromptTokens: 0, CompletionTokens: 0,
		UpstreamPromptTokens: 500, UpstreamCompletionTokens: 500,
		UpstreamReported: true,
	}
	d := u.Compare(0.05)
	if !d.OverThreshold {
		t.Fatalf("billing for content the gateway never saw must be flagged: %+v", d)
	}
	if math.IsInf(d.Worst, 0) || math.IsNaN(d.Worst) {
		t.Fatalf("deviation must stay finite for JSON: %+v", d)
	}
}

// TestCompareIsJSONSafe verifies that a deviation always round-trips, since it
// is persisted in the audit ledger.
func TestCompareIsJSONSafe(t *testing.T) {
	u := Usage{
		PromptTokens: 0, CompletionTokens: 0,
		UpstreamPromptTokens: 1, UpstreamCompletionTokens: 1,
		UpstreamReported: true,
	}
	d := u.Compare(0.05)
	if _, err := json.Marshal(d); err != nil {
		t.Fatalf("deviation is not JSON serialisable: %v", err)
	}
}

// TestToleranceIsRelative verifies the check is proportional, not absolute.
func TestToleranceIsRelative(t *testing.T) {
	small := Usage{PromptTokens: 10, CompletionTokens: 0,
		UpstreamPromptTokens: 11, UpstreamReported: true}
	large := Usage{PromptTokens: 10000, CompletionTokens: 0,
		UpstreamPromptTokens: 11000, UpstreamReported: true}

	if small.Compare(0.2).OverThreshold {
		t.Fatal("a 10% deviation on a small request should pass a 20% tolerance")
	}
	if !large.Compare(0.05).OverThreshold {
		t.Fatal("a 10% deviation on a large request should fail a 5% tolerance")
	}
}

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

func TestCounterUsagePrefersLocalRecount(t *testing.T) {
	c := NewCounter("gpt-4o")
	c.AddPromptText("hello world, this is a test")
	c.AddCompletionText("a reply")
	c.SetUpstream(protocol.Usage{PromptTokens: 999, CompletionTokens: 888, TotalTokens: 1887}, true)
	u := c.Usage()
	if u.PromptTokens == 999 {
		t.Fatal("the counter must not adopt the upstream's claim as its own count")
	}
	if u.UpstreamPromptTokens != 999 {
		t.Fatalf("upstream claim not retained: %+v", u)
	}
	if u.Method != "upstream" {
		t.Fatalf("method = %q", u.Method)
	}
}

// TestCounterFallsBackToUpstreamWhenNothingCountable documents the deliberate
// anti-false-positive behaviour: if the parser extracted no text but the
// upstream reported a count (for example a tool-call-only reply), the upstream
// figure is used so a false inflation signal is not manufactured.
func TestCounterFallsBackToUpstreamWhenNothingCountable(t *testing.T) {
	c := NewCounter("gpt-4o")
	c.AddPromptText("question")
	c.SetUpstream(protocol.Usage{PromptTokens: 10, CompletionTokens: 77, TotalTokens: 87}, true)
	u := c.Usage()
	if u.CompletionTokens != 77 {
		t.Fatalf("expected the upstream completion count to be used as a floor, got %+v", u)
	}
}

func TestCounterStreamMethod(t *testing.T) {
	c := NewCounter("gpt-4o")
	c.MarkStreamAccumulated()
	u := c.Usage()
	if u.Method != "stream_chunks" {
		t.Fatalf("method = %q", u.Method)
	}
}

func TestUsageTotalConsistency(t *testing.T) {
	c := NewCounter("gpt-4o")
	c.AddPromptText("a b c d e f g h i j")
	c.AddCompletionText("x y z")
	u := c.Usage()
	if u.TotalTokens != u.PromptTokens+u.CompletionTokens {
		t.Fatalf("total mismatch: %+v", u)
	}
}

// ---------------------------------------------------------------------------
// Absolute floor
// ---------------------------------------------------------------------------

// TestShortResponseNoiseIsNotFlagged is the regression test for a real
// false-positive found on FreeBSD: a five-token reply claimed as eight is +60%
// in relative terms, which a purely relative check calls fraud. Short requests
// are exactly the ones health checks and benchmark probes make, so without an
// absolute floor a legitimate upstream accumulates spurious integrity damage.
func TestShortResponseNoiseIsNotFlagged(t *testing.T) {
	u := Usage{
		PromptTokens: 5, CompletionTokens: 5, TotalTokens: 10,
		UpstreamPromptTokens: 8, UpstreamCompletionTokens: 8,
		UpstreamReported: true,
	}
	d := u.Compare(0.25)
	if d.Worst <= 0.25 {
		t.Fatalf("this case is meant to be relatively large: %+v", d)
	}
	if d.WorstAbs != 3 {
		t.Fatalf("WorstAbs = %d, want 3", d.WorstAbs)
	}
	if d.OverThreshold {
		t.Fatalf("a 3-token difference on a 5-token reply must not be flagged: %+v", d)
	}
}

// TestLargeDeviationIsStillFlagged verifies the floor does not blunt the check.
func TestLargeDeviationIsStillFlagged(t *testing.T) {
	u := Usage{
		PromptTokens: 500, CompletionTokens: 500,
		UpstreamPromptTokens: 1500, UpstreamCompletionTokens: 1500,
		UpstreamReported: true,
	}
	d := u.Compare(0.25)
	if !d.OverThreshold {
		t.Fatalf("a 200%% deviation must be flagged: %+v", d)
	}
	if d.WorstAbs != 1000 {
		t.Fatalf("WorstAbs = %d, want 1000", d.WorstAbs)
	}
}

// TestFloorBoundaryIsInclusive verifies a deviation exactly at the floor and
// exactly at the tolerance is reported.
func TestFloorBoundaryIsInclusive(t *testing.T) {
	u := Usage{
		PromptTokens: 100, CompletionTokens: 100,
		UpstreamPromptTokens: 108, UpstreamCompletionTokens: 100,
		UpstreamReported: true,
	}
	// 8 tokens absolute was the floor before it became configurable; with an
	// explicit floor of 8 and a tolerance of 0.05 this is exactly on both.
	d := u.CompareWith(0.05, 8)
	if !d.OverThreshold {
		t.Fatalf("a deviation exactly at both bounds should be reported: %+v", d)
	}
	d = u.CompareWith(0.05, 9)
	if d.OverThreshold {
		t.Fatalf("one token under the floor must not be reported: %+v", d)
	}
}

// TestZeroActualWithFloor verifies an upstream billing for a request the
// gateway counted as empty is still caught: the absolute difference is large
// in that case, so the floor does not hide it.
func TestZeroActualWithFloor(t *testing.T) {
	u := Usage{
		UpstreamPromptTokens: 500, UpstreamCompletionTokens: 500,
		UpstreamReported: true,
	}
	d := u.Compare(0.25)
	if !d.OverThreshold {
		t.Fatalf("billing 1000 tokens for an empty exchange must be flagged: %+v", d)
	}
}

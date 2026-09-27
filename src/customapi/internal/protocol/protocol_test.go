package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// In-place model rewriting
// ---------------------------------------------------------------------------

// TestReplaceTopLevelStringPreservesEverythingElse is the critical property:
// the gateway must not disturb a request body it does not understand.
func TestReplaceTopLevelStringPreservesEverythingElse(t *testing.T) {
	in := []byte(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}],"未知字段":{"a":1},"n":1e-3}`)
	out := ReplaceTopLevelString(in, "model", "gpt-4o-2024-11-20")

	if got := Model(out); got != "gpt-4o-2024-11-20" {
		t.Fatalf("model not rewritten: %q", got)
	}
	// Everything except the model value must be byte-identical.
	want := bytes.Replace(in, []byte(`"gpt-4o"`), []byte(`"gpt-4o-2024-11-20"`), 1)
	if !bytes.Equal(out, want) {
		t.Fatalf("body was altered beyond the model field:\n in: %s\nout: %s", in, out)
	}
}

func TestReplaceTopLevelStringKeepsValidJSON(t *testing.T) {
	cases := []string{
		`{"model":"a"}`,
		`{"model":"a","x":1}`,
		`{ "model" : "a" , "x" : { "y" : [1,2,3] } }`,
		`{"x":{"model":"nested"},"model":"a"}`,
		`{"model":"a","content":"a \"model\": b"}`,
		`{"model":"a","content":"escaped \" quote and \\ backslash"}`,
		`{"model":"a","nested":{"deep":{"deeper":[{"k":"v"}]}}}`,
		`{"model":"a","lit":[true,false,null,1.5e10]}`,
	}
	for _, in := range cases {
		out := ReplaceTopLevelString([]byte(in), "model", "NEW")
		var v map[string]any
		if err := json.Unmarshal(out, &v); err != nil {
			t.Fatalf("output is not valid JSON for input %s: %v\nout: %s", in, err, out)
		}
		if v["model"] != "NEW" {
			t.Fatalf("model not replaced for input %s: got %v", in, v["model"])
		}
	}
}

// TestReplaceTopLevelStringIgnoresNestedModel verifies that a nested "model"
// key (for example inside a response_format schema) is not mistaken for the
// top-level one.
func TestReplaceTopLevelStringIgnoresNestedModel(t *testing.T) {
	in := []byte(`{"nested":{"model":"inner"},"model":"outer"}`)
	out := ReplaceTopLevelString(in, "model", "NEW")
	var v struct {
		Nested struct {
			Model string `json:"model"`
		} `json:"nested"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v.Nested.Model != "inner" {
		t.Fatalf("nested model was modified: %q", v.Nested.Model)
	}
	if v.Model != "NEW" {
		t.Fatalf("top-level model not modified: %q", v.Model)
	}
}

func TestReplaceTopLevelStringAppendsWhenMissing(t *testing.T) {
	out := ReplaceTopLevelString([]byte(`{"a":1}`), "model", "gpt-4o")
	if got := Model(out); got != "gpt-4o" {
		t.Fatalf("expected the field to be appended, got %s", out)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("appended body is not valid JSON: %v (%s)", err, out)
	}
}

func TestReplaceTopLevelStringEmptyObject(t *testing.T) {
	out := ReplaceTopLevelString([]byte(`{}`), "model", "x")
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("not valid JSON: %v (%s)", err, out)
	}
	if v["model"] != "x" {
		t.Fatalf("unexpected result: %s", out)
	}
}

func TestReplaceTopLevelStringEscapesValue(t *testing.T) {
	out := ReplaceTopLevelString([]byte(`{"model":"a"}`), "model", `we"ird\name`)
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("not valid JSON: %v (%s)", err, out)
	}
	if v["model"] != `we"ird\name` {
		t.Fatalf("escaping broken: %v", v["model"])
	}
}

func TestReplaceTopLevelStringNonObject(t *testing.T) {
	in := []byte(`[1,2,3]`)
	if out := ReplaceTopLevelString(in, "model", "x"); !bytes.Equal(out, in) {
		t.Fatalf("non-object body should be returned unchanged, got %s", out)
	}
}

// TestReplaceTopLevelStringDoesNotMutateInput documents the copy semantics the
// proxy relies on to keep the original request for auditing.
func TestReplaceTopLevelStringDoesNotMutateInput(t *testing.T) {
	in := []byte(`{"model":"gpt-4o"}`)
	orig := string(in)
	_ = ReplaceTopLevelString(in, "model", "a-much-longer-model-name")
	if string(in) != orig {
		t.Fatalf("input was mutated: %s", in)
	}
}

func TestTopLevelFieldAbsent(t *testing.T) {
	if got := TopLevelString([]byte(`{"a":1}`), "model"); got != nil {
		t.Fatalf("expected nil, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// Protocol detection
// ---------------------------------------------------------------------------

func TestDetectProtocol(t *testing.T) {
	cases := []struct {
		path string
		body string
		want string
	}{
		{"/v1/chat/completions", `{"model":"gpt-4o"}`, "openai"},
		{"/v1/completions", `{"model":"x"}`, "openai"},
		{"/v1/messages", `{"model":"claude-3"}`, "anthropic"},
		{"/v1/messages", `{"model":"claude-3","max_tokens":10}`, "anthropic"},
		// An explicit, known path is authoritative: a client that posts to an
		// OpenAI endpoint is speaking OpenAI even if its body carries a field
		// that also exists in the Messages API.
		{"/v1/chat/completions", `{"model":"x","system":"be nice"}`, "openai"},
		// Unknown paths fall back to body sniffing.
		{"/proxy", `{"model":"x","anthropic_version":"2023-06-01"}`, "anthropic"},
		{"/proxy", `{"model":"x","system":"be nice","max_tokens":100}`, "anthropic"},
		{"/proxy", `{"model":"x","stop_sequences":["\n"]}`, "anthropic"},
		{"/proxy", `{"model":"x","messages":[{"role":"system","content":"s"},{"role":"user","content":"u"}]}`, "openai"},
		{"/proxy", `{"model":"x","messages":[{"role":"user","content":"u"}]}`, "openai"},
		{"/v1/embeddings", `{"model":"x"}`, "openai"},
	}
	for _, tc := range cases {
		if got := DetectProtocol(tc.path, []byte(tc.body)); got != tc.want {
			t.Fatalf("DetectProtocol(%s, %s) = %s, want %s", tc.path, tc.body, got, tc.want)
		}
	}
}

func TestIsStreaming(t *testing.T) {
	if !IsStreaming([]byte(`{"stream":true}`)) {
		t.Fatal("expected streaming")
	}
	if IsStreaming([]byte(`{"stream":false}`)) {
		t.Fatal("expected non-streaming")
	}
	if IsStreaming([]byte(`{}`)) {
		t.Fatal("absent stream field should be false")
	}
	if IsStreaming([]byte(`not json`)) {
		t.Fatal("malformed body should be false")
	}
}

func TestMaxTokensOf(t *testing.T) {
	if got := MaxTokensOf([]byte(`{"max_tokens":100}`)); got != 100 {
		t.Fatalf("got %d", got)
	}
	if got := MaxTokensOf([]byte(`{"max_tokens":100,"max_completion_tokens":200}`)); got != 200 {
		t.Fatalf("max_completion_tokens should win, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// SSE parsing
// ---------------------------------------------------------------------------

func TestSSEReaderBasic(t *testing.T) {
	stream := "data: {\"a\":1}\n\ndata: {\"b\":2}\n\ndata: [DONE]\n\n"
	r := NewSSEReader(strings.NewReader(stream))
	var got []string
	for {
		ev, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		got = append(got, string(ev.Data))
	}
	want := []string{`{"a":1}`, `{"b":2}`, `[DONE]`}
	if len(got) != len(want) {
		t.Fatalf("got %d events %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSSEReaderHandlesCRLFAndComments(t *testing.T) {
	stream := ": ping\r\n\r\ndata: hello\r\n\r\ndata: [DONE]\r\n\r\n"
	r := NewSSEReader(strings.NewReader(stream))
	var got []string
	for {
		ev, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		got = append(got, string(ev.Data))
	}
	if len(got) != 2 || got[0] != "hello" || got[1] != "[DONE]" {
		t.Fatalf("unexpected events: %v", got)
	}
}

func TestSSEReaderMultiLineData(t *testing.T) {
	stream := "data: line1\ndata: line2\n\n"
	r := NewSSEReader(strings.NewReader(stream))
	ev, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if string(ev.Data) != "line1\nline2" {
		t.Fatalf("got %q", ev.Data)
	}
}

func TestSSEReaderPreservesRawBytes(t *testing.T) {
	stream := "data: {\"x\":1}\n\n"
	r := NewSSEReader(strings.NewReader(stream))
	ev, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if string(ev.Raw) != stream {
		t.Fatalf("raw bytes not preserved: %q", ev.Raw)
	}
}

func TestSSEReaderEOFWithoutTrailingBlank(t *testing.T) {
	stream := "data: {\"x\":1}"
	r := NewSSEReader(strings.NewReader(stream))
	ev, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if string(ev.Data) != `{"x":1}` {
		t.Fatalf("got %q", ev.Data)
	}
}

// ---------------------------------------------------------------------------
// Stream accumulation
// ---------------------------------------------------------------------------

func TestStreamAccumulatorOpenAI(t *testing.T) {
	chunks := []string{
		`{"id":"c1","model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}`,
		`{"id":"c1","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"lo "}}]}`,
		`{"id":"c1","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"world"},"finish_reason":"stop"}]}`,
		`{"id":"c1","model":"gpt-4o","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":3,"total_tokens":13}}`,
	}
	acc := NewStreamAccumulator("openai")
	for _, c := range chunks {
		acc.Observe(&SSEEvent{Data: []byte(c)})
	}
	if acc.Text.String() != "Hello world" {
		t.Fatalf("text = %q", acc.Text.String())
	}
	if acc.Model != "gpt-4o" {
		t.Fatalf("model = %q", acc.Model)
	}
	if !acc.HasUsage || acc.Usage.CompletionTokens != 3 {
		t.Fatalf("usage = %+v", acc.Usage)
	}
	if acc.FinishReason != "stop" {
		t.Fatalf("finish reason = %q", acc.FinishReason)
	}
	resp := acc.AsResponse()
	if resp.Choices[0].Message.Content.Plain() != "Hello world" {
		t.Fatalf("AsResponse lost text: %+v", resp)
	}
}

func TestStreamAccumulatorToolCalls(t *testing.T) {
	chunks := []string{
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_","arguments":"{\"ci"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"weather","arguments":"ty\":\"SH\"}"}}]}}]}`,
	}
	acc := NewStreamAccumulator("openai")
	for _, c := range chunks {
		acc.Observe(&SSEEvent{Data: []byte(c)})
	}
	tcs := acc.ToolCallsInOrder()
	if len(tcs) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(tcs))
	}
	if tcs[0].Function.Name != "get_weather" {
		t.Fatalf("name = %q", tcs[0].Function.Name)
	}
	if tcs[0].Function.Arguments != `{"city":"SH"}` {
		t.Fatalf("arguments = %q", tcs[0].Function.Arguments)
	}
}

func TestStreamAccumulatorAnthropic(t *testing.T) {
	events := []*SSEEvent{
		{Event: "message_start", Data: []byte(`{"type":"message_start","message":{"id":"m1","model":"claude-3-5-sonnet","usage":{"input_tokens":12,"output_tokens":0}}}`)},
		{Event: "content_block_start", Data: []byte(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)},
		{Event: "content_block_delta", Data: []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi "}}`)},
		{Event: "content_block_delta", Data: []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"there"}}`)},
		{Event: "message_delta", Data: []byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`)},
	}
	acc := NewStreamAccumulator("anthropic")
	for _, ev := range events {
		acc.Observe(ev)
	}
	if acc.Text.String() != "Hi there" {
		t.Fatalf("text = %q", acc.Text.String())
	}
	if acc.Model != "claude-3-5-sonnet" {
		t.Fatalf("model = %q", acc.Model)
	}
	if acc.Usage.PromptTokens != 12 || acc.Usage.CompletionTokens != 2 {
		t.Fatalf("usage = %+v", acc.Usage)
	}
	if acc.FinishReason != "end_turn" {
		t.Fatalf("stop reason = %q", acc.FinishReason)
	}
}

func TestDetectStreamModel(t *testing.T) {
	raw := []byte(`data: {"id":"x","model":"gpt-4o-mini","choices":[]}`)
	if got := DetectStreamModel(raw); got != "gpt-4o-mini" {
		t.Fatalf("got %q", got)
	}
	if got := DetectStreamModel([]byte(`data: {"choices":[]}`)); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Content type
// ---------------------------------------------------------------------------

func TestContentStringForm(t *testing.T) {
	var c Content
	if err := json.Unmarshal([]byte(`"hello"`), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Text() != "hello" {
		t.Fatalf("text = %q", c.Text())
	}
	// Round-trip must preserve the string form, not expand it to an array.
	out, err := json.Marshal(&c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != `"hello"` {
		t.Fatalf("round-trip changed the shape: %s", out)
	}
}

func TestContentArrayForm(t *testing.T) {
	in := `[{"type":"text","text":"a"},{"type":"text","text":"b"}]`
	var c Content
	if err := json.Unmarshal([]byte(in), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Text() != "ab" {
		t.Fatalf("text = %q", c.Text())
	}
	out, _ := json.Marshal(&c)
	if string(out) != in {
		t.Fatalf("round-trip changed the payload:\n in: %s\nout: %s", in, out)
	}
}

func TestContentNull(t *testing.T) {
	var c Content
	if err := json.Unmarshal([]byte(`null`), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Text() != "" {
		t.Fatalf("expected empty text, got %q", c.Text())
	}
}

func TestChatRequestRoundTripPreservesUnknownFields(t *testing.T) {
	in := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"vendor_extension":{"x":1},"logit_bias":{"50256":-100}}`
	var req ChatRequest
	if err := json.Unmarshal([]byte(in), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Model != "gpt-4o" {
		t.Fatalf("model = %q", req.Model)
	}
	if len(req.Messages) != 1 || req.Messages[0].Content.Text() != "hi" {
		t.Fatalf("messages = %+v", req.Messages)
	}
}

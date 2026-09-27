package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Responses protocol detection
// ---------------------------------------------------------------------------

func TestDetectResponsesProtocol(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want string
	}{
		{"responses path", "/v1/responses", `{"model":"gpt-4o","input":"hi"}`, "responses"},
		{"chat path", "/v1/chat/completions", `{"model":"x","messages":[]}`, "openai"},
		{"messages path", "/v1/messages", `{"model":"x","max_tokens":1}`, "anthropic"},
		{"sniff input string", "/proxy", `{"model":"x","input":"hello"}`, "responses"},
		{"sniff instructions", "/proxy", `{"model":"x","instructions":"be nice"}`, "responses"},
		{"sniff messages wins", "/proxy", `{"model":"x","input":"a","messages":[{"role":"user","content":"b"}]}`, "openai"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectProtocol(tc.path, []byte(tc.body)); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Responses input extraction
// ---------------------------------------------------------------------------

// TestResponsesInputText covers the three shapes the input field takes: a bare
// string, an array of messages, and an array of bare content parts. All three
// must be audited, because all three reach the model.
func TestResponsesInputText(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantSubs []string
	}{
		{
			name:     "string input",
			body:     `{"model":"m","input":"hello world"}`,
			wantSubs: []string{"hello world"},
		},
		{
			name:     "instructions included",
			body:     `{"model":"m","instructions":"be terse","input":"hi"}`,
			wantSubs: []string{"be terse", "hi"},
		},
		{
			name:     "message array with string content",
			body:     `{"model":"m","input":[{"type":"message","role":"user","content":"from a message"}]}`,
			wantSubs: []string{"from a message"},
		},
		{
			name:     "message array with content parts",
			body:     `{"model":"m","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"part one"},{"type":"input_text","text":"part two"}]}]}`,
			wantSubs: []string{"part one", "part two"},
		},
		{
			name:     "function call and output",
			body:     `{"model":"m","input":[{"type":"function_call","name":"search","arguments":"{\"q\":\"x\"}"},{"type":"function_call_output","call_id":"c1","output":"result text"}]}`,
			wantSubs: []string{"search", `"q"`, "result text"},
		},
		{
			name:     "bare content part array",
			body:     `{"model":"m","input":[{"type":"input_text","text":"bare part"}]}`,
			wantSubs: []string{"bare part"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req ResponsesRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			var all strings.Builder
			for _, item := range req.InputText() {
				all.WriteString(item.Text)
				all.WriteString("\n")
			}
			got := all.String()
			for _, want := range tc.wantSubs {
				if !strings.Contains(got, want) {
					t.Fatalf("extracted text %q is missing %q", got, want)
				}
			}
		})
	}
}

func TestResponsesUsesServerState(t *testing.T) {
	var withPrev ResponsesRequest
	if err := json.Unmarshal([]byte(`{"model":"m","input":"x","previous_response_id":"resp_1"}`), &withPrev); err != nil {
		t.Fatal(err)
	}
	if !withPrev.UsesServerState() {
		t.Fatal("previous_response_id must count as server state")
	}
	yes := true
	withStore := ResponsesRequest{Store: &yes}
	if !withStore.UsesServerState() {
		t.Fatal("store=true must count as server state")
	}
	no := false
	without := ResponsesRequest{Store: &no}
	if without.UsesServerState() {
		t.Fatal("store=false must not count as server state")
	}
}

// ---------------------------------------------------------------------------
// Responses response and streaming
// ---------------------------------------------------------------------------

func TestResponsesResponseText(t *testing.T) {
	body := `{
		"id":"resp_1","object":"response","model":"gpt-4o","status":"completed",
		"output":[
			{"type":"reasoning","summary":[{"type":"summary_text","text":"thinking hard"}]},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"the answer"}]},
			{"type":"function_call","name":"lookup","arguments":"{\"k\":1}","call_id":"call_1"}
		],
		"usage":{"input_tokens":10,"output_tokens":20,"total_tokens":30}
	}`
	var resp ResponsesResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := resp.ResponseText(); !strings.Contains(got, "the answer") || !strings.Contains(got, "thinking hard") {
		t.Fatalf("ResponseText = %q", got)
	}
	if got := resp.ReasoningText(); got != "thinking hard" {
		t.Fatalf("ReasoningText = %q", got)
	}
	calls := resp.FunctionCalls()
	if len(calls) != 1 || calls[0].Name != "lookup" {
		t.Fatalf("FunctionCalls = %+v", calls)
	}
	u := resp.Usage.ToUsage()
	if u.PromptTokens != 10 || u.CompletionTokens != 20 || u.TotalTokens != 30 {
		t.Fatalf("usage mapping = %+v", u)
	}
}

// TestResponsesStreamAccumulation drives a realistic event sequence.
func TestResponsesStreamAccumulation(t *testing.T) {
	events := []string{
		`{"type":"response.created","response":{"id":"resp_1","model":"gpt-4o","status":"in_progress"}}`,
		`{"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_1","role":"assistant"}}`,
		`{"type":"response.output_text.delta","output_index":0,"delta":"Hel"}`,
		`{"type":"response.output_text.delta","output_index":0,"delta":"lo "}`,
		`{"type":"response.output_text.delta","output_index":0,"delta":"world"}`,
		`{"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","id":"fc_1","name":"look","call_id":"call_1"}}`,
		`{"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"a\":"}`,
		`{"type":"response.function_call_arguments.delta","output_index":1,"delta":"1}"}`,
		`{"type":"response.completed","response":{"id":"resp_1","model":"gpt-4o","status":"completed","usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10}}}`,
	}
	st := NewResponsesStreamState()
	for _, e := range events {
		st.Observe(&SSEEvent{Data: []byte(e)})
	}
	if got := st.Text.String(); got != "Hello world" {
		t.Fatalf("text = %q", got)
	}
	if st.Model != "gpt-4o" {
		t.Fatalf("model = %q", st.Model)
	}
	if !st.HasUsage || st.Usage.OutputTokens != 3 {
		t.Fatalf("usage = %+v", st.Usage)
	}
	calls := st.CallsInOrder()
	if len(calls) != 1 {
		t.Fatalf("expected 1 function call, got %d", len(calls))
	}
	if calls[0].Name != "look" || calls[0].Arguments != `{"a":1}` {
		t.Fatalf("call = %+v", calls[0])
	}
	if !st.Terminal() {
		t.Fatal("stream should be terminal after response.completed")
	}
	resp := st.AsResponse()
	if got := resp.ResponseText(); got != "Hello world" {
		t.Fatalf("AsResponse text = %q", got)
	}
}

// TestResponsesStreamFailed verifies that a failure event is captured, so the
// gateway can report an upstream error rather than an empty success.
func TestResponsesStreamFailed(t *testing.T) {
	st := NewResponsesStreamState()
	st.Observe(&SSEEvent{Data: []byte(`{"type":"response.created","response":{"id":"r","model":"m"}}`)})
	st.Observe(&SSEEvent{Data: []byte(`{"type":"response.failed","response":{"id":"r","status":"failed"},"error":{"message":"boom","type":"server_error"}}`)})
	if st.Error == nil || !strings.Contains(st.Error.Message, "boom") {
		t.Fatalf("failure not captured: %+v", st.Error)
	}
	if !st.Terminal() {
		t.Fatal("a failed response must be terminal")
	}
}

// TestResponsesStreamWholeTextFallback verifies that a server which sends the
// finished text instead of deltas is still counted, without double counting.
func TestResponsesStreamWholeTextFallback(t *testing.T) {
	st := NewResponsesStreamState()
	st.Observe(&SSEEvent{Data: []byte(`{"type":"response.output_text.done","text":"whole answer"}`)})
	if st.Text.String() != "whole answer" {
		t.Fatalf("text = %q", st.Text.String())
	}
	// A completed event repeating the same output must not append it again.
	st.Observe(&SSEEvent{Data: []byte(`{"type":"response.completed","response":{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"whole answer"}]}]}}`)})
	if st.Text.String() != "whole answer" {
		t.Fatalf("text was duplicated: %q", st.Text.String())
	}
}

func TestResponsesTerminalEvents(t *testing.T) {
	for _, name := range []string{"response.completed", "response.incomplete", "response.failed"} {
		if !IsResponsesTerminalEvent(name) {
			t.Fatalf("%s should be terminal", name)
		}
	}
	for _, name := range []string{"response.created", "response.output_text.delta", ""} {
		if IsResponsesTerminalEvent(name) {
			t.Fatalf("%s should not be terminal", name)
		}
	}
}

// TestEventNameFastPath verifies the cheap event-name extractor used on the
// streaming hot path agrees with a full parse.
func TestEventNameFastPath(t *testing.T) {
	cases := map[string]string{
		`{"type":"response.completed","response":{}}`:    "response.completed",
		`{"response":{"x":1},"type":"response.created"}`: "response.created",
		`{"foo":1}`: "",
		`not json`:  "",
	}
	for body, want := range cases {
		if got := EventName(&SSEEvent{Data: []byte(body)}); got != want {
			t.Fatalf("EventName(%s) = %q, want %q", body, got, want)
		}
	}
	if got := EventName(&SSEEvent{Event: "message_start", Data: []byte(`{}`)}); got != "message_start" {
		t.Fatalf("explicit event field should win, got %q", got)
	}
}

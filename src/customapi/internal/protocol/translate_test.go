package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

// TestChatAnthropicRoundTrip verifies that a conversation survives a conversion
// to the Messages shape and back, including tool calls and tool results, which
// are the parts most likely to be mangled.
func TestChatAnthropicRoundTrip(t *testing.T) {
	body := `{
		"model":"gpt-4o","max_tokens":100,"temperature":0.5,
		"messages":[
			{"role":"system","content":"You are terse."},
			{"role":"user","content":"What is the weather?"},
			{"role":"assistant","content":"Let me check.","tool_calls":[
				{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"SH\"}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"sunny, 22C"},
			{"role":"user","content":"Thanks."}
		],
		"tools":[{"type":"function","function":{"name":"get_weather","description":"weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}]
	}`
	var chat ChatRequest
	if err := json.Unmarshal([]byte(body), &chat); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	anth, err := ChatToAnthropic(&chat)
	if err != nil {
		t.Fatalf("ChatToAnthropic: %v", err)
	}

	// The system prompt must move to the top-level field.
	if anth.System == nil || !strings.Contains(anth.System.Text(), "terse") {
		t.Fatalf("system prompt not hoisted: %+v", anth.System)
	}
	// The Messages API requires max_tokens, and it must be the value asked for.
	if anth.MaxTokens != 100 {
		t.Fatalf("max_tokens = %d, want 100", anth.MaxTokens)
	}
	// Roles must alternate: no two consecutive user turns.
	for i := 1; i < len(anth.Messages); i++ {
		if anth.Messages[i].Role == anth.Messages[i-1].Role {
			t.Fatalf("consecutive %s turns at %d: the Messages API rejects them",
				anth.Messages[i].Role, i)
		}
	}
	// The tool call and its result must both survive.
	joined, err := json.Marshal(anth)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(joined)
	for _, want := range []string{"get_weather", "call_1", "sunny, 22C", "SH"} {
		if !strings.Contains(text, want) {
			t.Fatalf("converted request lost %q:\n%s", want, text)
		}
	}
	// The tool schema must be flattened, not nested under "function".
	if len(anth.Tools) != 1 || anth.Tools[0].Name != "get_weather" {
		t.Fatalf("tools = %+v", anth.Tools)
	}

	// ...and back again.
	back, err := AnthropicToChat(anth)
	if err != nil {
		t.Fatalf("AnthropicToChat: %v", err)
	}
	if back.Model != "gpt-4o" {
		t.Fatalf("model = %q", back.Model)
	}
	var sb strings.Builder
	for _, m := range back.Messages {
		sb.WriteString(m.Role + ":" + m.Content.Plain() + ";")
	}
	got := sb.String()
	for _, want := range []string{"system:You are terse.", "user:What is the weather?", "sunny, 22C"} {
		if !strings.Contains(got, want) {
			t.Fatalf("round trip lost %q, got %q", want, got)
		}
	}
}

// TestChatAnthropicRejectsRemoteImage verifies that an unrepresentable feature
// is refused loudly rather than dropped silently. A dropped image would produce
// a plausible answer to a question the model never saw.
func TestChatAnthropicRejectsRemoteImage(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":[
		{"type":"text","text":"what is this"},
		{"type":"image_url","image_url":{"url":"https://example.com/x.png"}}]}]}`
	var chat ChatRequest
	if err := json.Unmarshal([]byte(body), &chat); err != nil {
		t.Fatal(err)
	}
	_, err := ChatToAnthropic(&chat)
	if err == nil {
		t.Fatal("a remote image URL was accepted silently")
	}
	var te *TranslationError
	if !asTranslationError(err, &te) {
		t.Fatalf("expected a TranslationError, got %T: %v", err, err)
	}
	if !strings.Contains(te.Field, "image_url") {
		t.Fatalf("the error must name the offending field, got %q", te.Field)
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Fatalf("the error should say what to do instead: %v", err)
	}
}

// TestChatAnthropicAcceptsDataURLImage verifies the representable case works.
func TestChatAnthropicAcceptsDataURLImage(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":[
		{"type":"text","text":"what is this"},
		{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}]}]}`
	var chat ChatRequest
	if err := json.Unmarshal([]byte(body), &chat); err != nil {
		t.Fatal(err)
	}
	anth, err := ChatToAnthropic(&chat)
	if err != nil {
		t.Fatalf("ChatToAnthropic: %v", err)
	}
	joined, _ := json.Marshal(anth)
	if !strings.Contains(string(joined), "base64") || !strings.Contains(string(joined), "image/png") {
		t.Fatalf("image was not converted to a base64 source:\n%s", joined)
	}
}

// TestChatAnthropicDefaultsMaxTokens verifies the required field is supplied.
func TestChatAnthropicDefaultsMaxTokens(t *testing.T) {
	chat := &ChatRequest{Model: "m", Messages: []ChatMessage{
		{Role: "user", Content: Content{Parts: []ContentPart{{Type: "text", Text: "hi"}}}},
	}}
	anth, err := ChatToAnthropic(chat)
	if err != nil {
		t.Fatalf("ChatToAnthropic: %v", err)
	}
	if anth.MaxTokens != AnthropicMaxTokensDefault {
		t.Fatalf("max_tokens = %d, want the default %d", anth.MaxTokens, AnthropicMaxTokensDefault)
	}
}

// ---------------------------------------------------------------------------
// Responses <-> chat
// ---------------------------------------------------------------------------

func TestResponsesToChat(t *testing.T) {
	body := `{
		"model":"gpt-4o","instructions":"be brief","max_output_tokens":50,
		"input":[
			{"type":"message","role":"user","content":[{"type":"input_text","text":"question"}]},
			{"type":"function_call","call_id":"c1","name":"lookup","arguments":"{\"k\":1}"},
			{"type":"function_call_output","call_id":"c1","output":"found it"}
		],
		"tools":[{"type":"function","name":"lookup","description":"d","parameters":{"type":"object"}}]
	}`
	var req ResponsesRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	chat, err := ResponsesToChat(&req)
	if err != nil {
		t.Fatalf("ResponsesToChat: %v", err)
	}
	if chat.MaxCompletionTokens != 50 {
		t.Fatalf("max tokens = %d", chat.MaxCompletionTokens)
	}
	joined, _ := json.Marshal(chat)
	text := string(joined)
	for _, want := range []string{"be brief", "question", "lookup", "c1", "found it"} {
		if !strings.Contains(text, want) {
			t.Fatalf("conversion lost %q:\n%s", want, text)
		}
	}
	// The nested tool shape must be produced for the chat API.
	var probe struct {
		Tools []struct {
			Type     string `json:"type"`
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(joined, &probe); err != nil {
		t.Fatal(err)
	}
	if len(probe.Tools) != 1 || probe.Tools[0].Function.Name != "lookup" {
		t.Fatalf("tool not converted to the chat shape: %s", text)
	}
}

func TestChatToResponses(t *testing.T) {
	body := `{"model":"gpt-4o","max_tokens":30,"messages":[
		{"role":"system","content":"sys"},
		{"role":"user","content":"hello"},
		{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{}"}}]},
		{"role":"tool","tool_call_id":"c1","content":"out"}
	]}`
	var chat ChatRequest
	if err := json.Unmarshal([]byte(body), &chat); err != nil {
		t.Fatal(err)
	}
	resp, err := ChatToResponses(&chat)
	if err != nil {
		t.Fatalf("ChatToResponses: %v", err)
	}
	if resp.Instructions != "sys" {
		t.Fatalf("instructions = %q", resp.Instructions)
	}
	if resp.MaxOutputTokens != 30 {
		t.Fatalf("max_output_tokens = %d", resp.MaxOutputTokens)
	}
	joined, _ := json.Marshal(resp)
	text := string(joined)
	for _, want := range []string{"function_call", "function_call_output", "hello", "c1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("conversion lost %q:\n%s", want, text)
		}
	}
}

// TestResponsesRejectsBuiltinTools verifies that a server-side tool (which the
// gateway cannot emulate) is refused rather than silently dropped.
func TestResponsesRejectsBuiltinTools(t *testing.T) {
	var req ResponsesRequest
	if err := json.Unmarshal([]byte(`{"model":"m","input":"x","tools":[{"type":"web_search_preview"}]}`), &req); err != nil {
		t.Fatal(err)
	}
	if _, err := ResponsesToChat(&req); err == nil {
		t.Fatal("a built-in tool was accepted for a chat target")
	}
}

// ---------------------------------------------------------------------------
// Response-side conversions
// ---------------------------------------------------------------------------

func TestAnthropicToChatResponse(t *testing.T) {
	body := `{"id":"msg_1","type":"message","role":"assistant","model":"claude-3",
		"content":[{"type":"text","text":"hello"},{"type":"tool_use","id":"t1","name":"f","input":{"a":1}}],
		"stop_reason":"tool_use","usage":{"input_tokens":5,"output_tokens":3}}`
	var resp AnthropicResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	chat, err := AnthropicToChatResponse(&resp)
	if err != nil {
		t.Fatalf("AnthropicToChatResponse: %v", err)
	}
	choice := chat.Choices[0]
	if choice.Message.Content.Plain() != "hello" {
		t.Fatalf("text = %q", choice.Message.Content.Plain())
	}
	if len(choice.Message.ToolCalls) != 1 || choice.Message.ToolCalls[0].Function.Name != "f" {
		t.Fatalf("tool calls = %+v", choice.Message.ToolCalls)
	}
	if choice.FinishReason != "tool_calls" {
		t.Fatalf("finish reason = %q", choice.FinishReason)
	}
	if chat.Usage == nil || chat.Usage.PromptTokens != 5 {
		t.Fatalf("usage = %+v", chat.Usage)
	}
}

func TestChatToAnthropicResponse(t *testing.T) {
	body := `{"id":"c1","model":"gpt-4o","choices":[{"index":0,"message":
		{"role":"assistant","content":"hi","tool_calls":[{"id":"t","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}]},
		"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`
	var resp ChatResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	anth, err := ChatToAnthropicResponse(&resp)
	if err != nil {
		t.Fatalf("ChatToAnthropicResponse: %v", err)
	}
	if anth.StopReason != "tool_use" {
		t.Fatalf("stop reason = %q", anth.StopReason)
	}
	var hasText, hasTool bool
	for _, block := range anth.Content {
		if block.Type == "text" && block.Text == "hi" {
			hasText = true
		}
		if block.Type == "tool_use" && block.Name == "f" {
			hasTool = true
		}
	}
	if !hasText || !hasTool {
		t.Fatalf("content = %+v", anth.Content)
	}
	if anth.Usage == nil || anth.Usage.InputTokens != 4 {
		t.Fatalf("usage = %+v", anth.Usage)
	}
}

func TestResponsesToChatResponse(t *testing.T) {
	body := `{"id":"r1","object":"response","model":"gpt-4o","status":"completed",
		"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]},
		{"type":"function_call","name":"f","arguments":"{}","call_id":"c1"}],
		"usage":{"input_tokens":9,"output_tokens":4,"total_tokens":13}}`
	var resp ResponsesResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	chat, err := ResponsesToChatResponse(&resp)
	if err != nil {
		t.Fatalf("ResponsesToChatResponse: %v", err)
	}
	if chat.Choices[0].Message.Content.Plain() != "answer" {
		t.Fatalf("text = %q", chat.Choices[0].Message.Content.Plain())
	}
	if len(chat.Choices[0].Message.ToolCalls) != 1 {
		t.Fatalf("tool calls = %+v", chat.Choices[0].Message.ToolCalls)
	}
	if chat.Choices[0].FinishReason != "tool_calls" {
		t.Fatalf("finish reason = %q", chat.Choices[0].FinishReason)
	}
}

func TestChatToResponsesResponse(t *testing.T) {
	body := `{"id":"c1","model":"gpt-4o","choices":[{"index":0,"message":
		{"role":"assistant","content":"hi there","reasoning_content":"thinking"},"finish_reason":"stop"}],
		"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`
	var resp ChatResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	out, err := ChatToResponsesResponse(&resp)
	if err != nil {
		t.Fatalf("ChatToResponsesResponse: %v", err)
	}
	if out.Status != "completed" {
		t.Fatalf("status = %q", out.Status)
	}
	if got := out.ResponseText(); !strings.Contains(got, "hi there") {
		t.Fatalf("text = %q", got)
	}
	if got := out.ReasoningText(); got != "thinking" {
		t.Fatalf("reasoning = %q", got)
	}
	// Reasoning must precede the message, matching the Responses ordering.
	if len(out.Output) < 2 || out.Output[0].Type != "reasoning" {
		t.Fatalf("output order = %+v", out.Output)
	}
}

// ---------------------------------------------------------------------------
// Dispatch table
// ---------------------------------------------------------------------------

// TestTranslateDispatchCoversEveryPair verifies that every ordered pair of the
// three protocols either produces a body or reports a clear error, so a missing
// path cannot be mistaken for a working one.
func TestTranslateDispatchCoversEveryPair(t *testing.T) {
	bodies := map[string]string{
		"openai":    `{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
		"anthropic": `{"model":"m","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`,
		"responses": `{"model":"m","input":"hi"}`,
	}
	protocols := []string{"openai", "anthropic", "responses"}
	for _, from := range protocols {
		for _, to := range protocols {
			if from == to {
				continue
			}
			out, err := TranslateRequestBody(from, to, []byte(bodies[from]))
			if err != nil {
				t.Fatalf("%s -> %s failed: %v", from, to, err)
			}
			// The result must be valid JSON in a shape the target accepts.
			var probe map[string]any
			if err := json.Unmarshal(out, &probe); err != nil {
				t.Fatalf("%s -> %s produced invalid JSON: %v", from, to, err)
			}
			if probe["model"] != "m" {
				t.Fatalf("%s -> %s lost the model: %s", from, to, out)
			}
			switch to {
			case "anthropic":
				if _, ok := probe["max_tokens"]; !ok {
					t.Fatalf("%s -> anthropic omitted the required max_tokens: %s", from, out)
				}
				if _, ok := probe["messages"]; !ok {
					t.Fatalf("%s -> anthropic omitted messages: %s", from, out)
				}
			case "openai":
				if _, ok := probe["messages"]; !ok {
					t.Fatalf("%s -> openai omitted messages: %s", from, out)
				}
			case "responses":
				if _, ok := probe["input"]; !ok {
					t.Fatalf("%s -> responses omitted input: %s", from, out)
				}
			}
		}
	}
}

func TestTranslateResponseDispatchCoversEveryPair(t *testing.T) {
	// Each sample is a minimal valid reply of its protocol.
	samples := map[string]string{
		"openai":    `{"id":"c","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`,
		"anthropic": `{"id":"a","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`,
		"responses": `{"id":"r","object":"response","model":"m","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`,
	}
	protocols := []string{"openai", "anthropic", "responses"}
	for _, from := range protocols {
		for _, to := range protocols {
			if from == to {
				continue
			}
			out, err := TranslateResponseBody(from, to, []byte(samples[from]))
			if err != nil {
				t.Fatalf("%s -> %s failed: %v", from, to, err)
			}
			if !strings.Contains(string(out), "hi") {
				t.Fatalf("%s -> %s lost the text: %s", from, to, out)
			}
		}
	}
}

func TestTranslateSameProtocolIsIdentity(t *testing.T) {
	body := []byte(`{"model":"m","messages":[]}`)
	out, err := TranslateRequestBody("openai", "openai", body)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(body) {
		t.Fatalf("identity translation altered the body: %s", out)
	}
}

func TestTranslateUnknownProtocolFails(t *testing.T) {
	if _, err := TranslateRequestBody("openai", "gemini", []byte(`{}`)); err == nil {
		t.Fatal("an unknown target protocol must be rejected")
	}
}

func TestValidProtocol(t *testing.T) {
	for _, p := range []string{"openai", "responses", "anthropic"} {
		if !ValidProtocol(p) {
			t.Fatalf("%s should be valid", p)
		}
	}
	for _, p := range []string{"", "gemini", "chat"} {
		if ValidProtocol(p) {
			t.Fatalf("%s should be invalid", p)
		}
	}
}

// asTranslationError is a local errors.As to keep the import list short.
func asTranslationError(err error, target **TranslationError) bool {
	te, ok := err.(*TranslationError)
	if ok {
		*target = te
	}
	return ok
}

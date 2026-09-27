package protocol

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// OpenAI Responses API (/v1/responses)
// ---------------------------------------------------------------------------
//
// The Responses API is not a rename of chat completions: the request takes
// `input` instead of `messages`, the response returns a flat `output` array of
// typed items instead of `choices`, and streaming uses named events
// ("response.output_text.delta") rather than anonymous delta chunks terminated
// by [DONE]. All three differ enough that the gateway models them natively
// rather than pretending they are chat completions.

// ResponsesRequest is a request to POST /v1/responses.
type ResponsesRequest struct {
	Model string `json:"model"`
	// Input is either a plain string or an array of input items.
	Input json.RawMessage `json:"input,omitempty"`
	// Instructions replaces the chat "system" message.
	Instructions string `json:"instructions,omitempty"`
	// MaxOutputTokens bounds the generation.
	MaxOutputTokens int  `json:"max_output_tokens,omitempty"`
	Stream          bool `json:"stream,omitempty"`
	// Temperature / TopP mirror the chat parameters.
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
	// Tools and ToolChoice follow the Responses shape (flat function objects).
	Tools      []ResponsesTool `json:"tools,omitempty"`
	ToolChoice json.RawMessage `json:"tool_choice,omitempty"`
	// Text carries the structured-output configuration.
	Text json.RawMessage `json:"text,omitempty"`
	// Store and PreviousResponseID support server-side conversation state.
	// The gateway forwards them but cannot audit a conversation it never sees,
	// so a request using them is flagged (see ResponsesRequest.UsesServerState).
	Store              *bool  `json:"store,omitempty"`
	PreviousResponseID string `json:"previous_response_id,omitempty"`
	// Metadata is echoed back by the upstream.
	Metadata json.RawMessage `json:"metadata,omitempty"`
	// Reasoning configures reasoning-effort style models.
	Reasoning json.RawMessage `json:"reasoning,omitempty"`
	// Truncation controls how over-long input is handled.
	Truncation string `json:"truncation,omitempty"`
}

// UsesServerState reports whether the request depends on state the gateway
// cannot see.
//
// This matters for auditing: with previous_response_id the full prompt lives on
// the provider, so the gateway's outbound inspection sees only the new turn and
// its token recount cannot account for the earlier conversation. A caller that
// cares about complete auditing should refuse these or force store=false.
func (r *ResponsesRequest) UsesServerState() bool {
	if r.PreviousResponseID != "" {
		return true
	}
	return r.Store != nil && *r.Store
}

// ResponsesTool is a tool definition in the Responses shape.
//
// The Responses API flattens the chat "function" wrapper: the type is
// "function" and the name/parameters sit at the top level. Values produced by
// clients that still send the chat shape are handled by InputSchema below.
type ResponsesTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
	// Function carries the nested chat-style form when a client sends it.
	Function *ToolFunction `json:"function,omitempty"`
}

// ToolName returns the effective tool name regardless of which shape was sent.
func (t ResponsesTool) ToolName() string {
	if t.Name != "" {
		return t.Name
	}
	if t.Function != nil {
		return t.Function.Name
	}
	return ""
}

// ToolSchema returns the effective parameter schema.
func (t ResponsesTool) ToolSchema() json.RawMessage {
	if len(t.Parameters) > 0 {
		return t.Parameters
	}
	if t.Function != nil {
		return t.Function.Parameters
	}
	return nil
}

// ResponsesResponse is a non-streaming /v1/responses reply.
type ResponsesResponse struct {
	ID        string                `json:"id"`
	Object    string                `json:"object"`
	CreatedAt int64                 `json:"created_at"`
	Status    string                `json:"status,omitempty"`
	Model     string                `json:"model"`
	Output    []ResponsesOutputItem `json:"output,omitempty"`
	Usage     *ResponsesUsage       `json:"usage,omitempty"`
	// Error carries a failed response.
	Error *APIError `json:"error,omitempty"`
	// IncompleteDetails explains a truncated response.
	IncompleteDetails json.RawMessage `json:"incomplete_details,omitempty"`
	// OutputText is a convenience field some compatible servers add.
	OutputText string `json:"output_text,omitempty"`
}

// ResponsesOutputItem is one entry of the output array.
type ResponsesOutputItem struct {
	// Type is "message", "function_call", "reasoning", "web_search_call", ...
	Type string `json:"type"`
	// ID identifies the item.
	ID string `json:"id,omitempty"`
	// Role is set for message items.
	Role string `json:"role,omitempty"`
	// Content holds typed content parts for message items.
	Content []ResponsesContentPart `json:"content,omitempty"`
	// Status is "completed" or "incomplete".
	Status string `json:"status,omitempty"`
	// Below: function_call item fields.
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
	CallID    string `json:"call_id,omitempty"`
	// Below: reasoning item fields.
	Summary []ResponsesContentPart `json:"summary,omitempty"`
	// EncryptedContent is preserved verbatim (reasoning items are opaque).
	EncryptedContent string `json:"encrypted_content,omitempty"`
}

// ResponsesContentPart is one part of a message item.
type ResponsesContentPart struct {
	Type string `json:"type,omitempty"`
	Text string `json:"text,omitempty"`
	// Annotations and logprobs are preserved but not interpreted.
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

// ResponsesUsage is the Responses API usage block.
//
// Note the field names differ from chat completions: input_tokens/output_tokens
// rather than prompt_tokens/completion_tokens.
type ResponsesUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
	// InputTokensDetails breaks the input down (cached tokens).
	InputTokensDetails *ResponsesInputTokensDetails `json:"input_tokens_details,omitempty"`
	// OutputTokensDetails carries the reasoning-token count.
	OutputTokensDetails *ResponsesOutputTokensDetails `json:"output_tokens_details,omitempty"`
}

// ResponsesInputTokensDetails is the input breakdown.
type ResponsesInputTokensDetails struct {
	CachedTokens int `json:"cached_tokens,omitempty"`
}

// ResponsesOutputTokensDetails is the output breakdown.
type ResponsesOutputTokensDetails struct {
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
}

// ToUsage converts to the gateway's canonical usage shape.
func (u *ResponsesUsage) ToUsage() Usage {
	if u == nil {
		return Usage{}
	}
	total := u.TotalTokens
	if total == 0 {
		total = u.InputTokens + u.OutputTokens
	}
	return Usage{
		PromptTokens:     u.InputTokens,
		CompletionTokens: u.OutputTokens,
		TotalTokens:      total,
	}
}

// InputText extracts every piece of text the request sends, for auditing and
// for the local token recount.
//
// The Responses `input` field has three shapes: a bare string, an array of
// message objects, or an array of bare content parts. All three are handled;
// anything unrecognised is skipped rather than guessed at.
func (r *ResponsesRequest) InputText() []LabelledTextLike {
	var out []LabelledTextLike
	if r.Instructions != "" {
		out = append(out, LabelledTextLike{Field: "instructions", Text: r.Instructions})
	}
	raw := strings.TrimSpace(string(r.Input))
	if raw == "" || raw == "null" {
		return out
	}
	// Shape 1: a plain string.
	if strings.HasPrefix(raw, `"`) {
		var s string
		if err := json.Unmarshal(r.Input, &s); err == nil && s != "" {
			out = append(out, LabelledTextLike{Field: "input", Text: s})
		}
		return out
	}
	if !strings.HasPrefix(raw, "[") {
		return out
	}
	// Shape 2/3: an array. Try the message form first.
	var items []struct {
		Type    string          `json:"type"`
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
		// Some items carry text directly (input_text parts).
		Text string `json:"text"`
		// Function-call items carry arguments that must be audited too, and a
		// function_call_output carries the tool's result, which is user-visible
		// content and part of the next prompt.
		Arguments string          `json:"arguments"`
		Name      string          `json:"name"`
		Output    json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(r.Input, &items); err != nil {
		return out
	}
	for i, item := range items {
		field := fmt.Sprintf("input[%d]", i)
		if item.Text != "" {
			out = append(out, LabelledTextLike{Field: field, Text: item.Text})
		}
		if item.Name != "" {
			out = append(out, LabelledTextLike{Field: field + ".name", Text: item.Name})
		}
		if item.Arguments != "" {
			out = append(out, LabelledTextLike{Field: field + ".arguments", Text: item.Arguments})
		}
		if len(item.Output) > 0 {
			// The output may be a string or an array of content parts.
			ot := strings.TrimSpace(string(item.Output))
			if strings.HasPrefix(ot, `"`) {
				var s string
				if err := json.Unmarshal(item.Output, &s); err == nil && s != "" {
					out = append(out, LabelledTextLike{Field: field + ".output", Text: s})
				}
			} else if strings.HasPrefix(ot, "[") {
				var parts []ResponsesContentPart
				if err := json.Unmarshal(item.Output, &parts); err == nil {
					for j, part := range parts {
						if part.Text != "" {
							out = append(out, LabelledTextLike{
								Field: fmt.Sprintf("%s.output[%d]", field, j), Text: part.Text,
							})
						}
					}
				}
			}
		}
		if len(item.Content) == 0 {
			continue
		}
		// Content may be a string or an array of parts.
		ct := strings.TrimSpace(string(item.Content))
		if strings.HasPrefix(ct, `"`) {
			var s string
			if err := json.Unmarshal(item.Content, &s); err == nil && s != "" {
				out = append(out, LabelledTextLike{Field: field + ".content", Text: s})
			}
			continue
		}
		var parts []ResponsesContentPart
		if err := json.Unmarshal(item.Content, &parts); err != nil {
			continue
		}
		for j, part := range parts {
			if part.Text != "" {
				out = append(out, LabelledTextLike{
					Field: fmt.Sprintf("%s.content[%d]", field, j), Text: part.Text,
				})
			}
		}
	}
	return out
}

// ToolNames lists the tools the request declares.
func (r *ResponsesRequest) ToolNames() []string {
	var out []string
	for _, t := range r.Tools {
		if n := t.ToolName(); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// ResponseText returns the assistant text of a Responses reply.
func (r *ResponsesResponse) ResponseText() string {
	var sb strings.Builder
	if r.OutputText != "" {
		sb.WriteString(r.OutputText)
	}
	for _, item := range r.Output {
		switch item.Type {
		case "message":
			for _, part := range item.Content {
				sb.WriteString(part.Text)
			}
		case "reasoning":
			// Reasoning summaries are generated tokens and are billed, so they
			// count toward the completion side of the recount.
			for _, part := range item.Summary {
				sb.WriteString(part.Text)
			}
		}
	}
	return sb.String()
}

// ReasoningText returns any reasoning summary in the reply.
func (r *ResponsesResponse) ReasoningText() string {
	var sb strings.Builder
	for _, item := range r.Output {
		if item.Type != "reasoning" {
			continue
		}
		for _, part := range item.Summary {
			sb.WriteString(part.Text)
		}
	}
	return sb.String()
}

// FunctionCalls returns the function calls the model asked for.
func (r *ResponsesResponse) FunctionCalls() []ResponsesOutputItem {
	var out []ResponsesOutputItem
	for _, item := range r.Output {
		if item.Type == "function_call" {
			out = append(out, item)
		}
	}
	return out
}

// LabelledTextLike mirrors policy.LabelledText without importing the policy
// package, which would create a cycle (policy imports protocol).
type LabelledTextLike struct {
	Field string
	Text  string
}

// ---------------------------------------------------------------------------
// Responses SSE events
// ---------------------------------------------------------------------------

// ResponsesStreamState accumulates a streamed Responses reply.
//
// The event vocabulary is larger than chat completions and is analysed here
// rather than in the proxy so that the proxy stays protocol-agnostic.
type ResponsesStreamState struct {
	// ResponseID is the id from response.created.
	ResponseID string
	// Model is the model the upstream reports.
	Model string
	// Status is the terminal status ("completed", "incomplete", "failed").
	Status string
	// Text accumulates response.output_text.delta fragments.
	Text strings.Builder
	// Reasoning accumulates reasoning summary deltas.
	Reasoning strings.Builder
	// Calls accumulates function-call arguments by output index.
	Calls map[int]*ResponsesOutputItem
	// CallOrder preserves first-seen ordering of function-call indices.
	CallOrder []int
	// Usage is taken from response.completed/incomplete.
	Usage ResponsesUsage
	// HasUsage reports whether a usage block was seen.
	HasUsage bool
	// Error is set when the stream carried a failure event.
	Error *APIError
	// IncompleteReason explains a truncated response.
	IncompleteReason string
	// SeenEventTypes records which event types arrived, which makes an
	// unexpected upstream dialect visible in the audit record.
	SeenEventTypes map[string]int
	// Events counts consumed events.
	Events int
}

// NewResponsesStreamState creates an accumulator.
func NewResponsesStreamState() *ResponsesStreamState {
	return &ResponsesStreamState{
		Calls:          map[int]*ResponsesOutputItem{},
		SeenEventTypes: map[string]int{},
	}
}

// responsesEvent is the envelope shared by every Responses stream event.
type responsesEvent struct {
	Type        string `json:"type"`
	Delta       string `json:"delta,omitempty"`
	ItemID      string `json:"item_id,omitempty"`
	OutputIndex int    `json:"output_index,omitempty"`
	ContentIdx  int    `json:"content_index,omitempty"`
	SummaryIdx  int    `json:"summary_index,omitempty"`
	Text        string `json:"text,omitempty"`
	// Name/Arguments appear on response.function_call_arguments.delta and the
	// output_item.added event for a function call.
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
	CallID    string `json:"call_id,omitempty"`
	Item      *struct {
		Type      string                 `json:"type"`
		ID        string                 `json:"id"`
		Name      string                 `json:"name"`
		Arguments string                 `json:"arguments"`
		CallID    string                 `json:"call_id"`
		Role      string                 `json:"role"`
		Content   []ResponsesContentPart `json:"content"`
		Status    string                 `json:"status"`
	} `json:"item,omitempty"`
	Response *ResponsesResponse `json:"response,omitempty"`
	Error    *APIError          `json:"error,omitempty"`
	// Message accompanies error events.
	Message string `json:"message,omitempty"`
	// IncompleteDetails accompanies response.incomplete.
	IncompleteDetails json.RawMessage `json:"incomplete_details,omitempty"`
}

// Observe folds one SSE event into the state.
func (s *ResponsesStreamState) Observe(ev *SSEEvent) {
	if ev == nil {
		return
	}
	s.Events++
	data := strings.TrimSpace(string(ev.Data))
	if data == "" || data == "[DONE]" {
		return
	}
	var e responsesEvent
	if err := json.Unmarshal([]byte(data), &e); err != nil {
		// A non-JSON payload is tolerated: some compatible servers emit bare
		// text. It still counts as assistant output.
		s.Text.WriteString(data)
		return
	}
	// The event name is authoritative when present; some servers omit "type".
	name := e.Type
	if name == "" {
		name = ev.Event
	}
	if name == "" {
		name = "unknown"
	}
	s.SeenEventTypes[name]++

	switch name {
	case "response.created", "response.in_progress":
		if e.Response != nil {
			if e.Response.ID != "" {
				s.ResponseID = e.Response.ID
			}
			if e.Response.Model != "" {
				s.Model = e.Response.Model
			}
		}
	case "response.output_text.delta":
		s.Text.WriteString(e.Delta)
	case "response.output_text.done":
		// Some servers send the whole text here instead of deltas; only use it
		// when no deltas were seen, or the text would be counted twice.
		if e.Text != "" && s.Text.Len() == 0 {
			s.Text.WriteString(e.Text)
		}
	case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
		s.Reasoning.WriteString(e.Delta)
	case "response.reasoning_summary_text.done", "response.reasoning_text.done":
		if e.Text != "" && s.Reasoning.Len() == 0 {
			s.Reasoning.WriteString(e.Text)
		}
	case "response.output_item.added":
		if e.Item != nil && e.Item.Type == "function_call" {
			s.trackCall(e.OutputIndex, e.Item.ID, e.Item.Name, e.Item.CallID)
		}
	case "response.function_call_arguments.delta":
		call := s.trackCall(e.OutputIndex, e.ItemID, e.Name, e.CallID)
		call.Arguments += e.Delta
	case "response.function_call_arguments.done":
		call := s.trackCall(e.OutputIndex, e.ItemID, e.Name, e.CallID)
		if e.Arguments != "" {
			call.Arguments = e.Arguments
		}
	case "response.completed", "response.incomplete", "response.failed":
		if e.Response != nil {
			if e.Response.ID != "" {
				s.ResponseID = e.Response.ID
			}
			if e.Response.Model != "" {
				s.Model = e.Response.Model
			}
			if e.Response.Status != "" {
				s.Status = e.Response.Status
			}
			if e.Response.Usage != nil {
				s.Usage = *e.Response.Usage
				s.HasUsage = true
			}
			// A completed event may carry the full output when the server did
			// not stream deltas; fold it in without double counting.
			if s.Text.Len() == 0 {
				for _, item := range e.Response.Output {
					if item.Type == "message" {
						for _, part := range item.Content {
							s.Text.WriteString(part.Text)
						}
					}
					if item.Type == "function_call" {
						call := s.trackCallByCallID(item.CallID, item.ID, item.Name)
						if call.Arguments == "" {
							call.Arguments = item.Arguments
						}
					}
				}
			}
		}
		if name == "response.failed" {
			if e.Error != nil {
				s.Error = e.Error
			} else if e.Message != "" {
				s.Error = &APIError{Message: e.Message, Type: "upstream_error"}
			}
		}
		if len(e.IncompleteDetails) > 0 {
			s.IncompleteReason = string(e.IncompleteDetails)
		}
	case "error":
		if e.Error != nil {
			s.Error = e.Error
		} else if e.Message != "" {
			s.Error = &APIError{Message: e.Message, Type: "upstream_error"}
		}
	}
}

// trackCall returns the accumulator for a function call at an output index.
func (s *ResponsesStreamState) trackCall(index int, id, name, callID string) *ResponsesOutputItem {
	call, ok := s.Calls[index]
	if !ok {
		call = &ResponsesOutputItem{Type: "function_call", ID: id, CallID: callID}
		s.Calls[index] = call
		s.CallOrder = append(s.CallOrder, index)
	}
	if name != "" {
		call.Name += name
	}
	if id != "" {
		call.ID = id
	}
	if callID != "" {
		call.CallID = callID
	}
	return call
}

// trackCallByCallID finds or creates a call identified by call_id.
func (s *ResponsesStreamState) trackCallByCallID(callID, id, name string) *ResponsesOutputItem {
	for _, index := range s.CallOrder {
		if call := s.Calls[index]; call != nil && callID != "" && call.CallID == callID {
			return call
		}
	}
	index := len(s.Calls)
	call := &ResponsesOutputItem{Type: "function_call", ID: id, Name: name, CallID: callID}
	s.Calls[index] = call
	s.CallOrder = append(s.CallOrder, index)
	return call
}

// CallsInOrder returns accumulated function calls ordered by output index.
func (s *ResponsesStreamState) CallsInOrder() []ResponsesOutputItem {
	out := make([]ResponsesOutputItem, 0, len(s.CallOrder))
	for _, index := range s.CallOrder {
		if call, ok := s.Calls[index]; ok && call != nil {
			out = append(out, *call)
		}
	}
	return out
}

// AsResponse renders the accumulated stream as a non-streaming response, so
// the non-streaming audit rules can be applied unchanged.
func (s *ResponsesStreamState) AsResponse() *ResponsesResponse {
	resp := &ResponsesResponse{
		ID:     s.ResponseID,
		Object: "response",
		Model:  s.Model,
		Status: s.Status,
	}
	if s.Text.Len() > 0 {
		resp.Output = append(resp.Output, ResponsesOutputItem{
			Type: "message", Role: "assistant", Status: "completed",
			Content: []ResponsesContentPart{{Type: "output_text", Text: s.Text.String()}},
		})
	}
	if s.Reasoning.Len() > 0 {
		resp.Output = append(resp.Output, ResponsesOutputItem{
			Type:    "reasoning",
			Summary: []ResponsesContentPart{{Type: "summary_text", Text: s.Reasoning.String()}},
		})
	}
	resp.Output = append(resp.Output, s.CallsInOrder()...)
	if s.HasUsage {
		usage := s.Usage
		resp.Usage = &usage
	}
	if s.Error != nil {
		resp.Error = s.Error
	}
	return resp
}

// Terminal reports whether a terminal event has been observed.
func (s *ResponsesStreamState) Terminal() bool {
	switch s.Status {
	case "completed", "incomplete", "failed":
		return true
	}
	return s.Error != nil
}

// IsTerminal reports whether the event ends the stream.
//
// The Responses API has no [DONE] sentinel; a stream ends with response.completed,
// response.incomplete or response.failed, or simply with the connection closing.
// Recognising this is what stops the gateway from waiting for a terminator that
// will never arrive.
func IsResponsesTerminalEvent(name string) bool {
	switch name {
	case "response.completed", "response.incomplete", "response.failed":
		return true
	}
	return false
}

// EventName extracts the event name from a raw Responses SSE event without
// parsing the payload, for the streaming fast path.
func EventName(ev *SSEEvent) string {
	if ev == nil {
		return ""
	}
	if ev.Event != "" {
		return ev.Event
	}
	data := strings.TrimSpace(string(ev.Data))
	if !strings.HasPrefix(data, "{") {
		return ""
	}
	const key = `"type"`
	idx := strings.Index(data, key)
	if idx < 0 {
		return ""
	}
	rest := data[idx+len(key):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[colon+1:])
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	end := strings.IndexByte(rest[1:], '"')
	if end < 0 {
		return ""
	}
	return rest[1 : 1+end]
}

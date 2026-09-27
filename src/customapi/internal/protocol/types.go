// Package protocol holds the wire types the customs gateway inspects.
//
// The gateway is a transparent reverse proxy: it must be able to parse the
// bodies it forwards without altering them. Every type here therefore uses
// json.RawMessage for the parts the gateway does not understand, so that
// unknown or future fields survive a parse/encode round-trip untouched.
package protocol

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Flexible content
// ---------------------------------------------------------------------------

// Content accepts either a plain string or an array of typed content parts,
// which is how OpenAI and Anthropic both model message bodies.
type Content struct {
	// Parts holds the textual/typed pieces in order.
	Parts []ContentPart
	// Raw preserves the original JSON so a round-trip is lossless.
	Raw json.RawMessage
}

// ContentPart is one piece of a message body.
type ContentPart struct {
	Type string `json:"type,omitempty"`
	Text string `json:"text,omitempty"`
	// Name is used by tool_result / tool_use blocks.
	Name string `json:"name,omitempty"`
	// ID identifies a tool_use block, and is referenced by the matching
	// tool_result block. Required for cross-protocol tool round trips.
	ID string `json:"id,omitempty"`
	// Input is the raw JSON of a tool_use input object.
	Input json.RawMessage `json:"input,omitempty"`
	// Content is the nested content of a tool_result block.
	Content *Content `json:"content,omitempty"`
	// ImageURL / Source are preserved but not inspected as text.
	ImageURL *ImageURL       `json:"image_url,omitempty"`
	Source   json.RawMessage `json:"source,omitempty"`
	// CacheControl is preserved verbatim.
	CacheControl json.RawMessage `json:"cache_control,omitempty"`
}

// ImageURL is the OpenAI image reference shape.
type ImageURL struct {
	URL    string `json:"url,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// UnmarshalJSON accepts a string, an array of parts, or null.
func (c *Content) UnmarshalJSON(b []byte) error {
	c.Raw = append(c.Raw[:0], b...)
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		c.Parts = nil
		return nil
	}
	if strings.HasPrefix(trimmed, `"`) {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("content: string form: %w", err)
		}
		c.Parts = []ContentPart{{Type: "text", Text: s}}
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var parts []ContentPart
		if err := json.Unmarshal(b, &parts); err != nil {
			return fmt.Errorf("content: array form: %w", err)
		}
		c.Parts = parts
		return nil
	}
	// Anything else (object, number) is preserved but not interpreted.
	c.Parts = nil
	return nil
}

// MarshalJSON emits the original bytes when available so unknown fields are
// never lost.
func (c Content) MarshalJSON() ([]byte, error) {
	if len(c.Raw) > 0 {
		return c.Raw, nil
	}
	if len(c.Parts) == 1 && c.Parts[0].Type == "text" {
		return json.Marshal(c.Parts[0].Text)
	}
	if c.Parts == nil {
		return []byte("null"), nil
	}
	return json.Marshal(c.Parts)
}

// PartsOrParse returns the content parts, decoding Raw when Parts is empty.
//
// Content produced by json.Unmarshal of an Anthropic body has Raw set but Parts
// nil, because the string shorthand ("content":"hi") does not go through the
// custom UnmarshalJSON. Reading Parts directly would then silently yield no
// content - a translation would drop every message written in the shorthand,
// which is the single most common way to write one. Every consumer that needs
// structure rather than plain text must use this accessor.
func (c Content) PartsOrParse() []ContentPart {
	if len(c.Parts) > 0 || len(c.Raw) == 0 {
		return c.Parts
	}
	return c.decodeRaw()
}

// decodeRaw parses Raw into parts, tolerating both the string and array forms.
func (c Content) decodeRaw() []ContentPart {
	trimmed := strings.TrimSpace(string(c.Raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, `"`) {
		var s string
		if err := json.Unmarshal(c.Raw, &s); err != nil {
			return nil
		}
		if s == "" {
			return nil
		}
		return []ContentPart{{Type: "text", Text: s}}
	}
	var parts []ContentPart
	if err := json.Unmarshal(c.Raw, &parts); err != nil {
		return nil
	}
	return parts
}

// Text returns the concatenated text of all text-bearing parts.
func (c Content) Text() string {
	var sb strings.Builder
	for _, p := range c.PartsOrParse() {
		switch p.Type {
		case "", "text", "input_text", "output_text":
			sb.WriteString(p.Text)
		case "tool_result":
			if p.Content != nil {
				sb.WriteString(p.Content.Text())
			}
		}
	}
	return sb.String()
}

// Plain returns a best-effort plain-text rendering used by audit rules.
func (c Content) Plain() string { return c.Text() }

// TextAndToolInput returns all text-bearing strings, including tool inputs,
// which is what the policy engine needs to scan.
func (c Content) TextAndToolInput() []string {
	var out []string
	for _, p := range c.PartsOrParse() {
		switch p.Type {
		case "", "text", "input_text", "output_text":
			if p.Text != "" {
				out = append(out, p.Text)
			}
		case "tool_use":
			if p.Name != "" {
				out = append(out, p.Name)
			}
			if len(p.Input) > 0 {
				out = append(out, string(p.Input))
			}
		case "tool_result":
			if p.Content != nil {
				out = append(out, p.Content.TextAndToolInput()...)
			}
		}
	}
	return out
}

// IsEmpty reports whether the content carries nothing.
func (c Content) IsEmpty() bool { return len(c.Parts) == 0 }

// ---------------------------------------------------------------------------
// OpenAI-compatible chat completions
// ---------------------------------------------------------------------------

// ChatRequest is an OpenAI-compatible chat completion request.
type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream,omitempty"`
	// MaxTokens / MaxCompletionTokens are both accepted.
	MaxTokens           int             `json:"max_tokens,omitempty"`
	MaxCompletionTokens int             `json:"max_completion_tokens,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	TopP                *float64        `json:"top_p,omitempty"`
	Stop                json.RawMessage `json:"stop,omitempty"`
	Tools               []Tool          `json:"tools,omitempty"`
	ToolChoice          json.RawMessage `json:"tool_choice,omitempty"`
	ResponseFormat      *ResponseFormat `json:"response_format,omitempty"`
	User                string          `json:"user,omitempty"`
	// Extra preserves fields the gateway does not model.
	Extra map[string]json.RawMessage `json:"-"`
}

// ChatMessage is one OpenAI chat message.
type ChatMessage struct {
	Role       string     `json:"role"`
	Content    Content    `json:"content"`
	Name       string     `json:"name,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Refusal    string     `json:"refusal,omitempty"`
	// ReasoningContent carries DeepSeek/vLLM style chain-of-thought.
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

// ToolCall is an OpenAI tool call.
type ToolCall struct {
	Index    *int         `json:"index,omitempty"`
	ID       string       `json:"id,omitempty"`
	Type     string       `json:"type,omitempty"`
	Function FunctionCall `json:"function"`
}

// FunctionCall is the function payload of a tool call.
type FunctionCall struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// Tool is an OpenAI tool definition.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction describes a callable function.
type ToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

// ResponseFormat models structured output requests.
type ResponseFormat struct {
	Type       string          `json:"type"`
	Schema     json.RawMessage `json:"json_schema,omitempty"`
	JSONObject json.RawMessage `json:"-"`
}

// ChatResponse is an OpenAI-compatible chat completion response.
type ChatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   *Usage   `json:"usage,omitempty"`
	// SystemFingerprint is OpenAI's backend identity, useful for
	// fingerprinting which model actually served the request.
	SystemFingerprint string    `json:"system_fingerprint,omitempty"`
	ServiceTier       string    `json:"service_tier,omitempty"`
	Error             *APIError `json:"error,omitempty"`
}

// Choice is one completion alternative.
type Choice struct {
	Index        int             `json:"index"`
	Message      ChatMessage     `json:"message"`
	FinishReason string          `json:"finish_reason,omitempty"`
	Logprobs     json.RawMessage `json:"logprobs,omitempty"`
}

// Usage is the OpenAI usage block.
type Usage struct {
	PromptTokens            int           `json:"prompt_tokens"`
	CompletionTokens        int           `json:"completion_tokens"`
	TotalTokens             int           `json:"total_tokens"`
	PromptTokensDetails     *TokenDetails `json:"prompt_tokens_details,omitempty"`
	CompletionTokensDetails *TokenDetails `json:"completion_tokens_details,omitempty"`
}

// TokenDetails carries cached/reasoning breakdowns.
type TokenDetails struct {
	CachedTokens             int `json:"cached_tokens,omitempty"`
	AudioTokens              int `json:"audio_tokens,omitempty"`
	ReasoningTokens          int `json:"reasoning_tokens,omitempty"`
	AcceptedPredictionTokens int `json:"accepted_prediction_tokens,omitempty"`
	RejectedPredictionTokens int `json:"rejected_prediction_tokens,omitempty"`
}

// StreamChunk is one SSE chunk of a streaming chat completion.
type StreamChunk struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Created int64          `json:"created"`
	Model   string         `json:"model"`
	Choices []StreamChoice `json:"choices"`
	Usage   *Usage         `json:"usage,omitempty"`
	// SystemFingerprint mirrors the non-streaming field.
	SystemFingerprint string    `json:"system_fingerprint,omitempty"`
	Error             *APIError `json:"error,omitempty"`
}

// StreamChoice is one delta choice.
type StreamChoice struct {
	Index        int             `json:"index"`
	Delta        ChatMessage     `json:"delta"`
	FinishReason *string         `json:"finish_reason,omitempty"`
	Logprobs     json.RawMessage `json:"logprobs,omitempty"`
}

// APIError is the OpenAI error envelope.
type APIError struct {
	Message string `json:"message"`
	Type    string `json:"type,omitempty"`
	Param   string `json:"param,omitempty"`
	Code    any    `json:"code,omitempty"`
}

// Error implements the error interface so audit code can log it directly.
func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s (type=%s code=%v)", e.Message, e.Type, e.Code)
}

// ---------------------------------------------------------------------------
// Anthropic Messages API
// ---------------------------------------------------------------------------

// AnthropicRequest is a Messages API request.
type AnthropicRequest struct {
	Model       string             `json:"model"`
	Messages    []AnthropicMessage `json:"messages"`
	System      *Content           `json:"system,omitempty"`
	MaxTokens   int                `json:"max_tokens,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
	Temperature *float64           `json:"temperature,omitempty"`
	TopP        *float64           `json:"top_p,omitempty"`
	TopK        *int               `json:"top_k,omitempty"`
	StopSeqs    []string           `json:"stop_sequences,omitempty"`
	Tools       []AnthropicTool    `json:"tools,omitempty"`
	ToolChoice  json.RawMessage    `json:"tool_choice,omitempty"`
	Thinking    json.RawMessage    `json:"thinking,omitempty"`
	Metadata    json.RawMessage    `json:"metadata,omitempty"`
}

// AnthropicMessage is one Messages API message.
type AnthropicMessage struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

// AnthropicTool is a Messages API tool definition.
type AnthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	Type        string          `json:"type,omitempty"`
}

// AnthropicResponse is a Messages API response.
type AnthropicResponse struct {
	ID           string           `json:"id"`
	Type         string           `json:"type"`
	Role         string           `json:"role"`
	Model        string           `json:"model"`
	Content      []AnthropicBlock `json:"content"`
	StopReason   string           `json:"stop_reason,omitempty"`
	StopSequence string           `json:"stop_sequence,omitempty"`
	Usage        *AnthropicUsage  `json:"usage,omitempty"`
	Error        *AnthropicError  `json:"error,omitempty"`
}

// AnthropicBlock is one content block of a response.
type AnthropicBlock struct {
	Type     string          `json:"type"`
	Text     string          `json:"text,omitempty"`
	Thinking string          `json:"thinking,omitempty"`
	ID       string          `json:"id,omitempty"`
	Name     string          `json:"name,omitempty"`
	Input    json.RawMessage `json:"input,omitempty"`
}

// AnthropicUsage is the Messages API usage block.
type AnthropicUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
}

// AnthropicError is the Messages API error envelope.
type AnthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *AnthropicError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// ToOpenAI converts Anthropic usage into the OpenAI shape so that a single
// metering path can handle both protocols.
func (u *AnthropicUsage) ToOpenAI() Usage {
	if u == nil {
		return Usage{}
	}
	in := u.InputTokens + u.CacheCreationInputTokens + u.CacheReadInputTokens
	return Usage{
		PromptTokens:     in,
		CompletionTokens: u.OutputTokens,
		TotalTokens:      in + u.OutputTokens,
	}
}

// ---------------------------------------------------------------------------
// Models / pricing
// ---------------------------------------------------------------------------

// ModelList is the OpenAI /v1/models response.
type ModelList struct {
	Object string      `json:"object"`
	Data   []ModelInfo `json:"data"`
}

// ModelInfo is one entry of the model list.
type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created,omitempty"`
	OwnedBy string `json:"owned_by,omitempty"`
}

// PromptText extracts every piece of request text worth auditing or counting.
func (r *ChatRequest) PromptText() []string {
	var out []string
	for _, m := range r.Messages {
		out = append(out, m.Content.TextAndToolInput()...)
		if m.ReasoningContent != "" {
			out = append(out, m.ReasoningContent)
		}
	}
	return out
}

// AllToolNames returns the tool names declared by the request.
func (r *ChatRequest) AllToolNames() []string {
	var out []string
	for _, t := range r.Tools {
		out = append(out, t.Function.Name)
	}
	for _, m := range r.Messages {
		for _, tc := range m.ToolCalls {
			out = append(out, tc.Function.Name)
		}
	}
	return out
}

// ResponseText extracts all generated text from a chat response.
func (r *ChatResponse) ResponseText() string {
	var sb strings.Builder
	for _, ch := range r.Choices {
		sb.WriteString(ch.Message.Content.Plain())
	}
	return sb.String()
}

// ReasoningText extracts any chain-of-thought the upstream returned.
func (r *ChatResponse) ReasoningText() string {
	var sb strings.Builder
	for _, ch := range r.Choices {
		sb.WriteString(ch.Message.ReasoningContent)
	}
	return sb.String()
}

// ResponseText extracts all generated text from a Messages response.
func (r *AnthropicResponse) ResponseText() string {
	var sb strings.Builder
	for _, b := range r.Content {
		switch b.Type {
		case "text":
			sb.WriteString(b.Text)
		case "thinking":
			sb.WriteString(b.Thinking)
		}
	}
	return sb.String()
}

// ToolUses returns the tool calls an upstream asked for.
func (r *AnthropicResponse) ToolUses() []AnthropicBlock {
	var out []AnthropicBlock
	for _, b := range r.Content {
		if b.Type == "tool_use" {
			out = append(out, b)
		}
	}
	return out
}

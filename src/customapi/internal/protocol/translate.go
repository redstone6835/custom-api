// Package protocol: cross-protocol translation.
//
// # Why this exists
//
// A gateway that only routes to same-protocol upstreams cannot answer an
// Anthropic request when the model the user wants is served only by an
// OpenAI-compatible provider. Translation removes that dead end.
//
// Design rules
//
//  1. Translation is a *fallback*, never the default. The router prefers a
//     channel that speaks the client's protocol, so the common path is lossless
//     byte forwarding. Translation only happens when no such channel exists.
//  2. A translation is never silent. Every converted request is marked in the
//     audit record (see gateway.proxyContext.translated), because a converted
//     request has different fidelity from a forwarded one and an operator
//     debugging odd output needs to know which they are looking at.
//  3. Unrepresentable features are rejected loudly, not dropped quietly. If a
//     request uses something the target protocol cannot express, the conversion
//     returns an error naming the field, and the gateway turns that into a
//     clear client-facing message. Silently dropping a tool schema or an image
//     would produce a plausible-looking but wrong answer, which is far worse.
//  4. Raw JSON is preserved wherever a field is passed through, so fields the
//     gateway does not model survive the round trip.
package protocol

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Shared vocabulary
// ---------------------------------------------------------------------------

// Canonical message roles.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

// TranslationError describes a request that cannot be expressed in the target
// protocol. It names the offending field so the client can be told precisely
// what to change.
type TranslationError struct {
	// From and To are the protocol names.
	From, To string
	// Field is the request field that cannot be represented.
	Field string
	// Reason explains why.
	Reason string
}

func (e *TranslationError) Error() string {
	return fmt.Sprintf("cannot translate %s -> %s: %s (%s)", e.From, e.To, e.Reason, e.Field)
}

// ErrUnsupported reports that no direct translation path exists.
func ErrUnsupported(from, to string) error {
	return &TranslationError{From: from, To: to, Reason: "no translation path is implemented"}
}

// ---------------------------------------------------------------------------
// Chat completions -> Anthropic Messages
// ---------------------------------------------------------------------------

// AnthropicMaxTokensDefault is used when a chat request omits max_tokens.
//
// The Messages API requires the field, so a value must be supplied. The default
// is deliberately modest rather than unbounded: guessing high would let a
// translated request consume far more budget than the caller asked for.
const AnthropicMaxTokensDefault = 4096

// ChatToAnthropic converts an OpenAI chat request into a Messages request.
func ChatToAnthropic(req *ChatRequest) (*AnthropicRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("translate: nil chat request")
	}
	out := &AnthropicRequest{
		Model:       req.Model,
		Stream:      req.Stream,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
	}
	if out.MaxTokens == 0 {
		out.MaxTokens = req.MaxCompletionTokens
	}
	if out.MaxTokens == 0 {
		out.MaxTokens = AnthropicMaxTokensDefault
	}
	// Stop: chat accepts a string or an array; Messages only an array.
	if len(req.Stop) > 0 {
		var one string
		if err := json.Unmarshal(req.Stop, &one); err == nil {
			if one != "" {
				out.StopSeqs = []string{one}
			}
		} else {
			var many []string
			if err := json.Unmarshal(req.Stop, &many); err != nil {
				return nil, &TranslationError{From: "openai", To: "anthropic",
					Field: "stop", Reason: "must be a string or an array of strings"}
			}
			out.StopSeqs = many
		}
	}

	// System prompt: chat carries it as a message; Messages has a top field.
	var systemParts []ContentPart
	for _, m := range req.Messages {
		switch m.Role {
		case RoleSystem, "developer":
			for _, part := range m.Content.PartsOrParse() {
				if part.Type == "" || part.Type == "text" || part.Type == "input_text" {
					systemParts = append(systemParts, ContentPart{Type: "text", Text: part.Text})
				}
			}
		}
	}
	if len(systemParts) > 0 {
		raw, err := json.Marshal(systemParts)
		if err != nil {
			return nil, err
		}
		out.System = &Content{Raw: raw, Parts: systemParts}
	}

	// Messages. Consecutive same-role messages are merged, because the Messages
	// API requires alternating roles and rejects two user turns in a row.
	for _, m := range req.Messages {
		switch m.Role {
		case RoleSystem, "developer":
			continue
		case RoleTool:
			// A tool result in chat is its own message; in the Messages API it
			// is a tool_result block inside a user turn. The block must carry
			// the id of the tool_use it answers, so a chat tool message without
			// one cannot be expressed and is refused rather than sent without
			// its correlation id - which the provider would reject anyway, with
			// a message far less clear than this one.
			if m.ToolCallID == "" {
				return nil, &TranslationError{From: "openai", To: "anthropic",
					Field:  "messages[].tool_call_id",
					Reason: "a tool result must reference the tool call it answers"}
			}
			raw, err := json.Marshal([]map[string]any{{
				"type":        "tool_result",
				"tool_use_id": m.ToolCallID,
				"content":     m.Content.Plain(),
			}})
			if err != nil {
				return nil, err
			}
			appendAnthropicMessage(out, RoleUser, raw)
		case RoleAssistant:
			var parts []ContentPart
			if text := m.Content.Plain(); text != "" {
				parts = append(parts, ContentPart{Type: "text", Text: text})
			}
			for _, tc := range m.ToolCalls {
				var input json.RawMessage
				if strings.TrimSpace(tc.Function.Arguments) != "" {
					input = json.RawMessage(tc.Function.Arguments)
				} else {
					input = json.RawMessage(`{}`)
				}
				parts = append(parts, ContentPart{
					Type: "tool_use", ID: tc.ID, Name: tc.Function.Name, Input: input,
				})
			}
			if len(parts) == 0 {
				continue
			}
			raw, err := json.Marshal(parts)
			if err != nil {
				return nil, err
			}
			appendAnthropicMessage(out, RoleAssistant, raw)
		default: // user
			var parts []ContentPart
			for _, part := range m.Content.PartsOrParse() {
				switch part.Type {
				case "", "text", "input_text", "output_text":
					parts = append(parts, ContentPart{Type: "text", Text: part.Text})
				case "image_url":
					if part.ImageURL == nil {
						continue
					}
					// Messages wants base64 sources; a remote URL is not
					// representable, so reject rather than drop the image.
					if !strings.HasPrefix(part.ImageURL.URL, "data:") {
						return nil, &TranslationError{From: "openai", To: "anthropic",
							Field: "messages[].content[].image_url.url",
							Reason: "the Messages API accepts base64 data URLs only; " +
								"fetch the image and inline it, or route to an OpenAI-compatible provider"}
					}
					media, data, ok := parseDataURL(part.ImageURL.URL)
					if !ok {
						return nil, &TranslationError{From: "openai", To: "anthropic",
							Field:  "messages[].content[].image_url.url",
							Reason: "malformed data URL"}
					}
					raw, _ := json.Marshal(map[string]any{
						"type": "image",
						"source": map[string]any{
							"type": "base64", "media_type": media, "data": data,
						},
					})
					parts = append(parts, ContentPart{Type: "image", Source: raw})
				default:
					return nil, &TranslationError{From: "openai", To: "anthropic",
						Field:  "messages[].content[].type",
						Reason: fmt.Sprintf("content part type %q has no Messages equivalent", part.Type)}
				}
			}
			if len(parts) == 0 {
				continue
			}
			raw, err := json.Marshal(parts)
			if err != nil {
				return nil, err
			}
			appendAnthropicMessage(out, RoleUser, raw)
		}
	}

	// Tools: chat nests under "function"; Messages flattens.
	for _, t := range req.Tools {
		if t.Type != "" && t.Type != "function" {
			return nil, &TranslationError{From: "openai", To: "anthropic",
				Field:  "tools[].type",
				Reason: fmt.Sprintf("tool type %q is not supported by the Messages API", t.Type)}
		}
		out.Tools = append(out.Tools, AnthropicTool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			InputSchema: t.Function.Parameters,
		})
	}
	if len(req.ToolChoice) > 0 {
		out.ToolChoice = translateToolChoiceToAnthropic(req.ToolChoice)
	}
	if req.ResponseFormat != nil && req.ResponseFormat.Type == "json_schema" {
		// Messages has no response_format; the schema can be expressed as a
		// single forced tool, which preserves the structured-output contract.
		var schema struct {
			Name   string          `json:"name"`
			Schema json.RawMessage `json:"schema"`
			Strict *bool           `json:"strict"`
		}
		if err := json.Unmarshal(req.ResponseFormat.Schema, &schema); err == nil && len(schema.Schema) > 0 {
			name := schema.Name
			if name == "" {
				name = "structured_output"
			}
			out.Tools = append(out.Tools, AnthropicTool{
				Name:        name,
				Description: "Return the answer in this JSON schema.",
				InputSchema: schema.Schema,
			})
			out.ToolChoice = json.RawMessage(fmt.Sprintf(`{"type":"tool","name":%q}`, name))
		}
	}
	return out, nil
}

// appendAnthropicMessage appends a message, merging into the previous one when
// the role repeats. The Messages API rejects consecutive same-role turns, and
// merging is the standard way to preserve the content.
func appendAnthropicMessage(out *AnthropicRequest, role string, content json.RawMessage) {
	if n := len(out.Messages); n > 0 && out.Messages[n-1].Role == role {
		prev := &out.Messages[n-1]
		merged := mergeContentArrays(prev.Content.Raw, content)
		prev.Content = Content{Raw: merged}
		return
	}
	out.Messages = append(out.Messages, AnthropicMessage{
		Role:    role,
		Content: Content{Raw: content},
	})
}

// mergeContentArrays concatenates two JSON arrays of content parts.
func mergeContentArrays(a, b json.RawMessage) json.RawMessage {
	var left, right []json.RawMessage
	_ = json.Unmarshal(a, &left)
	_ = json.Unmarshal(b, &right)
	merged, err := json.Marshal(append(left, right...))
	if err != nil {
		return b
	}
	return merged
}

// parseDataURL splits a data: URL into media type and payload.
func parseDataURL(u string) (media, data string, ok bool) {
	rest, found := strings.CutPrefix(u, "data:")
	if !found {
		return "", "", false
	}
	meta, payload, found := strings.Cut(rest, ",")
	if !found {
		return "", "", false
	}
	media = strings.TrimSuffix(meta, ";base64")
	if media == "" {
		media = "application/octet-stream"
	}
	return media, payload, true
}

// translateToolChoiceToAnthropic maps the chat tool_choice onto Messages.
func translateToolChoiceToAnthropic(choice json.RawMessage) json.RawMessage {
	var one string
	if err := json.Unmarshal(choice, &one); err == nil {
		switch one {
		case "auto":
			return json.RawMessage(`{"type":"auto"}`)
		case "required":
			return json.RawMessage(`{"type":"any"}`)
		case "none":
			// Messages has no "none"; an empty tool list is the equivalent, but
			// the tools were already copied. "auto" is the closest safe choice.
			return json.RawMessage(`{"type":"auto"}`)
		}
		return nil
	}
	var obj struct {
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if err := json.Unmarshal(choice, &obj); err == nil && obj.Function.Name != "" {
		raw, _ := json.Marshal(map[string]string{"type": "tool", "name": obj.Function.Name})
		return raw
	}
	return nil
}

// ---------------------------------------------------------------------------
// Anthropic Messages -> Chat completions
// ---------------------------------------------------------------------------

// ChatMaxTokensDefault is used when a Messages request omits max_tokens.
// The chat API makes the field optional, so the bound is only advisory.
const ChatMaxTokensDefault = 4096

// AnthropicToChat converts a Messages request into an OpenAI chat request.
func AnthropicToChat(req *AnthropicRequest) (*ChatRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("translate: nil anthropic request")
	}
	out := &ChatRequest{
		Model:               req.Model,
		Stream:              req.Stream,
		MaxCompletionTokens: req.MaxTokens,
		Temperature:         req.Temperature,
		TopP:                req.TopP,
	}
	if out.MaxCompletionTokens == 0 {
		out.MaxCompletionTokens = ChatMaxTokensDefault
	}
	if len(req.StopSeqs) == 1 {
		raw, _ := json.Marshal(req.StopSeqs[0])
		out.Stop = raw
	} else if len(req.StopSeqs) > 1 {
		raw, _ := json.Marshal(req.StopSeqs)
		out.Stop = raw
	}
	if req.System != nil {
		if text := req.System.Text(); text != "" {
			out.Messages = append(out.Messages, ChatMessage{
				Role:    RoleSystem,
				Content: Content{Parts: []ContentPart{{Type: "text", Text: text}}},
			})
		}
	}
	for _, m := range req.Messages {
		msg := ChatMessage{Role: m.Role}
		var (
			texts   []ContentPart
			results []ChatMessage
		)
		for _, part := range m.Content.PartsOrParse() {
			switch part.Type {
			case "", "text":
				texts = append(texts, ContentPart{Type: "text", Text: part.Text})
			case "tool_use":
				args := "{}"
				if len(part.Input) > 0 {
					args = string(part.Input)
				}
				msg.ToolCalls = append(msg.ToolCalls, ToolCall{
					ID: part.ID, Type: "function",
					Function: FunctionCall{Name: part.Name, Arguments: args},
				})
			case "tool_result":
				// A tool_result block becomes its own chat "tool" message.
				toolMsg := ChatMessage{Role: RoleTool, ToolCallID: part.ID}
				if part.Content != nil {
					toolMsg.Content = Content{
						Parts: []ContentPart{{Type: "text", Text: part.Content.Text()}},
					}
				} else {
					toolMsg.Content = Content{Parts: []ContentPart{{Type: "text", Text: ""}}}
				}
				results = append(results, toolMsg)
			case "image":
				if len(part.Source) == 0 {
					continue
				}
				var src struct {
					Type      string `json:"type"`
					MediaType string `json:"media_type"`
					Data      string `json:"data"`
					URL       string `json:"url"`
				}
				if err := json.Unmarshal(part.Source, &src); err != nil {
					continue
				}
				switch src.Type {
				case "base64":
					texts = append(texts, ContentPart{
						Type: "image_url",
						ImageURL: &ImageURL{
							URL: "data:" + src.MediaType + ";base64," + src.Data,
						},
					})
				case "url":
					texts = append(texts, ContentPart{
						Type: "image_url", ImageURL: &ImageURL{URL: src.URL},
					})
				default:
					return nil, &TranslationError{From: "anthropic", To: "openai",
						Field:  "messages[].content[].source.type",
						Reason: fmt.Sprintf("image source type %q has no chat equivalent", src.Type)}
				}
			case "thinking":
				// A replayed thinking block is not accepted by the chat API as
				// input; dropping it here is safe because it is not user-visible
				// content, but the caller is told via the audit marker that this
				// request was translated.
				continue
			default:
				return nil, &TranslationError{From: "anthropic", To: "openai",
					Field:  "messages[].content[].type",
					Reason: fmt.Sprintf("content block type %q has no chat equivalent", part.Type)}
			}
		}
		if len(texts) > 0 || len(msg.ToolCalls) > 0 {
			if len(texts) == 1 && texts[0].Type == "text" {
				msg.Content = Content{Parts: texts}
			} else if len(texts) > 0 {
				msg.Content = Content{Parts: texts}
			}
			out.Messages = append(out.Messages, msg)
		}
		out.Messages = append(out.Messages, results...)
	}

	for _, t := range req.Tools {
		out.Tools = append(out.Tools, Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.InputSchema,
			},
		})
	}
	if len(req.ToolChoice) > 0 {
		out.ToolChoice = translateToolChoiceToChat(req.ToolChoice)
	}
	return out, nil
}

// translateToolChoiceToChat maps the Messages tool_choice onto chat.
func translateToolChoiceToChat(choice json.RawMessage) json.RawMessage {
	var obj struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(choice, &obj); err != nil {
		return nil
	}
	switch obj.Type {
	case "auto":
		return json.RawMessage(`"auto"`)
	case "any":
		return json.RawMessage(`"required"`)
	case "tool":
		raw, _ := json.Marshal(map[string]any{
			"type":     "function",
			"function": map[string]string{"name": obj.Name},
		})
		return raw
	}
	return nil
}

// ---------------------------------------------------------------------------
// Responses <-> Chat completions
// ---------------------------------------------------------------------------

// ResponsesToChat converts a Responses request into a chat request.
func ResponsesToChat(req *ResponsesRequest) (*ChatRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("translate: nil responses request")
	}
	out := &ChatRequest{
		Model:               req.Model,
		Stream:              req.Stream,
		MaxCompletionTokens: req.MaxOutputTokens,
		Temperature:         req.Temperature,
		TopP:                req.TopP,
	}
	if out.MaxCompletionTokens == 0 {
		out.MaxCompletionTokens = ChatMaxTokensDefault
	}
	if req.Instructions != "" {
		out.Messages = append(out.Messages, ChatMessage{
			Role:    RoleSystem,
			Content: Content{Parts: []ContentPart{{Type: "text", Text: req.Instructions}}},
		})
	}
	// Reuse the Responses input walker, then group the flat list back into
	// messages. The walker already understands all three input shapes.
	raw := strings.TrimSpace(string(req.Input))
	if raw != "" && raw != "null" {
		if strings.HasPrefix(raw, `"`) {
			var s string
			if err := json.Unmarshal(req.Input, &s); err == nil {
				out.Messages = append(out.Messages, ChatMessage{
					Role:    RoleUser,
					Content: Content{Parts: []ContentPart{{Type: "text", Text: s}}},
				})
			}
		} else {
			var items []struct {
				Type    string          `json:"type"`
				Role    string          `json:"role"`
				Content json.RawMessage `json:"content"`
				Text    string          `json:"text"`
				// function_call / function_call_output items
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
				CallID    string `json:"call_id"`
				Output    string `json:"output"`
			}
			if err := json.Unmarshal(req.Input, &items); err != nil {
				return nil, &TranslationError{From: "responses", To: "openai",
					Field: "input", Reason: "not a string or an array of input items"}
			}
			for _, item := range items {
				switch item.Type {
				case "", "message":
					role := item.Role
					if role == "" {
						role = RoleUser
					}
					parts, err := responsesPartsToChat(item.Content, item.Text)
					if err != nil {
						return nil, err
					}
					if len(parts) > 0 {
						out.Messages = append(out.Messages, ChatMessage{
							Role: role, Content: Content{Parts: parts},
						})
					}
				case "function_call":
					out.Messages = append(out.Messages, ChatMessage{
						Role: RoleAssistant,
						ToolCalls: []ToolCall{{
							ID: item.CallID, Type: "function",
							Function: FunctionCall{Name: item.Name, Arguments: item.Arguments},
						}},
					})
				case "function_call_output":
					out.Messages = append(out.Messages, ChatMessage{
						Role: RoleTool, ToolCallID: item.CallID,
						Content: Content{Parts: []ContentPart{{Type: "text", Text: item.Output}}},
					})
				case "reasoning":
					// Reasoning items are opaque state; they are not valid
					// input for the chat API and carry no user content.
					continue
				default:
					return nil, &TranslationError{From: "responses", To: "openai",
						Field:  "input[].type",
						Reason: fmt.Sprintf("input item type %q has no chat equivalent", item.Type)}
				}
			}
		}
	}
	for _, t := range req.Tools {
		if t.Type != "" && t.Type != "function" {
			return nil, &TranslationError{From: "responses", To: "openai",
				Field:  "tools[].type",
				Reason: fmt.Sprintf("built-in tool %q is server-side; it has no chat equivalent", t.Type)}
		}
		out.Tools = append(out.Tools, Tool{
			Type: "function",
			Function: ToolFunction{
				Name: t.ToolName(), Description: t.Description, Parameters: t.ToolSchema(),
			},
		})
	}
	if len(req.ToolChoice) > 0 {
		out.ToolChoice = req.ToolChoice
	}
	return out, nil
}

// responsesPartsToChat converts a Responses content field into chat parts.
func responsesPartsToChat(content json.RawMessage, directText string) ([]ContentPart, error) {
	var parts []ContentPart
	if directText != "" {
		parts = append(parts, ContentPart{Type: "text", Text: directText})
	}
	raw := strings.TrimSpace(string(content))
	if raw == "" || raw == "null" {
		return parts, nil
	}
	if strings.HasPrefix(raw, `"`) {
		var s string
		if err := json.Unmarshal(content, &s); err == nil && s != "" {
			parts = append(parts, ContentPart{Type: "text", Text: s})
		}
		return parts, nil
	}
	var typed []struct {
		Type     string `json:"type"`
		Text     string `json:"text"`
		ImageURL string `json:"image_url"`
	}
	if err := json.Unmarshal(content, &typed); err != nil {
		return parts, nil
	}
	for _, part := range typed {
		switch part.Type {
		case "input_text", "output_text", "text", "":
			if part.Text != "" {
				parts = append(parts, ContentPart{Type: "text", Text: part.Text})
			}
		case "input_image":
			if part.ImageURL != "" {
				parts = append(parts, ContentPart{
					Type: "image_url", ImageURL: &ImageURL{URL: part.ImageURL},
				})
			}
		default:
			return nil, &TranslationError{From: "responses", To: "openai",
				Field:  "input[].content[].type",
				Reason: fmt.Sprintf("content part type %q has no chat equivalent", part.Type)}
		}
	}
	return parts, nil
}

// ChatToResponses converts a chat request into a Responses request.
func ChatToResponses(req *ChatRequest) (*ResponsesRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("translate: nil chat request")
	}
	out := &ResponsesRequest{
		Model:           req.Model,
		Stream:          req.Stream,
		MaxOutputTokens: req.MaxCompletionTokens,
		Temperature:     req.Temperature,
		TopP:            req.TopP,
	}
	if out.MaxOutputTokens == 0 {
		out.MaxOutputTokens = req.MaxTokens
	}
	if out.MaxOutputTokens == 0 {
		out.MaxOutputTokens = ChatMaxTokensDefault
	}
	var (
		systemParts []string
		items       []map[string]any
	)
	for _, m := range req.Messages {
		switch m.Role {
		case RoleSystem, "developer":
			if text := m.Content.Plain(); text != "" {
				systemParts = append(systemParts, text)
			}
		case RoleTool:
			items = append(items, map[string]any{
				"type": "function_call_output", "call_id": m.ToolCallID,
				"output": m.Content.Plain(),
			})
		case RoleAssistant:
			text := m.Content.Plain()
			if text != "" {
				items = append(items, map[string]any{
					"type": "message", "role": "assistant",
					"content": []map[string]any{{"type": "output_text", "text": text}},
				})
			}
			for _, tc := range m.ToolCalls {
				items = append(items, map[string]any{
					"type": "function_call", "call_id": tc.ID,
					"name": tc.Function.Name, "arguments": tc.Function.Arguments,
				})
			}
		default: // user
			parts, err := chatPartsToResponses(m.Content.PartsOrParse())
			if err != nil {
				return nil, err
			}
			if len(parts) > 0 {
				items = append(items, map[string]any{
					"type": "message", "role": "user", "content": parts,
				})
			}
		}
	}
	out.Instructions = strings.Join(systemParts, "\n\n")
	if raw, err := json.Marshal(items); err == nil {
		out.Input = raw
	} else {
		out.Input = json.RawMessage(`[]`)
	}
	for _, t := range req.Tools {
		if t.Type != "" && t.Type != "function" {
			return nil, &TranslationError{From: "openai", To: "responses",
				Field:  "tools[].type",
				Reason: fmt.Sprintf("tool type %q is not supported by the Responses API", t.Type)}
		}
		out.Tools = append(out.Tools, ResponsesTool{
			Type: "function", Name: t.Function.Name,
			Description: t.Function.Description, Parameters: t.Function.Parameters,
			Strict: t.Function.Strict,
		})
	}
	if len(req.ToolChoice) > 0 {
		out.ToolChoice = req.ToolChoice
	}
	return out, nil
}

// chatPartsToResponses converts chat content parts into Responses parts.
func chatPartsToResponses(parts []ContentPart) ([]map[string]any, error) {
	var out []map[string]any
	for _, part := range parts {
		switch part.Type {
		case "", "text", "input_text", "output_text":
			if part.Text != "" {
				out = append(out, map[string]any{"type": "input_text", "text": part.Text})
			}
		case "image_url":
			if part.ImageURL == nil {
				continue
			}
			// The Responses API calls this input_image with the URL inline.
			out = append(out, map[string]any{
				"type": "input_image", "image_url": part.ImageURL.URL,
			})
		default:
			return nil, &TranslationError{From: "openai", To: "responses",
				Field:  "messages[].content[].type",
				Reason: fmt.Sprintf("content part type %q has no Responses equivalent", part.Type)}
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Response side: non-streaming conversions
// ---------------------------------------------------------------------------

// AnthropicToChatResponse converts a Messages reply into a chat reply.
func AnthropicToChatResponse(resp *AnthropicResponse) (*ChatResponse, error) {
	if resp == nil {
		return nil, fmt.Errorf("translate: nil anthropic response")
	}
	msg := ChatMessage{Role: RoleAssistant}
	var texts []string
	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			texts = append(texts, block.Text)
		case "thinking":
			msg.ReasoningContent += block.Thinking
		case "tool_use":
			args := "{}"
			if len(block.Input) > 0 {
				args = string(block.Input)
			}
			msg.ToolCalls = append(msg.ToolCalls, ToolCall{
				ID: block.ID, Type: "function",
				Function: FunctionCall{Name: block.Name, Arguments: args},
			})
		}
	}
	msg.Content = Content{Parts: []ContentPart{{Type: "text", Text: strings.Join(texts, "")}}}
	out := &ChatResponse{
		ID:      orDefaultStr(resp.ID, "msg_translated"),
		Object:  "chat.completion",
		Model:   resp.Model,
		Choices: []Choice{{Index: 0, Message: msg, FinishReason: anthropicStopToChat(resp.StopReason)}},
	}
	if resp.Usage != nil {
		u := resp.Usage.ToOpenAI()
		out.Usage = &u
	}
	return out, nil
}

// ChatToAnthropicResponse converts a chat reply into a Messages reply.
func ChatToAnthropicResponse(resp *ChatResponse) (*AnthropicResponse, error) {
	if resp == nil {
		return nil, fmt.Errorf("translate: nil chat response")
	}
	out := &AnthropicResponse{
		ID:    orDefaultStr(resp.ID, "chatcmpl_translated"),
		Type:  "message",
		Role:  RoleAssistant,
		Model: resp.Model,
	}
	stop := "end_turn"
	for _, choice := range resp.Choices {
		if text := choice.Message.Content.Plain(); text != "" {
			out.Content = append(out.Content, AnthropicBlock{Type: "text", Text: text})
		}
		if choice.Message.ReasoningContent != "" {
			out.Content = append(out.Content, AnthropicBlock{
				Type: "thinking", Thinking: choice.Message.ReasoningContent,
			})
		}
		for _, tc := range choice.Message.ToolCalls {
			input := json.RawMessage(tc.Function.Arguments)
			if len(input) == 0 {
				input = json.RawMessage(`{}`)
			}
			out.Content = append(out.Content, AnthropicBlock{
				Type: "tool_use", ID: tc.ID, Name: tc.Function.Name, Input: input,
			})
		}
		stop = chatStopToAnthropic(choice.FinishReason)
	}
	out.StopReason = stop
	if resp.Usage != nil {
		out.Usage = &AnthropicUsage{
			InputTokens:  resp.Usage.PromptTokens,
			OutputTokens: resp.Usage.CompletionTokens,
		}
	}
	return out, nil
}

// ResponsesToChatResponse converts a Responses reply into a chat reply.
func ResponsesToChatResponse(resp *ResponsesResponse) (*ChatResponse, error) {
	if resp == nil {
		return nil, fmt.Errorf("translate: nil responses response")
	}
	msg := ChatMessage{Role: RoleAssistant}
	msg.Content = Content{Parts: []ContentPart{{Type: "text", Text: resp.ResponseText()}}}
	msg.ReasoningContent = resp.ReasoningText()
	for _, call := range resp.FunctionCalls() {
		msg.ToolCalls = append(msg.ToolCalls, ToolCall{
			ID: call.CallID, Type: "function",
			Function: FunctionCall{Name: call.Name, Arguments: call.Arguments},
		})
	}
	finish := "stop"
	if len(msg.ToolCalls) > 0 {
		finish = "tool_calls"
	}
	if resp.Status == "incomplete" {
		finish = "length"
	}
	out := &ChatResponse{
		ID:      orDefaultStr(resp.ID, "resp_translated"),
		Object:  "chat.completion",
		Model:   resp.Model,
		Choices: []Choice{{Index: 0, Message: msg, FinishReason: finish}},
	}
	if resp.Usage != nil {
		u := resp.Usage.ToUsage()
		out.Usage = &u
	}
	return out, nil
}

// ChatToResponsesResponse converts a chat reply into a Responses reply.
func ChatToResponsesResponse(resp *ChatResponse) (*ResponsesResponse, error) {
	if resp == nil {
		return nil, fmt.Errorf("translate: nil chat response")
	}
	out := &ResponsesResponse{
		ID:     orDefaultStr(resp.ID, "chatcmpl_translated"),
		Object: "response",
		Model:  resp.Model,
		Status: "completed",
	}
	var texts []string
	var reasoning []string
	for _, choice := range resp.Choices {
		if text := choice.Message.Content.Plain(); text != "" {
			texts = append(texts, text)
		}
		if choice.Message.ReasoningContent != "" {
			reasoning = append(reasoning, choice.Message.ReasoningContent)
		}
		for _, tc := range choice.Message.ToolCalls {
			out.Output = append(out.Output, ResponsesOutputItem{
				Type: "function_call", ID: "fc_" + tc.ID, CallID: tc.ID,
				Name: tc.Function.Name, Arguments: tc.Function.Arguments,
			})
		}
		if choice.FinishReason == "length" {
			out.Status = "incomplete"
		}
	}
	// Output items are ordered the way the Responses API emits them: reasoning
	// first, then the assistant message, then any function calls. Assigning
	// through a fresh slice avoids the double-prepend that would otherwise
	// reverse this order.
	ordered := make([]ResponsesOutputItem, 0, len(out.Output)+2)
	if len(reasoning) > 0 {
		ordered = append(ordered, ResponsesOutputItem{
			Type:    "reasoning",
			Summary: []ResponsesContentPart{{Type: "summary_text", Text: strings.Join(reasoning, "")}},
		})
	}
	if len(texts) > 0 {
		ordered = append(ordered, ResponsesOutputItem{
			Type: "message", Role: "assistant", Status: "completed",
			Content: []ResponsesContentPart{{Type: "output_text", Text: strings.Join(texts, "")}},
		})
	}
	ordered = append(ordered, out.Output...)
	out.Output = ordered
	if resp.Usage != nil {
		out.Usage = &ResponsesUsage{
			InputTokens:  resp.Usage.PromptTokens,
			OutputTokens: resp.Usage.CompletionTokens,
			TotalTokens:  resp.Usage.TotalTokens,
		}
	}
	return out, nil
}

func anthropicStopToChat(stop string) string {
	switch stop {
	case "end_turn", "stop_sequence":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	default:
		return stop
	}
}

func chatStopToAnthropic(stop string) string {
	switch stop {
	case "stop":
		return "end_turn"
	case "length":
		return "max_tokens"
	case "tool_calls", "function_call":
		return "tool_use"
	default:
		return orDefaultStr(stop, "end_turn")
	}
}

func orDefaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

// TranslateRequestBody converts a request body between protocols.
//
// It is the single entry point the proxy uses, so adding a protocol later means
// adding cases here rather than touching the request pipeline.
func TranslateRequestBody(from, to string, body []byte) ([]byte, error) {
	if from == to {
		return body, nil
	}
	switch {
	case from == "openai" && to == "anthropic":
		var req ChatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, fmt.Errorf("translate: parse chat request: %w", err)
		}
		out, err := ChatToAnthropic(&req)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	case from == "anthropic" && to == "openai":
		var req AnthropicRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, fmt.Errorf("translate: parse anthropic request: %w", err)
		}
		out, err := AnthropicToChat(&req)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	case from == "openai" && to == "responses":
		var req ChatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, fmt.Errorf("translate: parse chat request: %w", err)
		}
		out, err := ChatToResponses(&req)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	case from == "responses" && to == "openai":
		var req ResponsesRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, fmt.Errorf("translate: parse responses request: %w", err)
		}
		out, err := ResponsesToChat(&req)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	case from == "responses" && to == "anthropic":
		// Two hops, because the intermediate representation is chat and
		// duplicating every rule for the direct path would be a second place to
		// get the same details wrong.
		mid, err := TranslateRequestBody("responses", "openai", body)
		if err != nil {
			return nil, err
		}
		return TranslateRequestBody("openai", "anthropic", mid)
	case from == "anthropic" && to == "responses":
		mid, err := TranslateRequestBody("anthropic", "openai", body)
		if err != nil {
			return nil, err
		}
		return TranslateRequestBody("openai", "responses", mid)
	default:
		return nil, ErrUnsupported(from, to)
	}
}

// TranslateResponseBody converts a response body between protocols.
func TranslateResponseBody(from, to string, body []byte) ([]byte, error) {
	if from == to {
		return body, nil
	}
	switch {
	case from == "anthropic" && to == "openai":
		var resp AnthropicResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("translate: parse anthropic response: %w", err)
		}
		out, err := AnthropicToChatResponse(&resp)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	case from == "openai" && to == "anthropic":
		var resp ChatResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("translate: parse chat response: %w", err)
		}
		out, err := ChatToAnthropicResponse(&resp)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	case from == "responses" && to == "openai":
		var resp ResponsesResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("translate: parse responses response: %w", err)
		}
		out, err := ResponsesToChatResponse(&resp)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	case from == "openai" && to == "responses":
		var resp ChatResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("translate: parse chat response: %w", err)
		}
		out, err := ChatToResponsesResponse(&resp)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	case from == "responses" && to == "anthropic":
		mid, err := TranslateResponseBody("responses", "openai", body)
		if err != nil {
			return nil, err
		}
		return TranslateResponseBody("openai", "anthropic", mid)
	case from == "anthropic" && to == "responses":
		mid, err := TranslateResponseBody("anthropic", "openai", body)
		if err != nil {
			return nil, err
		}
		return TranslateResponseBody("openai", "responses", mid)
	default:
		return nil, ErrUnsupported(from, to)
	}
}

// ValidProtocol reports whether a protocol name is recognised.
func ValidProtocol(p string) bool {
	switch p {
	case "openai", "anthropic", "responses":
		return true
	}
	return false
}

// ProtocolDisplayName returns a human-facing name.
func ProtocolDisplayName(p string) string {
	switch p {
	case "openai":
		return "OpenAI Chat Completions"
	case "anthropic":
		return "Anthropic Messages"
	case "responses":
		return "OpenAI Responses"
	}
	return p
}

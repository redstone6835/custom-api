package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ---------------------------------------------------------------------------
// Protocol detection
// ---------------------------------------------------------------------------

// DetectProtocol guesses which wire protocol a request body speaks.
//
// The gateway uses this when a channel is configured for automatic protocol
// selection. It is intentionally conservative: an ambiguous body is reported
// as OpenAI-compatible, matching the plan's "OpenAI first" milestone order.
func DetectProtocol(path string, body []byte) string {
	switch {
	case strings.HasSuffix(path, "/v1/messages"):
		return "anthropic"
	case strings.Contains(path, "/v1/complete"):
		return "anthropic"
	// /v1/responses is its own protocol, not a spelling of chat completions:
	// the request, response and streaming event models all differ, so the
	// gateway parses it natively and can translate to and from it.
	case strings.HasSuffix(path, "/v1/responses"):
		return "responses"
	case strings.HasSuffix(path, "/v1/chat/completions"),
		strings.HasSuffix(path, "/v1/completions"),
		strings.HasSuffix(path, "/v1/embeddings"):
		return "openai"
	}
	// Fall back to shape sniffing, since the two APIs differ in ways that can
	// be scored rather than guessed at:
	//
	//	anthropic_version        - decisive, OpenAI has no such field
	//	top-level system         - OpenAI puts the system prompt in messages
	//	system + max_tokens      - the canonical minimal Messages request
	//	assistant prefill/tools  - both, so not decisive
	//
	// The scoring form is used so that a body which merely happens to carry
	// one Anthropic-ish field is not misclassified.
	var probe struct {
		System           json.RawMessage `json:"system"`
		AnthropicVersion string          `json:"anthropic_version"`
		MaxTokens        *int            `json:"max_tokens"`
		TopP             *float64        `json:"top_p"`
		StopSequences    json.RawMessage `json:"stop_sequences"`
		Messages         []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "openai"
	}
	if probe.AnthropicVersion != "" {
		return "anthropic"
	}
	// Shape check for the Responses API before the chat heuristics: it is
	// identified by an `input` field (string or array) with no `messages`.
	var rprobe struct {
		Input        json.RawMessage `json:"input"`
		Messages     json.RawMessage `json:"messages"`
		Instructions string          `json:"instructions"`
	}
	if err := json.Unmarshal(body, &rprobe); err == nil {
		if len(rprobe.Messages) == 0 && (len(rprobe.Input) > 0 || rprobe.Instructions != "") {
			return "responses"
		}
	}
	score := 0
	if probe.System != nil {
		score += 2
	}
	if len(probe.StopSequences) > 0 {
		// OpenAI calls this field "stop"; its presence under the Anthropic
		// name is decisive on its own.
		score += 2
	}
	if probe.MaxTokens != nil && probe.System != nil {
		score += 2
	}
	// The Messages API has no "developer" role and never places a "system"
	// entry inside messages; a system message is a strong OpenAI signal.
	for _, m := range probe.Messages {
		if m.Role == "system" || m.Role == "developer" {
			score -= 2
		}
	}
	if score >= 2 {
		return "anthropic"
	}
	return "openai"
}

// IsStreaming reports whether a request body asks for a streamed response.
func IsStreaming(body []byte) bool {
	var probe struct {
		Stream bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return probe.Stream
}

// Model extracts the top-level "model" field without fully parsing the body.
func Model(body []byte) string {
	raw := TopLevelString(body, "model")
	if len(raw) == 0 {
		return ""
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return v
}

// ---------------------------------------------------------------------------
// In-place field rewriting
// ---------------------------------------------------------------------------

// TopLevelString returns the raw JSON value bytes of a top-level string field.
//
// It walks the object byte-wise tracking depth and string state rather than
// unmarshalling, so that unknown fields, key order and whitespace are all
// preserved when the caller splices a replacement back in.
func TopLevelString(body []byte, field string) []byte {
	_, val := topLevelField(body, field)
	return val
}

// ReplaceTopLevelString returns a copy of body with a top-level string field
// replaced by value.
//
// When the field is absent, the encoded field is appended before the closing
// brace. When body is not a JSON object, body is returned unchanged. The
// original slice is never mutated.
func ReplaceTopLevelString(body []byte, field, value string) []byte {
	start, _ := topLevelField(body, field)
	encoded, err := json.Marshal(value)
	if err != nil {
		return body
	}
	if start < 0 {
		return appendField(body, field, encoded)
	}
	// start points at the opening quote of the value.
	end := start + 1
	for end < len(body) {
		if body[end] == '\\' {
			end += 2
			continue
		}
		if body[end] == '"' {
			end++
			break
		}
		end++
	}
	out := make([]byte, 0, len(body)-(end-start)+len(encoded))
	out = append(out, body[:start]...)
	out = append(out, encoded...)
	out = append(out, body[end:]...)
	return out
}

// topLevelField locates a top-level field, returning the byte offset where its
// value begins and the raw value bytes. A start of -1 means "not found".
func topLevelField(body []byte, field string) (int, []byte) {
	i := skipSpace(body, 0)
	if i >= len(body) || body[i] != '{' {
		return -1, nil
	}
	i++
	depth := 1
	for i < len(body) {
		i = skipSpace(body, i)
		if i >= len(body) {
			return -1, nil
		}
		if body[i] == '}' {
			depth--
			if depth == 0 {
				return -1, nil
			}
			i++
			continue
		}
		if body[i] == ',' {
			i++
			continue
		}
		if body[i] != '"' {
			// Unexpected token at object level; give up rather than guess.
			return -1, nil
		}
		keyStart := i
		keyEnd, ok := scanString(body, keyStart)
		if !ok {
			return -1, nil
		}
		var name string
		if err := json.Unmarshal(body[keyStart:keyEnd], &name); err != nil {
			return -1, nil
		}
		i = skipSpace(body, keyEnd)
		if i >= len(body) || body[i] != ':' {
			return -1, nil
		}
		i = skipSpace(body, i+1)
		valStart := i
		valEnd, ok := scanValue(body, valStart)
		if !ok {
			return -1, nil
		}
		if name == field {
			return valStart, body[valStart:valEnd]
		}
		i = valEnd
	}
	return -1, nil
}

// appendField inserts a field before the final closing brace.
func appendField(body []byte, field string, encodedValue []byte) []byte {
	end := len(body)
	for end > 0 && (body[end-1] == ' ' || body[end-1] == '\n' || body[end-1] == '\t' || body[end-1] == '\r') {
		end--
	}
	if end == 0 || body[end-1] != '}' {
		return body
	}
	// Detect an empty object to avoid emitting a leading comma.
	inner := bytes.TrimSpace(body[1 : end-1])
	sep := []byte(",")
	if len(inner) == 0 {
		sep = nil
	}
	out := make([]byte, 0, len(body)+len(field)+len(encodedValue)+4)
	out = append(out, body[:end-1]...)
	out = append(out, sep...)
	keyJSON, err := json.Marshal(field)
	if err != nil {
		return body
	}
	out = append(out, keyJSON...)
	out = append(out, ':')
	out = append(out, encodedValue...)
	out = append(out, body[end-1:]...)
	return out
}

func skipSpace(b []byte, i int) int {
	for i < len(b) {
		switch b[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// scanString returns the offset just past the closing quote of a JSON string
// starting at i.
func scanString(b []byte, i int) (int, bool) {
	if i >= len(b) || b[i] != '"' {
		return 0, false
	}
	i++
	for i < len(b) {
		switch b[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1, true
		default:
			i++
		}
	}
	return 0, false
}

// scanValue returns the offset just past a JSON value starting at i.
func scanValue(b []byte, i int) (int, bool) {
	if i >= len(b) {
		return 0, false
	}
	switch b[i] {
	case '"':
		return scanString(b, i)
	case '{', '[':
		open := b[i]
		closeCh := byte('}')
		if open == '[' {
			closeCh = ']'
		}
		depth := 0
		for i < len(b) {
			switch b[i] {
			case '"':
				end, ok := scanString(b, i)
				if !ok {
					return 0, false
				}
				i = end
				continue
			case open:
				depth++
			case closeCh:
				depth--
				if depth == 0 {
					return i + 1, true
				}
			}
			i++
		}
		return 0, false
	default:
		// Literal: number, true, false, null.
		start := i
		for i < len(b) {
			switch b[i] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				if i == start {
					return 0, false
				}
				return i, true
			}
			i++
		}
		if i > start {
			return i, true
		}
		return 0, false
	}
}

// ---------------------------------------------------------------------------
// Streaming model detection
// ---------------------------------------------------------------------------

// streamModelKey is the byte pattern every OpenAI-compatible stream chunk uses
// to report the served model.
var streamModelKey = []byte(`"model":"`)

// DetectStreamModel scans a raw SSE chunk for the served model name.
//
// Some upstreams rewrite the model field on every chunk, and others only send
// it once. This helper lets the gateway notice a substitution mid-stream
// without parsing every chunk into a struct, which matters because chunks can
// be very large (base64 images, long tool arguments).
func DetectStreamModel(raw []byte) string {
	idx := bytes.Index(raw, streamModelKey)
	if idx < 0 {
		return ""
	}
	start := idx + len(streamModelKey)
	end := start
	for end < len(raw) {
		if raw[end] == '\\' {
			end += 2
			continue
		}
		if raw[end] == '"' {
			return string(raw[start:end])
		}
		end++
	}
	return ""
}

// MaxTokensOf returns the effective output token cap of a request, preferring
// max_completion_tokens when both are present.
func MaxTokensOf(body []byte) int {
	var probe struct {
		MaxTokens           int `json:"max_tokens"`
		MaxCompletionTokens int `json:"max_completion_tokens"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return 0
	}
	if probe.MaxCompletionTokens > 0 {
		return probe.MaxCompletionTokens
	}
	return probe.MaxTokens
}

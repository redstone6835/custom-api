package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// SSEEvent is one server-sent event.
type SSEEvent struct {
	// Event is the "event:" field; empty for OpenAI-style streams.
	Event string
	// Data is the concatenated "data:" payload.
	Data []byte
	// Raw is the exact bytes of the event including its terminator, so the
	// gateway can forward it verbatim without re-encoding.
	Raw []byte
}

// SSEReader reads server-sent events one at a time.
//
// It is deliberately tolerant: comment lines, unknown fields, CRLF and LF
// terminators, and multi-line data fields are all handled, matching what real
// gateways emit.
type SSEReader struct {
	r   *bufio.Reader
	buf bytes.Buffer
}

// NewSSEReader wraps an io.Reader.
func NewSSEReader(r io.Reader) *SSEReader {
	return &SSEReader{r: bufio.NewReaderSize(r, 32*1024)}
}

// Next returns the next event, or io.EOF when the stream ends.
func (s *SSEReader) Next() (*SSEEvent, error) {
	ev := &SSEEvent{}
	s.buf.Reset()
	var data bytes.Buffer
	sawField := false

	for {
		line, err := s.r.ReadBytes('\n')
		if len(line) > 0 {
			s.buf.Write(line)
			trimmed := bytes.TrimRight(line, "\r\n")
			switch {
			case len(trimmed) == 0:
				// Blank line terminates the event.
				if !sawField {
					// Keep-alive blank line; skip it.
					s.buf.Reset()
					if err != nil {
						return nil, err
					}
					continue
				}
				ev.Data = data.Bytes()
				ev.Raw = append([]byte(nil), s.buf.Bytes()...)
				return ev, nil
			case trimmed[0] == ':':
				// Comment / heartbeat (": ping"). Forwarded verbatim, but it
				// is NOT a payload field: a comment-only block must not
				// terminate the stream or emit an empty event.
			default:
				name, value, _ := bytes.Cut(trimmed, []byte(":"))
				value = bytes.TrimPrefix(value, []byte(" "))
				switch string(name) {
				case "event":
					ev.Event = string(value)
				case "data":
					if data.Len() > 0 {
						data.WriteByte('\n')
					}
					data.Write(value)
				default:
					// id:, retry: and vendor extensions are preserved in Raw.
				}
				sawField = true
			}
		}
		if err != nil {
			if err == io.EOF && sawField {
				// Stream ended without a trailing blank line.
				ev.Data = data.Bytes()
				ev.Raw = append([]byte(nil), s.buf.Bytes()...)
				return ev, nil
			}
			return nil, err
		}
	}
}

// SSEWriter serialises events and flushes after each one.
type SSEWriter struct {
	w io.Writer
	f interface{ Flush() error }
}

// NewSSEWriter wraps a writer, using its Flush method when available.
func NewSSEWriter(w io.Writer) *SSEWriter {
	sw := &SSEWriter{w: w}
	if f, ok := w.(interface{ Flush() error }); ok {
		sw.f = f
	}
	return sw
}

// WriteEvent writes one event and flushes it downstream.
func (w *SSEWriter) WriteEvent(ev *SSEEvent) error {
	if len(ev.Raw) > 0 {
		if _, err := w.w.Write(ev.Raw); err != nil {
			return err
		}
	} else {
		if ev.Event != "" {
			if _, err := fmt.Fprintf(w.w, "event: %s\n", ev.Event); err != nil {
				return err
			}
		}
		for _, line := range bytes.Split(ev.Data, []byte("\n")) {
			if _, err := fmt.Fprintf(w.w, "data: %s\n", line); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w.w, "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

// WriteRaw forwards exact bytes and flushes.
func (w *SSEWriter) WriteRaw(b []byte) error {
	if _, err := w.w.Write(b); err != nil {
		return err
	}
	return w.Flush()
}

// Flush flushes the underlying writer when it supports flushing.
func (w *SSEWriter) Flush() error {
	if w.f != nil {
		return w.f.Flush()
	}
	return nil
}

// IsDone reports whether the event is the OpenAI "[DONE]" sentinel.
func (e *SSEEvent) IsDone() bool {
	return strings.TrimSpace(string(e.Data)) == "[DONE]"
}

// ---------------------------------------------------------------------------
// Stream accumulation
// ---------------------------------------------------------------------------

// StreamAccumulator reassembles a streaming response into a single logical
// response, which is what the audit and fingerprinting layers need.
//
// It never mutates the bytes it observes: the proxy forwards each event as it
// arrives and feeds a copy here.
type StreamAccumulator struct {
	// Text is the concatenated assistant text.
	Text strings.Builder
	// Reasoning is the concatenated chain-of-thought, when present.
	Reasoning strings.Builder
	// ToolCalls maps a tool-call index to its accumulated call.
	ToolCalls map[int]*ToolCall
	// ToolOrder preserves first-seen ordering of tool-call indices.
	ToolOrder []int
	// Usage is the usage block, usually on the final chunk.
	Usage Usage
	// HasUsage reports whether any chunk carried usage.
	HasUsage bool
	// Model is the model reported by the upstream.
	Model string
	// ID is the response/completion id.
	ID string
	// SystemFingerprint is OpenAI's backend identity field.
	SystemFingerprint string
	// FinishReason is the last non-empty finish reason seen.
	FinishReason string
	// SawDone records that the [DONE] sentinel arrived. It is the only reliable
	// signal that a chat-style stream ended deliberately, because a
	// finish_reason can precede a further usage chunk.
	SawDone bool
	// Events counts events consumed.
	Events int
	// Bytes counts raw SSE bytes consumed.
	Bytes int
	// Err records a malformed chunk without aborting the stream.
	Err error
	// provider is "openai" or "anthropic", selected at construction.
	provider string
	// blocks accumulates Anthropic content blocks by index.
	blocks map[int]*AnthropicBlock
	// blockOrder preserves first-seen block indices.
	blockOrder []int
}

// Provider returns the protocol this accumulator was created for.
func (a *StreamAccumulator) Provider() string { return a.provider }

// NewStreamAccumulator creates an accumulator for the given provider
// ("openai" or "anthropic").
func NewStreamAccumulator(provider string) *StreamAccumulator {
	if provider == "" {
		provider = "openai"
	}
	return &StreamAccumulator{
		ToolCalls: map[int]*ToolCall{},
		provider:  provider,
		blocks:    map[int]*AnthropicBlock{},
	}
}

// Observe feeds one event into the accumulator.
func (a *StreamAccumulator) Observe(ev *SSEEvent) {
	if ev == nil {
		return
	}
	a.Events++
	a.Bytes += len(ev.Raw)
	data := bytes.TrimSpace(ev.Data)
	if bytes.Equal(data, []byte("[DONE]")) {
		a.SawDone = true
		return
	}
	if len(data) == 0 {
		return
	}
	if a.provider == "anthropic" || ev.Event != "" {
		a.observeAnthropic(ev, data)
		return
	}
	a.observeOpenAI(data)
}

func (a *StreamAccumulator) observeOpenAI(data []byte) {
	var ch StreamChunk
	if err := json.Unmarshal(data, &ch); err != nil {
		if a.Err == nil {
			a.Err = fmt.Errorf("stream: chunk parse: %w", err)
		}
		return
	}
	if ch.ID != "" {
		a.ID = ch.ID
	}
	if ch.Model != "" {
		a.Model = ch.Model
	}
	if ch.SystemFingerprint != "" {
		a.SystemFingerprint = ch.SystemFingerprint
	}
	if ch.Usage != nil {
		a.Usage = *ch.Usage
		a.HasUsage = true
	}
	for _, c := range ch.Choices {
		if c.Delta.Content.Plain() != "" {
			a.Text.WriteString(c.Delta.Content.Plain())
		}
		if c.Delta.ReasoningContent != "" {
			a.Reasoning.WriteString(c.Delta.ReasoningContent)
		}
		if c.FinishReason != nil && *c.FinishReason != "" {
			a.FinishReason = *c.FinishReason
		}
		for i, tc := range c.Delta.ToolCalls {
			idx := i
			if tc.Index != nil {
				idx = *tc.Index
			}
			acc, ok := a.ToolCalls[idx]
			if !ok {
				acc = &ToolCall{Index: &idx}
				a.ToolCalls[idx] = acc
				a.ToolOrder = append(a.ToolOrder, idx)
			}
			if tc.ID != "" {
				acc.ID = tc.ID
			}
			if tc.Type != "" {
				acc.Type = tc.Type
			}
			if tc.Function.Name != "" {
				acc.Function.Name += tc.Function.Name
			}
			if tc.Function.Arguments != "" {
				acc.Function.Arguments += tc.Function.Arguments
			}
		}
	}
}

// anthropicStreamEvent models the Messages API streaming envelope.
type anthropicStreamEvent struct {
	Type         string          `json:"type"`
	Index        int             `json:"index"`
	Message      json.RawMessage `json:"message,omitempty"`
	ContentBlock json.RawMessage `json:"content_block,omitempty"`
	Delta        json.RawMessage `json:"delta,omitempty"`
	Usage        *AnthropicUsage `json:"usage,omitempty"`
	Error        *AnthropicError `json:"error,omitempty"`
}

func (a *StreamAccumulator) observeAnthropic(ev *SSEEvent, data []byte) {
	var se anthropicStreamEvent
	if err := json.Unmarshal(data, &se); err != nil {
		if a.Err == nil {
			a.Err = fmt.Errorf("stream: anthropic chunk parse: %w", err)
		}
		return
	}
	switch se.Type {
	case "message_start":
		var msg AnthropicResponse
		if err := json.Unmarshal(se.Message, &msg); err == nil {
			a.ID = msg.ID
			a.Model = msg.Model
			if msg.Usage != nil {
				a.Usage = msg.Usage.ToOpenAI()
				a.HasUsage = true
			}
		}
	case "content_block_start":
		var blk AnthropicBlock
		if err := json.Unmarshal(se.ContentBlock, &blk); err == nil {
			cp := blk
			a.blocks[se.Index] = &cp
			a.blockOrder = append(a.blockOrder, se.Index)
		}
	case "content_block_delta":
		var d struct {
			Type        string `json:"type"`
			Text        string `json:"text,omitempty"`
			Thinking    string `json:"thinking,omitempty"`
			PartialJSON string `json:"partial_json,omitempty"`
		}
		if err := json.Unmarshal(se.Delta, &d); err != nil {
			return
		}
		switch d.Type {
		case "text_delta":
			a.Text.WriteString(d.Text)
		case "thinking_delta":
			a.Reasoning.WriteString(d.Thinking)
		case "input_json_delta":
			blk, ok := a.blocks[se.Index]
			if !ok {
				blk = &AnthropicBlock{Type: "tool_use"}
				a.blocks[se.Index] = blk
				a.blockOrder = append(a.blockOrder, se.Index)
			}
			blk.Input = append(blk.Input, []byte(d.PartialJSON)...)
		}
	case "message_delta":
		var d struct {
			StopReason string          `json:"stop_reason,omitempty"`
			Usage      *AnthropicUsage `json:"usage,omitempty"`
		}
		if err := json.Unmarshal(se.Delta, &d); err == nil && d.StopReason != "" {
			a.FinishReason = d.StopReason
		}
		if se.Usage != nil {
			out := se.Usage.OutputTokens
			a.Usage.CompletionTokens = out
			a.Usage.TotalTokens = a.Usage.PromptTokens + out
			a.HasUsage = true
		}
	}
}

// ToolCallsInOrder returns accumulated tool calls ordered by index.
func (a *StreamAccumulator) ToolCallsInOrder() []ToolCall {
	out := make([]ToolCall, 0, len(a.ToolOrder))
	for _, idx := range a.ToolOrder {
		if tc, ok := a.ToolCalls[idx]; ok {
			out = append(out, *tc)
		}
	}
	return out
}

// AnthropicBlocksInOrder returns accumulated content blocks ordered by index.
func (a *StreamAccumulator) AnthropicBlocksInOrder() []AnthropicBlock {
	out := make([]AnthropicBlock, 0, len(a.blockOrder))
	for _, idx := range a.blockOrder {
		if b, ok := a.blocks[idx]; ok {
			out = append(out, *b)
		}
	}
	return out
}

// AsResponse renders the accumulated stream as a non-streaming response so
// that downstream audit rules can run unchanged.
func (a *StreamAccumulator) AsResponse() *ChatResponse {
	msg := ChatMessage{
		Role:             "assistant",
		Content:          Content{Parts: []ContentPart{{Type: "text", Text: a.Text.String()}}},
		ReasoningContent: a.Reasoning.String(),
	}
	if len(a.ToolCalls) > 0 {
		msg.ToolCalls = a.ToolCallsInOrder()
	}
	resp := &ChatResponse{
		ID:                a.ID,
		Object:            "chat.completion",
		Model:             a.Model,
		SystemFingerprint: a.SystemFingerprint,
		Choices:           []Choice{{Index: 0, Message: msg, FinishReason: a.FinishReason}},
	}
	if a.HasUsage {
		u := a.Usage
		resp.Usage = &u
	}
	return resp
}

// AsAnthropicResponse renders the accumulated stream as a Messages response.
func (a *StreamAccumulator) AsAnthropicResponse() *AnthropicResponse {
	resp := &AnthropicResponse{
		ID:         a.ID,
		Type:       "message",
		Role:       "assistant",
		Model:      a.Model,
		Content:    a.AnthropicBlocksInOrder(),
		StopReason: a.FinishReason,
	}
	if a.Text.Len() > 0 {
		resp.Content = append([]AnthropicBlock{{Type: "text", Text: a.Text.String()}}, resp.Content...)
	}
	if a.HasUsage {
		resp.Usage = &AnthropicUsage{
			InputTokens:  a.Usage.PromptTokens,
			OutputTokens: a.Usage.CompletionTokens,
		}
	}
	return resp
}

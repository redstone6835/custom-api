package protocol

import (
	"encoding/json"
	"fmt"
)

// ---------------------------------------------------------------------------
// Streaming translation
// ---------------------------------------------------------------------------
//
// Converting a non-streaming body between protocols is a pure function over a
// complete object. Converting a *stream* is not: the target protocol's event
// vocabulary and ordering differ, and a client that asked for streamed output
// must keep receiving events as they are produced rather than being buffered
// into one body.
//
// The translation is therefore expressed as a stateful event rewriter that
// mirrors the accumulator: it watches what the upstream sent, tracks the
// indices and ids the target protocol requires, and emits the target's events
// as it goes.
//
// Which pairs are supported: chat -> Responses and chat -> Messages are, because
// those cover the case that motivated translation at all, a client speaking a
// newer or vendor-specific protocol while the provider only offers the chat
// surface. The reverse (a Responses or Messages upstream feeding a chat client)
// and Responses <-> Messages are *not* yet rewritten; the gateway detects that
// and falls back to buffering the stream so the reply is still correct, at the
// cost of incremental delivery. Saying so plainly is better than emitting a
// stream in the wrong dialect that a client would misparse.

// StreamTranslator rewrites a streamed reply from one protocol into another.
type StreamTranslator interface {
	// Observe folds one upstream event in and returns the events to send on.
	Observe(ev *SSEEvent) []*SSEEvent
	// Finish flushes any terminal events the translation still owes.
	Finish() []*SSEEvent
}

// NewStreamTranslator builds a rewriter for one direction.
//
// It returns nil when the direction is not implemented, so the caller can fall
// back to buffering instead of guessing.
func NewStreamTranslator(from, to string) StreamTranslator {
	switch {
	case from == "openai" && to == "responses":
		return &chatToResponsesStream{}
	case from == "openai" && to == "anthropic":
		return &chatToAnthropicStream{}
	default:
		return nil
	}
}

// StreamTranslationSupported reports whether a streamed direction is rewritten.
//
// It is exported so the proxy can decide between live translation and buffered
// translation without duplicating the table above.
func StreamTranslationSupported(from, to string) bool {
	return NewStreamTranslator(from, to) != nil
}

// ---------------------------------------------------------------------------
// chat -> Responses
// ---------------------------------------------------------------------------

// chatToResponsesStream rewrites chat completion chunks into Responses events.
type chatToResponsesStream struct {
	responseID string
	model      string
	created    int64
	// started reports whether response.created has been emitted.
	started bool
	// itemOpen tracks whether the message output item is currently open.
	itemOpen bool
	// textSeen reports whether any text delta has been forwarded.
	textSeen bool
	// finished guards against emitting a terminal event twice.
	finished bool
	// seq numbers the emitted events.
	seq int
	// usageSent records that a usage block was already attached.
	usageSent bool
}

// OpenResponsesEvents are the fixed opening events of a well-formed stream.
func (t *chatToResponsesStream) open(created int64) []*SSEEvent {
	t.started = true
	resp := map[string]any{
		"id": t.responseID, "object": "response", "created_at": created,
		"model": t.model, "status": "in_progress",
	}
	return []*SSEEvent{t.event("response.created", map[string]any{"response": resp})}
}

func (t *chatToResponsesStream) event(name string, payload map[string]any) *SSEEvent {
	payload["type"] = name
	payload["sequence_number"] = t.seq
	t.seq++
	b, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return &SSEEvent{Event: name, Data: b}
}

func (t *chatToResponsesStream) Observe(ev *SSEEvent) []*SSEEvent {
	if ev == nil || t.finished {
		return nil
	}
	if ev.IsDone() {
		return t.complete()
	}
	var chunk StreamChunk
	if err := json.Unmarshal(ev.Data, &chunk); err != nil {
		return nil
	}
	if chunk.ID != "" {
		t.responseID = chunk.ID
	}
	if chunk.Model != "" {
		t.model = chunk.Model
	}
	if chunk.Created != 0 {
		t.created = chunk.Created
	}
	if t.responseID == "" {
		t.responseID = "resp_stream"
	}

	var out []*SSEEvent
	if !t.started {
		out = append(out, t.open(t.created)...)
	}
	// A stream may carry a failure; forward it as a terminal failure event.
	if chunk.Error != nil {
		out = append(out, t.event("response.failed", map[string]any{
			"response": map[string]any{
				"id": t.responseID, "object": "response", "model": t.model,
				"status": "failed",
				"error":  map[string]any{"message": chunk.Error.Message, "type": chunk.Error.Type},
			},
		}))
		t.finished = true
		return out
	}

	for _, choice := range chunk.Choices {
		// The message item opens lazily, on the first text or tool delta, so a
		// tool-only reply does not open an empty message item.
		text := choice.Delta.Content.Plain()
		if text != "" {
			if !t.itemOpen {
				out = append(out, t.openMessageItem()...)
			}
			out = append(out, t.event("response.output_text.delta", map[string]any{
				"item_id": "msg_0", "output_index": 0, "content_index": 0, "delta": text,
			}))
			t.textSeen = true
		}
		if choice.Delta.ReasoningContent != "" {
			out = append(out, t.event("response.reasoning_summary_text.delta", map[string]any{
				"item_id": "rs_0", "output_index": 0, "summary_index": 0,
				"delta": choice.Delta.ReasoningContent,
			}))
		}
		for _, tc := range choice.Delta.ToolCalls {
			index := 1
			if tc.Index != nil {
				index = *tc.Index + 1
			}
			out = append(out, t.toolCallEvents(index, tc)...)
		}
		if choice.FinishReason != nil && *choice.FinishReason != "" {
			out = append(out, t.finishReasonEvents(*choice.FinishReason)...)
		}
	}

	// A usage-only chunk (choices empty) still carries the counts the client
	// expects on the terminating event.
	if len(chunk.Choices) == 0 && chunk.Usage != nil {
		out = append(out, t.completeWithUsage(chunk.Usage)...)
	}
	return compact(out)
}

func (t *chatToResponsesStream) openMessageItem() []*SSEEvent {
	t.itemOpen = true
	return []*SSEEvent{t.event("response.output_item.added", map[string]any{
		"output_index": 0,
		"item": map[string]any{
			"id": "msg_0", "type": "message", "role": "assistant", "status": "in_progress",
			"content": []any{},
		},
	})}
}

func (t *chatToResponsesStream) toolCallEvents(index int, tc ToolCall) []*SSEEvent {
	var out []*SSEEvent
	out = append(out, t.event("response.output_item.added", map[string]any{
		"output_index": index,
		"item": map[string]any{
			"id": "fc_" + tc.ID, "type": "function_call",
			"call_id": tc.ID, "name": tc.Function.Name, "arguments": "",
			"status": "in_progress",
		},
	}))
	if tc.Function.Arguments != "" {
		out = append(out, t.event("response.function_call_arguments.delta", map[string]any{
			"item_id": "fc_" + tc.ID, "output_index": index, "delta": tc.Function.Arguments,
		}))
	}
	return out
}

func (t *chatToResponsesStream) finishReasonEvents(reason string) []*SSEEvent {
	if t.finished {
		return nil
	}
	status := "completed"
	if reason == "length" {
		status = "incomplete"
	}
	return t.terminalEvents(status, nil)
}

func (t *chatToResponsesStream) complete() []*SSEEvent {
	if t.finished {
		return nil
	}
	return t.terminalEvents("completed", nil)
}

func (t *chatToResponsesStream) completeWithUsage(u *Usage) []*SSEEvent {
	if t.finished {
		return nil
	}
	return t.terminalEvents("completed", u)
}

// terminalEvents emits the closing items and the terminal event.
func (t *chatToResponsesStream) terminalEvents(status string, usage *Usage) []*SSEEvent {
	t.finished = true
	var out []*SSEEvent
	if !t.started {
		out = append(out, t.open(t.created)...)
	}
	if t.itemOpen {
		out = append(out, t.event("response.output_text.done", map[string]any{
			"item_id": "msg_0", "output_index": 0, "content_index": 0, "text": "",
		}))
		out = append(out, t.event("response.output_item.done", map[string]any{
			"output_index": 0,
			"item": map[string]any{
				"id": "msg_0", "type": "message", "role": "assistant", "status": "completed",
			},
		}))
	}
	resp := map[string]any{
		"id": t.responseID, "object": "response", "created_at": t.created,
		"model": t.model, "status": status,
	}
	if usage != nil {
		resp["usage"] = map[string]any{
			"input_tokens":  usage.PromptTokens,
			"output_tokens": usage.CompletionTokens,
			"total_tokens":  usage.TotalTokens,
		}
		t.usageSent = true
	}
	name := "response.completed"
	if status == "incomplete" {
		name = "response.incomplete"
	}
	out = append(out, t.event(name, map[string]any{"response": resp}))
	// A [DONE] sentinel is not part of the Responses protocol, but some clients
	// tolerate it and some proxies rely on it. It is omitted: emitting a token
	// the protocol does not define is exactly the kind of thing that makes a
	// translation subtly wrong.
	return compact(out)
}

func (t *chatToResponsesStream) Finish() []*SSEEvent {
	if t.finished {
		return nil
	}
	// The upstream closed without a terminator; close the stream properly so a
	// client is not left waiting.
	status := "completed"
	if !t.started {
		status = "completed"
	}
	return t.terminalEvents(status, nil)
}

// ---------------------------------------------------------------------------
// chat -> Messages
// ---------------------------------------------------------------------------

// chatToAnthropicStream rewrites chat chunks into Messages events.
type chatToAnthropicStream struct {
	messageID string
	model     string
	started   bool
	blockOpen bool
	finished  bool
	// index is the next content-block index.
	index int
	// toolIndex maps a chat tool-call index onto a Messages block index.
	toolIndex map[int]int
}

func (t *chatToAnthropicStream) Observe(ev *SSEEvent) []*SSEEvent {
	if ev == nil || t.finished {
		return nil
	}
	if ev.IsDone() {
		return t.terminal("end_turn")
	}
	var chunk StreamChunk
	if err := json.Unmarshal(ev.Data, &chunk); err != nil {
		return nil
	}
	if chunk.ID != "" {
		t.messageID = chunk.ID
	}
	if chunk.Model != "" {
		t.model = chunk.Model
	}
	if t.messageID == "" {
		t.messageID = "msg_stream"
	}
	if t.toolIndex == nil {
		t.toolIndex = map[int]int{}
	}

	var out []*SSEEvent
	if !t.started {
		t.started = true
		out = append(out, t.event("message_start", map[string]any{
			"message": map[string]any{
				"id": t.messageID, "type": "message", "role": "assistant",
				"model": t.model, "content": []any{},
				"usage": map[string]any{"input_tokens": 0, "output_tokens": 0},
			},
		}))
	}
	if chunk.Error != nil {
		out = append(out, t.event("error", map[string]any{
			"error": map[string]any{"type": "upstream_error", "message": chunk.Error.Message},
		}))
		t.finished = true
		return compact(out)
	}

	for _, choice := range chunk.Choices {
		if text := choice.Delta.Content.Plain(); text != "" {
			if !t.blockOpen {
				t.blockOpen = true
				out = append(out, t.event("content_block_start", map[string]any{
					"index": t.index, "content_block": map[string]any{"type": "text", "text": ""},
				}))
			}
			out = append(out, t.event("content_block_delta", map[string]any{
				"index": t.index,
				"delta": map[string]any{"type": "text_delta", "text": text},
			}))
		}
		if choice.Delta.ReasoningContent != "" {
			out = append(out, t.event("content_block_delta", map[string]any{
				"index": t.index,
				"delta": map[string]any{"type": "thinking_delta", "thinking": choice.Delta.ReasoningContent},
			}))
		}
		for _, tc := range choice.Delta.ToolCalls {
			key := 0
			if tc.Index != nil {
				key = *tc.Index
			}
			out = append(out, t.toolEvents(key, tc)...)
		}
		if choice.FinishReason != nil && *choice.FinishReason != "" {
			out = append(out, t.terminal(anthropicStopToChat(*choice.FinishReason))...)
		}
	}
	return compact(out)
}

func (t *chatToAnthropicStream) toolEvents(key int, tc ToolCall) []*SSEEvent {
	var out []*SSEEvent
	blockIndex, known := t.toolIndex[key]
	if !known {
		// Close the text block before opening a tool block: the Messages
		// protocol requires blocks to be strictly sequential.
		if t.blockOpen {
			out = append(out, t.event("content_block_stop", map[string]any{"index": t.index}))
			t.index++
			t.blockOpen = false
		}
		blockIndex = t.index
		t.toolIndex[key] = blockIndex
		t.index++
		out = append(out, t.event("content_block_start", map[string]any{
			"index": blockIndex,
			"content_block": map[string]any{
				"type": "tool_use", "id": tc.ID, "name": tc.Function.Name, "input": map[string]any{},
			},
		}))
	}
	if tc.Function.Arguments != "" {
		out = append(out, t.event("content_block_delta", map[string]any{
			"index": blockIndex,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": tc.Function.Arguments},
		}))
	}
	return out
}

func (t *chatToAnthropicStream) terminal(stopReason string) []*SSEEvent {
	if t.finished {
		return nil
	}
	t.finished = true
	var out []*SSEEvent
	if !t.started {
		t.started = true
		out = append(out, t.event("message_start", map[string]any{
			"message": map[string]any{
				"id": t.messageID, "type": "message", "role": "assistant",
				"model": t.model, "content": []any{},
				"usage": map[string]any{"input_tokens": 0, "output_tokens": 0},
			},
		}))
	}
	if t.blockOpen {
		out = append(out, t.event("content_block_stop", map[string]any{"index": t.index}))
	}
	for _, blockIndex := range t.toolIndex {
		out = append(out, t.event("content_block_stop", map[string]any{"index": blockIndex}))
	}
	out = append(out,
		t.event("message_delta", map[string]any{
			"delta": map[string]any{"stop_reason": stopReason, "stop_sequence": nil},
			"usage": map[string]any{"output_tokens": 0},
		}),
		t.event("message_stop", map[string]any{}),
	)
	return compact(out)
}

func (t *chatToAnthropicStream) event(name string, payload map[string]any) *SSEEvent {
	payload["type"] = name
	b, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return &SSEEvent{Event: name, Data: b}
}

func (t *chatToAnthropicStream) Finish() []*SSEEvent {
	if t.finished {
		return nil
	}
	return t.terminal("end_turn")
}

// compact removes nil events, which is what a failed marshal produces.
func compact(events []*SSEEvent) []*SSEEvent {
	out := events[:0]
	for _, ev := range events {
		if ev != nil {
			out = append(out, ev)
		}
	}
	return out
}

// AnthropicStopToChat exposes the stop-reason mapping for the streaming path.
func AnthropicStopToChat(stop string) string { return anthropicStopToChat(stop) }

// ChatStopToAnthropic exposes the reverse mapping.
func ChatStopToAnthropic(stop string) string { return chatStopToAnthropic(stop) }

// DescribeStreamTranslation renders a short description for logs and headers.
func DescribeStreamTranslation(from, to string) string {
	if !StreamTranslationSupported(from, to) {
		return ""
	}
	return fmt.Sprintf("%s->%s", from, to)
}

// Ensure the interfaces are satisfied at compile time.
var (
	_ StreamTranslator = (*chatToResponsesStream)(nil)
	_ StreamTranslator = (*chatToAnthropicStream)(nil)
)

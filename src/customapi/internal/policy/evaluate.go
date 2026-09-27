package policy

import (
	"fmt"
	"regexp"
	"time"

	"github.com/redstone/customapi/internal/protocol"
)

// ---------------------------------------------------------------------------
// Request / response payloads
// ---------------------------------------------------------------------------

// InspectRequest is the request-side payload handed to the engine.
type InspectRequest struct {
	// Protocol is "openai" or "anthropic".
	Protocol string
	// Model is the canonical model name.
	Model string
	// Actor identifies the user for audit correlation.
	Actor string
	// Trusted marks the user as allowlisted, which downgrades blocks to
	// reports but never disables inspection.
	Trusted bool
	// Text is every piece of user-authored text, labelled by origin.
	Text []LabelledText
	// Tools are the tool names the client declared or already invoked.
	Tools []string
	// ToolArgs are the arguments of declared/invoked tool calls, also
	// labelled so a finding can point at the offending path.
	ToolArgs []LabelledText
}

// LabelledText is a piece of text with its origin path.
type LabelledText struct {
	Field string
	Text  string
}

// Labelled is a small helper for building LabelledText.
func Labelled(field, text string) LabelledText { return LabelledText{Field: field, Text: text} }

// InspectRequestFromOpenAI extracts the audit surface of a chat request.
func InspectRequestFromOpenAI(actor, model string, trusted bool, req *protocol.ChatRequest) *InspectRequest {
	ir := &InspectRequest{Protocol: "openai", Model: model, Actor: actor, Trusted: trusted}
	if req == nil {
		return ir
	}
	for i, m := range req.Messages {
		f := fmt.Sprintf("messages[%d]", i)
		for j, p := range m.Content.Parts {
			switch p.Type {
			case "", "text", "input_text", "output_text":
				ir.Text = append(ir.Text, Labelled(fmt.Sprintf("%s.content[%d]", f, j), p.Text))
			case "tool_result":
				if p.Content != nil {
					ir.Text = append(ir.Text, Labelled(fmt.Sprintf("%s.tool_result[%d]", f, j), p.Content.Text()))
				}
			}
		}
		for j, tc := range m.ToolCalls {
			if tc.Function.Name != "" {
				ir.Tools = append(ir.Tools, tc.Function.Name)
			}
			if tc.Function.Arguments != "" {
				ir.ToolArgs = append(ir.ToolArgs,
					Labelled(fmt.Sprintf("%s.tool_calls[%d].arguments", f, j), tc.Function.Arguments))
			}
		}
	}
	for _, t := range req.Tools {
		if t.Function.Name != "" {
			ir.Tools = append(ir.Tools, t.Function.Name)
		}
		if len(t.Function.Parameters) > 0 {
			ir.ToolArgs = append(ir.ToolArgs, Labelled("tools.schema", string(t.Function.Parameters)))
		}
	}
	return ir
}

// InspectRequestFromAnthropic extracts the audit surface of a Messages call.
func InspectRequestFromAnthropic(actor, model string, trusted bool, req *protocol.AnthropicRequest) *InspectRequest {
	ir := &InspectRequest{Protocol: "anthropic", Model: model, Actor: actor, Trusted: trusted}
	if req == nil {
		return ir
	}
	if req.System != nil {
		for j, p := range req.System.Parts {
			if p.Type == "" || p.Type == "text" {
				ir.Text = append(ir.Text, Labelled(fmt.Sprintf("system[%d]", j), p.Text))
			}
		}
	}
	for i, m := range req.Messages {
		f := fmt.Sprintf("messages[%d]", i)
		for j, p := range m.Content.Parts {
			switch p.Type {
			case "", "text":
				ir.Text = append(ir.Text, Labelled(fmt.Sprintf("%s.content[%d]", f, j), p.Text))
			case "tool_result":
				if p.Content != nil {
					ir.Text = append(ir.Text, Labelled(fmt.Sprintf("%s.tool_result[%d]", f, j), p.Content.Text()))
				}
			case "tool_use":
				if p.Name != "" {
					ir.Tools = append(ir.Tools, p.Name)
				}
				if len(p.Input) > 0 {
					ir.ToolArgs = append(ir.ToolArgs,
						Labelled(fmt.Sprintf("%s.content[%d].input", f, j), string(p.Input)))
				}
			}
		}
	}
	for _, t := range req.Tools {
		if t.Name != "" {
			ir.Tools = append(ir.Tools, t.Name)
		}
		if len(t.InputSchema) > 0 {
			ir.ToolArgs = append(ir.ToolArgs, Labelled("tools.input_schema", string(t.InputSchema)))
		}
	}
	return ir
}

// InspectResponse is the response-side payload handed to the engine.
type InspectResponse struct {
	// Protocol is "openai" or "anthropic".
	Protocol string
	// Channel is the upstream that produced the response.
	Channel string
	// Trusted marks the channel as allowlisted.
	Trusted bool
	// Text is the generated text, plus any tool-call payloads.
	Text []LabelledText
	// ToolCalls are the tool calls the upstream asked the client to execute.
	ToolCalls []ToolCallRequest
}

// ToolCallRequest is a tool call proposed by the upstream.
type ToolCallRequest struct {
	Name      string
	Arguments string
	Kind      string // "function", "tool_use", ...
}

// InspectResponseFromOpenAI extracts the audit surface of a chat response.
func InspectResponseFromOpenAI(channel string, trusted bool, resp *protocol.ChatResponse) *InspectResponse {
	ir := &InspectResponse{Protocol: "openai", Channel: channel, Trusted: trusted}
	if resp == nil {
		return ir
	}
	for i, ch := range resp.Choices {
		f := fmt.Sprintf("choices[%d].message", i)
		if t := ch.Message.Content.Plain(); t != "" {
			ir.Text = append(ir.Text, Labelled(f+".content", t))
		}
		if ch.Message.ReasoningContent != "" {
			ir.Text = append(ir.Text, Labelled(f+".reasoning_content", ch.Message.ReasoningContent))
		}
		for j, tc := range ch.Message.ToolCalls {
			ir.ToolCalls = append(ir.ToolCalls, ToolCallRequest{
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
				Kind:      orDefault(tc.Type, "function"),
			})
			if tc.Function.Arguments != "" {
				ir.Text = append(ir.Text,
					Labelled(fmt.Sprintf("%s.tool_calls[%d].arguments", f, j), tc.Function.Arguments))
			}
		}
	}
	return ir
}

// InspectResponseFromAnthropic extracts the audit surface of a Messages reply.
func InspectResponseFromAnthropic(channel string, trusted bool, resp *protocol.AnthropicResponse) *InspectResponse {
	ir := &InspectResponse{Protocol: "anthropic", Channel: channel, Trusted: trusted}
	if resp == nil {
		return ir
	}
	for i, b := range resp.Content {
		f := fmt.Sprintf("content[%d]", i)
		switch b.Type {
		case "text":
			ir.Text = append(ir.Text, Labelled(f+".text", b.Text))
		case "thinking":
			ir.Text = append(ir.Text, Labelled(f+".thinking", b.Thinking))
		case "tool_use":
			args := string(b.Input)
			ir.ToolCalls = append(ir.ToolCalls, ToolCallRequest{
				Name: b.Name, Arguments: args, Kind: "tool_use",
			})
			if args != "" {
				ir.Text = append(ir.Text, Labelled(f+".input", args))
			}
		}
	}
	return ir
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

// CheckOutbound evaluates request-side rules.
func (e *Engine) CheckOutbound(req *InspectRequest) Decision {
	start := time.Now()
	if req == nil {
		return Decision{Action: ActionAllow}
	}
	var findings []Finding
	evaluated := 0

	for _, r := range e.outbound {
		if r.exact != nil {
			continue
		}
		evaluated++
		for _, lt := range req.Text {
			if lt.Text == "" {
				continue
			}
			if ok, ex := r.match(lt.Text); ok {
				findings = append(findings, e.finding(r, lt.Field, ex))
			}
		}
	}
	// Exact-identifier tool rules.
	for _, r := range e.outbound {
		if r.exact == nil {
			continue
		}
		evaluated++
		for _, name := range req.Tools {
			if r.matchesIdent(name) {
				findings = append(findings, Finding{
					Rule: r.id, Direction: r.dir, Severity: r.sev,
					Field: "tool_call", Detail: fmt.Sprintf("%s: %s", r.detail, name),
					ExcerptHash: e.excerptHash(name), MatchLen: len(name),
				})
			}
		}
	}
	// Allowlist mode: any tool not on the list is a violation.
	if len(e.allowTools) > 0 {
		evaluated++
		allowed := map[string]bool{}
		for _, a := range e.allowTools {
			allowed[a] = true
		}
		for _, name := range req.Tools {
			if !allowed[name] {
				findings = append(findings, Finding{
					Rule: "allowlist.tool_not_allowed", Direction: Outbound, Severity: SevHigh,
					Field: "tool_call", Detail: "tool is not on the operator allowlist: " + name,
					ExcerptHash: e.excerptHash(name), MatchLen: len(name),
				})
			}
		}
	}
	// Dangerous-path rules also inspect tool arguments.
	for _, r := range e.outbound {
		if r.id != "default.tool_dangerous_path" && r.id != "user.deny_path" {
			continue
		}
		for _, lt := range req.ToolArgs {
			if lt.Text == "" {
				continue
			}
			if ok, ex := r.match(lt.Text); ok {
				findings = append(findings, e.finding(r, lt.Field, ex))
			}
		}
	}

	d := e.buildDecision(Outbound, findings, e.outMode, req.Trusted)
	d.RulesEvaluated = evaluated
	d.ElapsedNS = time.Since(start).Nanoseconds()
	return d
}

// CheckInbound evaluates response-side rules, including tool-call policy.
func (e *Engine) CheckInbound(resp *InspectResponse) Decision {
	start := time.Now()
	if resp == nil {
		return Decision{Action: ActionAllow}
	}
	var findings []Finding
	evaluated := 0

	for _, r := range e.inbound {
		evaluated++
		for _, lt := range resp.Text {
			if lt.Text == "" {
				continue
			}
			if ok, ex := r.match(lt.Text); ok {
				findings = append(findings, e.finding(r, lt.Field, ex))
			}
		}
	}

	// Upstream-proposed tool calls are a distinct risk channel: they are the
	// mechanism by which a hostile upstream would try to run code locally.
	if len(resp.ToolCalls) > 0 && e.toolPolicy != "off" {
		evaluated++
		for _, tc := range resp.ToolCalls {
			sev := SevHigh
			if e.toolPolicy == "report" {
				sev = SevMedium
			}
			findings = append(findings, Finding{
				Rule: "default.upstream_tool_call", Direction: Inbound, Severity: sev,
				Field: "tool_call",
				Detail: fmt.Sprintf("upstream proposed tool call %q (policy=%s, %d bytes of arguments)",
					tc.Name, e.toolPolicy, len(tc.Arguments)),
				ExcerptHash: e.excerptHash(tc.Name + "\x00" + tc.Arguments),
				MatchLen:    len(tc.Arguments),
			})
		}
	}

	trusted := resp.Trusted
	// A blocked tool-call policy is not downgraded by trust for the tool
	// channel itself, because executing an upstream-supplied command is
	// precisely the threat the trust model exists to stop. Content findings
	// still downgrade.
	if len(resp.ToolCalls) > 0 && e.toolPolicy == "off" {
		trusted = resp.Trusted
	} else {
		trusted = resp.Trusted
	}

	d := e.buildDecision(Inbound, findings, e.inMode, trusted)
	if e.inMode != "report" && e.toolPolicy == "block" && len(resp.ToolCalls) > 0 {
		d.Action = ActionBlock
		for i := range d.Findings {
			d.Findings[i].TrustExempt = false
		}
	}
	d.RulesEvaluated = evaluated
	d.ElapsedNS = time.Since(start).Nanoseconds()
	return d
}

func (e *Engine) finding(r rule, field, excerpt string) Finding {
	return Finding{
		Rule:        r.id,
		Direction:   r.dir,
		Severity:    r.sev,
		Field:       field,
		Detail:      r.detail,
		ExcerptHash: e.excerptHash(excerpt),
		MatchLen:    len(excerpt),
	}
}

// ---------------------------------------------------------------------------
// Streaming inspection
// ---------------------------------------------------------------------------

// StreamDetector inspects a response while it is still streaming.
//
// Matching a pattern across chunk boundaries is the hard part: an upstream can
// split "ignore previous instructions" into several SSE deltas to evade a
// naive per-chunk regexp. The detector therefore keeps a sliding tail of the
// text seen so far and rescans an overlap window on every delta, which catches
// any match shorter than the window regardless of how it was fragmented.
type StreamDetector struct {
	engine *Engine
	// window is the retained overlap in bytes.
	window int
	// tail holds the last `window` bytes of audited text.
	tail []byte
	// checkedThrough marks how much of the concatenated stream has been
	// covered by a completed scan, so matches are not reported twice.
	checkedThrough int
	// total counts all bytes observed.
	total int
	// findings accumulates deduplicated findings.
	findings []Finding
	// field labels findings from this stream.
	field string
	// truncated reports that the stream exceeded MaxScanBytes and auditing
	// stopped early.
	truncated bool
}

// MaxScanBytes bounds how much of a single response is scanned, so a runaway
// generation cannot consume unbounded CPU. 4 MiB is far beyond any legitimate
// chat completion.
const MaxScanBytes = 4 << 20

// NewStreamDetector returns a detector using the engine's inbound rules.
func NewStreamDetector(e *Engine, field string) *StreamDetector {
	if field == "" {
		field = "stream"
	}
	return &StreamDetector{engine: e, window: 256, field: field}
}

// Observe feeds a text delta and returns any newly matched findings.
func (d *StreamDetector) Observe(delta string) []Finding {
	if d.truncated || delta == "" {
		return nil
	}
	d.total += len(delta)
	if d.total > MaxScanBytes {
		d.truncated = true
		return nil
	}
	d.tail = append(d.tail, delta...)
	if len(d.tail) > d.window {
		d.tail = d.tail[len(d.tail)-d.window:]
	}
	// Rescan the retained window; dedupe keeps repeated matches from
	// inflating the finding list.
	var fresh []Finding
	for _, r := range d.engine.inbound {
		if r.re == nil && len(r.keywords) == 0 {
			continue
		}
		if ok, ex := r.match(string(d.tail)); ok {
			f := d.engine.finding(r, d.field, ex)
			fresh = append(fresh, f)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	before := len(d.findings)
	d.findings = dedupeFindings(append(d.findings, fresh...))
	if len(d.findings) == before {
		return nil
	}
	return d.findings[before:]
}

// Decision finalises the streaming decision.
func (d *StreamDetector) Decision() Decision {
	dec := d.engine.buildDecision(Inbound, d.findings, d.engine.inMode, false)
	dec.Findings = dedupeFindings(d.findings)
	dec.RulesEvaluated = len(d.engine.inbound)
	return dec
}

// Truncated reports whether scanning stopped early.
func (d *StreamDetector) Truncated() bool { return d.truncated }

// ScannedBytes returns how many bytes were examined.
func (d *StreamDetector) ScannedBytes() int { return d.total }

// ---------------------------------------------------------------------------
// Sanitiser
// ---------------------------------------------------------------------------

// Redactor masks secrets in text before it is persisted to the audit log.
type Redactor struct {
	rules []regexpRedactor
}

type regexpRedactor struct {
	re   *regexp.Regexp
	mask string
}

// NewRedactor compiles extra operator patterns on top of the built-in
// credential patterns.
func NewRedactor(extra []string) (*Redactor, error) {
	r := &Redactor{}
	re, err := compileAny(defaultSecretPatterns())
	if err != nil {
		return nil, err
	}
	r.rules = append(r.rules, regexpRedactor{re: re, mask: "[redacted]"})
	if len(extra) > 0 {
		re2, err := compileAny(extra)
		if err != nil {
			return nil, fmt.Errorf("policy: redact patterns: %w", err)
		}
		r.rules = append(r.rules, regexpRedactor{re: re2, mask: "[redacted]"})
	}
	return r, nil
}

// Redact replaces every known secret pattern with a fixed mask.
func (r *Redactor) Redact(s string) string {
	if r == nil {
		return s
	}
	for _, rule := range r.rules {
		if rule.re == nil {
			continue
		}
		s = rule.re.ReplaceAllString(s, rule.mask)
	}
	return s
}

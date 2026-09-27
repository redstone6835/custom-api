// Package policy implements the customs "audit" layer: request-side rules that
// protect upstream access points from abusive users, and response-side rules
// that protect users from a hostile or compromised upstream.
//
// Design notes
//
//   - Rules are pure functions over extracted text. Nothing here performs I/O,
//     which makes every rule trivially unit-testable and keeps the gateway's
//     hot path free of hidden latency.
//   - Findings carry a SHA-256 prefix of the matched excerpt instead of the
//     excerpt itself. Audit records therefore prove that *something* matched
//     without persisting potentially illegal or secret content.
//   - Enforcement mode is per-direction ("enforce" or "report") plus two trust
//     levels, so a trusted channel or user can be inspected without being
//     blocked. Metering and audit persistence are never relaxed by trust.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/redstone/customapi/internal/config"
)

// Direction identifies which side of the gateway a rule protects.
type Direction string

const (
	// Outbound rules run on the user's request before it reaches an upstream.
	Outbound Direction = "outbound"
	// Inbound rules run on the upstream's response before it reaches a user.
	Inbound Direction = "inbound"
)

// Severity ranks a finding.
type Severity string

const (
	// SevLow is informational.
	SevLow Severity = "low"
	// SevMedium warrants recording and possibly throttling.
	SevMedium Severity = "medium"
	// SevHigh should be blocked under normal policy.
	SevHigh Severity = "high"
	// SevCritical is an unambiguous attack or credential leak.
	SevCritical Severity = "critical"
)

// Finding is one rule violation.
//
// A finding never contains the offending text. It records which rule fired,
// where, how bad it is, and a hash that lets an operator confirm a specific
// input later without the audit log itself holding the payload.
type Finding struct {
	Rule      string    `json:"rule"`
	Direction Direction `json:"direction"`
	Severity  Severity  `json:"severity"`
	// Field names where the match occurred, e.g. "messages[2].content".
	Field string `json:"field,omitempty"`
	// ExcerptHash is the first 16 hex chars of SHA-256 over the matched text.
	ExcerptHash string `json:"excerpt_hash,omitempty"`
	// MatchLen is the byte length of the match.
	MatchLen int `json:"match_len,omitempty"`
	// Detail is a human-readable, non-sensitive explanation.
	Detail string `json:"detail,omitempty"`
	// TrustExempt records that the finding would have blocked, but the
	// subject is on the trusted allowlist.
	TrustExempt bool `json:"trust_exempt,omitempty"`
}

// Action is the decision the engine reached.
type Action string

const (
	// ActionAllow forwards the exchange unchanged.
	ActionAllow Action = "allow"
	// ActionReport forwards the exchange but records findings.
	ActionReport Action = "report"
	// ActionBlock rejects the exchange.
	ActionBlock Action = "block"
)

// Decision is the outcome of evaluating a payload.
type Decision struct {
	Action   Action    `json:"action"`
	Findings []Finding `json:"findings,omitempty"`
	// RulesEvaluated and ElapsedNS expose engine cost for tuning.
	RulesEvaluated int   `json:"rules_evaluated"`
	ElapsedNS      int64 `json:"elapsed_ns"`
	// Degraded reports that the engine itself failed and the configured
	// fail-open/fail-closed policy was applied.
	Degraded bool `json:"degraded,omitempty"`
	// DegradedReason explains a degraded decision.
	DegradedReason string `json:"degraded_reason,omitempty"`
}

// Blocked reports whether the decision stops the exchange.
func (d Decision) Blocked() bool { return d.Action == ActionBlock }

// Highest returns the most severe finding, if any.
func (d Decision) Highest() (Finding, bool) {
	if len(d.Findings) == 0 {
		return Finding{}, false
	}
	best := d.Findings[0]
	for _, f := range d.Findings[1:] {
		if severityRank(f.Severity) > severityRank(best.Severity) {
			best = f
		}
	}
	return best, true
}

func severityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	default:
		return 1
	}
}

// ---------------------------------------------------------------------------
// Rule representation
// ---------------------------------------------------------------------------

// rule is a compiled inspection rule.
//
// A rule matches either by regexp, by substring keywords, or by exact
// identifier (tool names). Exactly one of the three mechanisms is populated.
type rule struct {
	id     string
	dir    Direction
	sev    Severity
	field  string
	detail string
	re     *regexp.Regexp
	// keywords are lowercase substrings matched case-insensitively.
	keywords []string
	// exact matches a whole identifier case-sensitively (tool names).
	exact []string
}

func (r *rule) match(text string) (ok bool, excerpt string) {
	if r.re != nil {
		if loc := r.re.FindStringIndex(text); loc != nil {
			return true, text[loc[0]:loc[1]]
		}
		return false, ""
	}
	if len(r.keywords) > 0 {
		lower := strings.ToLower(text)
		for _, kw := range r.keywords {
			if i := strings.Index(lower, kw); i >= 0 {
				end := i + len(kw)
				if end > len(text) {
					end = len(text)
				}
				return true, text[i:end]
			}
		}
	}
	return false, ""
}

// matchesIdent reports whether an exact identifier rule fires.
func (r *rule) matchesIdent(name string) bool {
	for _, e := range r.exact {
		if e == name {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

// Engine evaluates outbound and inbound rules.
//
// An Engine is immutable after construction and safe for concurrent use.
type Engine struct {
	outbound   []rule
	inbound    []rule
	outMode    string
	inMode     string
	toolPolicy string
	failMode   string
	// allowTools, when non-empty, switches outbound tool checking to
	// allowlist mode.
	allowTools []string
	// maxFindings bounds the findings slice so a pathological payload cannot
	// allocate without limit.
	maxFindings int
	// excerptHashSalt prevents trivial recovery of hashed excerpts from a
	// leaked audit log.
	excerptHashSalt string
}

// Options tunes engine construction.
type Options struct {
	// Policy is the operator configuration.
	Policy config.Policy
	// FailMode is "open" or "closed" when the engine itself fails.
	FailMode string
	// HashSalt is mixed into excerpt hashes.
	HashSalt string
	// DisableDefaults skips the built-in rule set, so only operator rules
	// apply. Used by tests that need an exactly specified rule set.
	DisableDefaults bool
}

// New compiles an engine from configuration plus the built-in rule set.
func New(opts Options) (*Engine, error) {
	e := &Engine{
		outMode:         orDefault(opts.Policy.Outbound.Mode, "enforce"),
		inMode:          orDefault(opts.Policy.Inbound.Mode, "enforce"),
		toolPolicy:      orDefault(opts.Policy.Inbound.ToolCallPolicy, "block"),
		failMode:        orDefault(opts.FailMode, "open"),
		maxFindings:     64,
		excerptHashSalt: opts.HashSalt,
	}
	if opts.HashSalt == "" {
		e.excerptHashSalt = "customapi-policy"
	}
	if !opts.DisableDefaults {
		e.outbound = append(e.outbound, defaultOutboundRules()...)
		e.inbound = append(e.inbound, defaultInboundRules()...)
	}

	ob := opts.Policy.Outbound
	if len(ob.BlockKeywords) > 0 {
		e.outbound = append(e.outbound, rule{
			id: "user.block_keyword", dir: Outbound, sev: SevHigh, field: "request",
			detail:   "request contains an operator-blocked keyword",
			keywords: lowerAll(ob.BlockKeywords),
		})
	}
	if len(ob.BlockPatterns) > 0 {
		re, err := compileAny(ob.BlockPatterns)
		if err != nil {
			return nil, fmt.Errorf("policy: outbound.block_patterns: %w", err)
		}
		e.outbound = append(e.outbound, rule{
			id: "user.block_pattern", dir: Outbound, sev: SevHigh, field: "request",
			detail: "request matches an operator-blocked pattern", re: re,
		})
	}
	if len(ob.DenyTools) > 0 {
		e.outbound = append(e.outbound, rule{
			id: "user.deny_tool", dir: Outbound, sev: SevHigh, field: "tool_call",
			detail: "tool/function name is on the operator deny list",
			exact:  append([]string(nil), ob.DenyTools...),
		})
	}
	if len(ob.AllowTools) > 0 {
		e.allowTools = append([]string(nil), ob.AllowTools...)
	}
	if len(ob.DenyPathPatterns) > 0 {
		re, err := compileAny(ob.DenyPathPatterns)
		if err != nil {
			return nil, fmt.Errorf("policy: outbound.deny_path_patterns: %w", err)
		}
		e.outbound = append(e.outbound, rule{
			id: "user.deny_path", dir: Outbound, sev: SevHigh, field: "tool_arguments",
			detail: "tool arguments reference a protected path or dangerous command",
			re:     re,
		})
	}

	ib := opts.Policy.Inbound
	if len(ib.InjectionPatterns) > 0 {
		re, err := compileAny(ib.InjectionPatterns)
		if err != nil {
			return nil, fmt.Errorf("policy: inbound.injection_patterns: %w", err)
		}
		e.inbound = append(e.inbound, rule{
			id: "user.injection", dir: Inbound, sev: SevHigh, field: "response",
			detail: "response matches an operator-supplied injection pattern", re: re,
		})
	}
	if len(ib.SecretPatterns) > 0 {
		re, err := compileAny(ib.SecretPatterns)
		if err != nil {
			return nil, fmt.Errorf("policy: inbound.secret_patterns: %w", err)
		}
		e.inbound = append(e.inbound, rule{
			id: "user.secret", dir: Inbound, sev: SevCritical, field: "response",
			detail: "response matches an operator-supplied secret pattern", re: re,
		})
	}
	return e, nil
}

// OutboundRuleCount reports how many outbound rules are compiled.
func (e *Engine) OutboundRuleCount() int { return len(e.outbound) }

// InboundRuleCount reports how many inbound rules are compiled.
func (e *Engine) InboundRuleCount() int { return len(e.inbound) }

// FailMode returns the configured degradation behaviour.
func (e *Engine) FailMode() string { return e.failMode }

// OutboundMode returns the configured enforcement mode.
func (e *Engine) OutboundMode() string { return e.outMode }

// InboundMode returns the configured enforcement mode.
func (e *Engine) InboundMode() string { return e.inMode }

// ToolCallPolicy returns the configured tool-call policy.
func (e *Engine) ToolCallPolicy() string { return e.toolPolicy }

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.ToLower(s))
		}
	}
	return out
}

// compileAny compiles several expressions into one alternation.
func compileAny(patterns []string) (*regexp.Regexp, error) {
	var parts []string
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		parts = append(parts, "(?:"+p+")")
	}
	if len(parts) == 0 {
		return nil, nil
	}
	return regexp.Compile(strings.Join(parts, "|"))
}

// excerptHash returns a short, salted digest of matched text.
func (e *Engine) excerptHash(s string) string {
	h := sha256.New()
	h.Write([]byte(e.excerptHashSalt))
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// buildDecision turns findings into an action, honouring enforcement mode and
// the trust exemption.
func (e *Engine) buildDecision(dir Direction, findings []Finding, mode string, trusted bool) Decision {
	d := Decision{Action: ActionAllow, Findings: dedupeFindings(findings)}
	if len(d.Findings) == 0 {
		return d
	}
	highest := SevLow
	for _, f := range d.Findings {
		if severityRank(f.Severity) > severityRank(highest) {
			highest = f.Severity
		}
	}
	switch {
	case mode == "report":
		d.Action = ActionReport
	case trusted:
		// Trusted subjects are still inspected and recorded, but a blocking
		// finding is downgraded to a report. Metering/audit never downgrade.
		d.Action = ActionReport
		for i := range d.Findings {
			d.Findings[i].TrustExempt = true
		}
	default:
		d.Action = ActionBlock
	}
	return d
}

// dedupeFindings removes duplicates, sorts by severity and applies the cap.
func dedupeFindings(in []Finding) []Finding {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		key := f.Rule + "|" + f.Field + "|" + f.ExcerptHash
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return severityRank(out[i].Severity) > severityRank(out[j].Severity)
	})
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

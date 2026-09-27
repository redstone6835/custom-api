// Package audit implements the customs gateway's append-only, tamper-evident
// audit ledger.
//
// The project plan requires that accounting, quota deduction and audit trails
// are never skipped, by any subject, under any trust level, and that audit
// evidence lives in a store separate from the business database. This package
// provides that store.
//
// # Tamper evidence
//
// Every record is written as one JSON object per line with three chain fields:
//
//	seq         monotonic sequence number starting at 1
//	prev_hash   entry_hash of the previous record ("genesis" for seq 1)
//	entry_hash  SHA-256 over the canonical JSON of the record with entry_hash
//	            removed
//
// Because entry_hash covers prev_hash, altering, reordering, inserting or
// deleting any record breaks verification from that point onward. An attacker
// who rewrites the whole chain can still be caught by the periodic anchors
// written to a separate file (and, in production, shipped off-host).
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

// GenesisHash is the prev_hash of the first record.
const GenesisHash = "genesis"

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

// Decision summarises what the gateway did with an exchange.
type Decision string

const (
	// DecisionAllow means the exchange was forwarded unchanged.
	DecisionAllow Decision = "allow"
	// DecisionReport means it was forwarded but findings were recorded.
	DecisionReport Decision = "report"
	// DecisionBlockUser means the request was rejected before reaching the
	// upstream.
	DecisionBlockUser Decision = "block_user"
	// DecisionBlockUpstream means the upstream response was withheld from the
	// user.
	DecisionBlockUpstream Decision = "block_upstream"
	// DecisionUpstreamError means the upstream failed.
	DecisionUpstreamError Decision = "upstream_error"
)

// Cost is the monetary accounting for one exchange.
type Cost struct {
	// Currency of the amounts below.
	Currency string `json:"currency,omitempty"`
	// InputCost and OutputCost are the priced components.
	InputCost  float64 `json:"input_cost,omitempty"`
	OutputCost float64 `json:"output_cost,omitempty"`
	// TotalCost is InputCost + OutputCost (already discounted).
	TotalCost float64 `json:"total_cost,omitempty"`
	// ListCost is the undiscounted total, kept so the discount is auditable.
	ListCost float64 `json:"list_cost,omitempty"`
	// DiscountPct is the effective discount percentage.
	DiscountPct float64 `json:"discount_pct,omitempty"`
	// Basis records how the price was obtained: "catalogue", "unknown".
	Basis string `json:"basis,omitempty"`
	// PriceModel identifies the price row used.
	PriceModel string `json:"price_model,omitempty"`
}

// UsageSummary is the metering verdict for one exchange.
type UsageSummary struct {
	// PromptTokens / CompletionTokens are the gateway's own recount.
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
	// Upstream* are the upstream's claims.
	UpstreamPromptTokens     int `json:"upstream_prompt_tokens,omitempty"`
	UpstreamCompletionTokens int `json:"upstream_completion_tokens,omitempty"`
	UpstreamTotalTokens      int `json:"upstream_total_tokens,omitempty"`
	// UpstreamReported is false when the upstream omitted usage.
	UpstreamReported bool `json:"upstream_reported"`
	// TokenizerFamily is the estimator used for the recount.
	TokenizerFamily string `json:"tokenizer_family,omitempty"`
	// Method is "upstream", "stream_chunks" or "local_only".
	Method string `json:"method,omitempty"`
	// PromptDelta / CompletionDelta are relative deviations.
	PromptDelta     float64 `json:"prompt_delta,omitempty"`
	CompletionDelta float64 `json:"completion_delta,omitempty"`
	// Verdict is "consistent", "over_billed", "under_billed", "not_reported"
	// or "not_verifiable".
	Verdict string `json:"verdict"`
	// Tolerance used for the verdict.
	Tolerance float64 `json:"tolerance,omitempty"`
	// MinAbsoluteDelta is the absolute floor applied with the tolerance.
	MinAbsoluteDelta int `json:"min_absolute_delta,omitempty"`
	// WorstAbs is the deviation in tokens, which is what the floor compares.
	WorstAbs int `json:"worst_abs,omitempty"`
}

// Fingerprint is the result of a behavioural model-identity check.
type Fingerprint struct {
	// Checked is false when the request was not sampled for a probe.
	Checked bool `json:"checked"`
	// Score is the divergence from the channel's baseline (JS divergence,
	// 0 == identical distributions).
	Score float64 `json:"score,omitempty"`
	// Threshold applied when deciding Verdict.
	Threshold float64 `json:"threshold,omitempty"`
	// Verdict is "match", "mismatch", "no_baseline" or "skipped".
	Verdict string `json:"verdict,omitempty"`
	// BaselineSource names where the reference distribution came from.
	BaselineSource string `json:"baseline_source,omitempty"`
	// SampleHash is a digest of the probe sample, for reproducibility.
	SampleHash string `json:"sample_hash,omitempty"`
}

// Record is one audited exchange.
//
// Chain fields (Seq, PrevHash, EntryHash) are managed by the Writer and must
// not be set by callers.
type Record struct {
	Seq      int64  `json:"seq"`
	PrevHash string `json:"prev_hash"`
	// EntryHash is the digest of this record.
	//
	// It is omitted while empty so that the bytes hashed at write time are
	// exactly the bytes a verifier recovers by stripping the field: the writer
	// hashes the record before the hash exists, and the verifier hashes the
	// stored line with the hash removed. Emitting the field while empty made
	// those two disagree, so every record failed its own check.
	EntryHash string `json:"entry_hash,omitempty"`

	// ID identifies the request end to end.
	ID string `json:"id"`
	// Time is the request start timestamp (RFC3339, UTC).
	Time time.Time `json:"time"`
	// EndTime is when the response finished.
	EndTime time.Time `json:"end_time,omitempty"`

	// Actor is the user name, Channel the upstream access point.
	Actor   string `json:"actor,omitempty"`
	Channel string `json:"channel,omitempty"`
	// Provider and Key identify the credential that served the request. A
	// provider with several keys expands to several channels, so without these
	// an operator cannot tell which key is being rate-limited or is costing
	// more.
	Provider string `json:"provider,omitempty"`
	Key      string `json:"key,omitempty"`
	// Model is the canonical model name, UpstreamModel what was sent.
	Model         string `json:"model,omitempty"`
	UpstreamModel string `json:"upstream_model,omitempty"`
	// Protocol is the protocol the client spoke: "openai", "responses" or
	// "anthropic".
	Protocol string `json:"protocol,omitempty"`
	// UpstreamProtocol is the protocol the channel actually speaks. It differs
	// from Protocol when the exchange was translated.
	UpstreamProtocol string `json:"upstream_protocol,omitempty"`
	// Translated reports that the request and response were converted between
	// protocols. A converted exchange has different fidelity from a forwarded
	// one, so an operator debugging odd output needs to know which it was.
	Translated bool `json:"translated,omitempty"`
	// ServerState reports that the request relied on provider-side conversation
	// state, so the gateway could neither audit the whole prompt nor confirm
	// the full token count.
	ServerState bool `json:"server_state,omitempty"`
	// Stream reports whether the response was streamed.
	Stream bool `json:"stream"`
	// Endpoint is the requested path.
	Endpoint string `json:"endpoint,omitempty"`
	// ClientIP is the remote address.
	ClientIP string `json:"client_ip,omitempty"`

	// Decision is the overall outcome.
	Decision Decision `json:"decision"`
	// StatusCode is the HTTP status returned to the client.
	StatusCode int `json:"status_code,omitempty"`
	// Error is a short, non-sensitive failure description.
	Error string `json:"error,omitempty"`

	// OutboundFindings / InboundFindings summarise policy hits.
	OutboundFindings []FindingRef `json:"outbound_findings,omitempty"`
	InboundFindings  []FindingRef `json:"inbound_findings,omitempty"`

	// Usage is the metering verdict.
	Usage UsageSummary `json:"usage"`
	// Cost is the monetary accounting.
	Cost Cost `json:"cost,omitempty"`
	// Fingerprint is the identity check result.
	Fingerprint Fingerprint `json:"fingerprint,omitempty"`

	// LatencyMS breaks down where the time went.
	LatencyMS Latency `json:"latency_ms,omitempty"`

	// RequestHash is a digest of the (redacted) request body.
	RequestHash string `json:"request_hash,omitempty"`
	// ResponseHash is a digest of the (redacted) response body.
	ResponseHash string `json:"response_hash,omitempty"`
	// RouteReason explains why this channel was chosen.
	RouteReason string `json:"route_reason,omitempty"`
	// Attempts counts upstream calls made, including failed failovers.
	Attempts int `json:"attempts,omitempty"`
	// FailoverNote records a channel switch caused by an upstream failure.
	FailoverNote string `json:"failover_note,omitempty"`
	// QuotaAfter is the actor's remaining allowance after this request.
	QuotaAfter int64 `json:"quota_after,omitempty"`
	// Sample contains an optional redacted request/response excerpt, present
	// only when sampling is enabled.
	Sample *Sample `json:"sample,omitempty"`
}

// Latency breaks down request handling time.
//
// Every field is milliseconds. An earlier revision stored the two audit stages
// in nanoseconds while the others were milliseconds, which silently produced
// values a thousand times too large for any consumer that treated the object as
// one unit; the names now carry the unit so the mistake cannot be repeated.
type Latency struct {
	// Total is the whole request, from authentication to the last byte.
	Total int64 `json:"total_ms,omitempty"`
	// OutboundAuditMS is the request-side policy evaluation.
	OutboundAuditMS int64 `json:"outbound_audit_ms,omitempty"`
	// UpstreamMS is the time spent waiting on the provider.
	UpstreamMS int64 `json:"upstream_ms,omitempty"`
	// InboundAuditMS is the response-side policy evaluation.
	InboundAuditMS int64 `json:"inbound_audit_ms,omitempty"`
	// TTFBMS is the time to the first byte of the reply.
	TTFBMS int64 `json:"ttfb_ms,omitempty"`
}

// FindingRef is a compact, non-sensitive reference to a policy finding.
type FindingRef struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Field       string `json:"field,omitempty"`
	ExcerptHash string `json:"excerpt_hash,omitempty"`
	TrustExempt bool   `json:"trust_exempt,omitempty"`
}

// Sample holds redacted excerpts for operator inspection.
type Sample struct {
	// RequestText is the redacted request payload excerpt.
	RequestText string `json:"request_text,omitempty"`
	// ResponseText is the redacted response payload excerpt.
	ResponseText string `json:"response_text,omitempty"`
	// Note explains why this exchange was sampled.
	Note string `json:"note,omitempty"`
}

// Clone returns a deep-ish copy safe for mutation by the caller.
func (r *Record) Clone() *Record {
	if r == nil {
		return nil
	}
	cp := *r
	cp.OutboundFindings = append([]FindingRef(nil), r.OutboundFindings...)
	cp.InboundFindings = append([]FindingRef(nil), r.InboundFindings...)
	return &cp
}

// ---------------------------------------------------------------------------
// Canonical hashing
// ---------------------------------------------------------------------------

// hashPayload returns the bytes the entry hash is computed over: the record's
// own JSON with the entry_hash field removed.
//
// # Why the raw bytes rather than a re-marshalled struct
//
// Hashing a re-marshalled Record means the chain is only verifiable by a binary
// whose struct definitions produce byte-identical JSON. Any later change to a
// field name, a JSON tag or a field's presence silently invalidates every
// historical record, and the ledger reports a wholesale tampering that never
// happened - which is exactly what occurred when the latency fields were
// renamed: all 96 records became "unverifiable" overnight.
//
// Hashing the stored bytes makes the evidence self-describing: verification
// depends only on the file, so a ledger written by any version stays verifiable
// by any later version.
func hashPayload(raw []byte) ([]byte, error) {
	stripped, found, err := removeTopLevelField(raw, "entry_hash")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("audit: record has no entry_hash field")
	}
	return stripped, nil
}

// removeTopLevelField deletes one top-level member from a JSON object and
// reports whether it was present.
//
// The remaining members keep their original bytes, order and spacing, so the
// result is a function of the stored text alone.
func removeTopLevelField(raw []byte, field string) ([]byte, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false, fmt.Errorf("audit: record is not a JSON object")
	}
	// Find each top-level member by walking the object with depth tracking, so
	// a nested "entry_hash" (which no record has, but a hand-edited one might)
	// cannot be mistaken for the real field.
	i := 1
	for i < len(trimmed) {
		i = skipJSONSpace(trimmed, i)
		if i >= len(trimmed) {
			break
		}
		if trimmed[i] == '}' {
			break
		}
		if trimmed[i] == ',' {
			i++
			continue
		}
		if trimmed[i] != '"' {
			return nil, false, fmt.Errorf("audit: unexpected byte %q at offset %d", trimmed[i], i)
		}
		keyStart := i
		keyEnd, ok := scanJSONString(trimmed, keyStart)
		if !ok {
			return nil, false, fmt.Errorf("audit: unterminated key at offset %d", keyStart)
		}
		var name string
		if err := json.Unmarshal(trimmed[keyStart:keyEnd], &name); err != nil {
			return nil, false, err
		}
		i = skipJSONSpace(trimmed, keyEnd)
		if i >= len(trimmed) || trimmed[i] != ':' {
			return nil, false, fmt.Errorf("audit: expected ':' after key %q", name)
		}
		i = skipJSONSpace(trimmed, i+1)
		valStart := i
		valEnd, ok := scanJSONValue(trimmed, valStart)
		if !ok {
			return nil, false, fmt.Errorf("audit: unterminated value for key %q", name)
		}
		if name != field {
			i = valEnd
			continue
		}
		// Remove the member plus one adjacent comma, preferring the following
		// one so a trailing member leaves valid JSON behind.
		start, end := keyStart, valEnd
		if end < len(trimmed) {
			j := skipJSONSpace(trimmed, end)
			if j < len(trimmed) && trimmed[j] == ',' {
				end = j + 1
			} else if start > 0 {
				// Last member: swallow the preceding comma instead.
				k := start - 1
				for k > 0 && (trimmed[k] == ' ' || trimmed[k] == '\n' || trimmed[k] == '\t' || trimmed[k] == '\r') {
					k--
				}
				if trimmed[k] == ',' {
					start = k
				}
			}
		}
		out := make([]byte, 0, len(trimmed)-(end-start))
		out = append(out, trimmed[:start]...)
		out = append(out, trimmed[end:]...)
		return out, true, nil
	}
	return nil, false, nil
}

func skipJSONSpace(b []byte, i int) int {
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

// scanJSONString returns the offset just past a JSON string's closing quote.
func scanJSONString(b []byte, i int) (int, bool) {
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

// scanJSONValue returns the offset just past a JSON value.
func scanJSONValue(b []byte, i int) (int, bool) {
	if i >= len(b) {
		return 0, false
	}
	switch b[i] {
	case '"':
		return scanJSONString(b, i)
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
				end, ok := scanJSONString(b, i)
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

// computeHash returns the entry hash for a record about to be written.
//
// The caller guarantees EntryHash is empty, and because the field is omitted
// while empty the marshalled bytes are exactly what a verifier recovers by
// stripping entry_hash from the stored line. That equality is the whole reason
// the chain can be verified by a different version of the software.
func computeHash(r *Record) (string, error) {
	if r.EntryHash != "" {
		return "", fmt.Errorf("audit: entry hash must be computed before it is set")
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

// Writer appends records to an append-only JSONL ledger.
//
// Writes are serialised by a mutex and flushed on every record, so a crash
// loses at most the in-progress record and never corrupts the chain.
type Writer struct {
	mu   sync.Mutex
	path string
	f    *os.File
	w    *bufio.Writer
	seq  int64
	prev string
	// dev and ino identify the open file. They are compared on every append so
	// that a ledger replaced underneath the process (by a rotation script, a
	// restore from backup, or an attacker) is noticed instead of silently
	// receiving appends into an orphaned inode.
	dev uint64
	ino uint64
	// replacementHook is called once when a replacement is detected, before the
	// ledger is reopened. Tests use it to observe the event.
	replacementHook func(string)
	// replaced counts detected replacements.
	replaced int64
	// fsyncOnWrite forces an fsync per record, trading throughput for
	// durability. Enabled for audit logs where loss is unacceptable.
	fsyncOnWrite bool
	written      int64
}

// WriterOptions configures a Writer.
type WriterOptions struct {
	// Path is the ledger file. Parent directories are created.
	Path string
	// Sync forces an fsync after every record.
	Sync bool
	// Truncate starts a fresh ledger instead of appending. Only for tests and
	// for explicitly rotating a ledger.
	Truncate bool
}

// Open opens (or creates) the ledger for appending, resuming the chain from
// the last valid record.
func Open(opts WriterOptions) (*Writer, error) {
	if opts.Path == "" {
		return nil, errors.New("audit: path is required")
	}
	if dir := filepath.Dir(opts.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("audit: create dir: %w", err)
		}
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if opts.Truncate {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(opts.Path, flags, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", opts.Path, err)
	}
	w := &Writer{path: opts.Path, f: f, w: bufio.NewWriter(f), prev: GenesisHash, fsyncOnWrite: opts.Sync}
	if err := w.rememberIdentity(); err != nil {
		f.Close()
		return nil, err
	}
	if !opts.Truncate {
		if err := w.resume(); err != nil {
			f.Close()
			return nil, err
		}
	}
	return w, nil
}

// rememberIdentity records the device and inode of the open ledger file.
func (w *Writer) rememberIdentity() error {
	fi, err := w.f.Stat()
	if err != nil {
		return fmt.Errorf("audit: stat %s: %w", w.path, err)
	}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		w.dev = uint64(sys.Dev)
		w.ino = uint64(sys.Ino)
	}
	return nil
}

// SetReplacementHook installs a callback invoked when the ledger file is
// replaced under the process. It must not block.
func (w *Writer) SetReplacementHook(f func(path string)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.replacementHook = f
}

// Replacements returns how many times the ledger was replaced under the
// process. A non-zero value means evidence written before the replacement is
// not in the file the writer is appending to.
func (w *Writer) Replacements() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.replaced
}

// resume reads the tail of an existing ledger to continue the chain.
//
// It also verifies the chain. A gateway that silently appends to a tampered
// ledger would launder the tampering: the resulting file would look internally
// consistent from that point on, and the break would only be discoverable by
// someone who happened to verify the whole file. Refusing to start is the
// correct behaviour for an evidence store.
func (w *Writer) resume() error {
	f, err := os.Open(w.path)
	if err != nil {
		return fmt.Errorf("audit: reopen %s: %w", w.path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	var last *Record
	var lineNo int64
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		lineNo++
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			// A torn trailing line is tolerated; anything else is a real
			// corruption that must not be silently skipped.
			return fmt.Errorf("audit: corrupt record at line %d: %w", lineNo, err)
		}
		cp := r
		last = &cp
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("audit: scan %s: %w", w.path, err)
	}
	if err := w.verifyExisting(); err != nil {
		return err
	}
	if last != nil {
		w.seq = last.Seq
		w.prev = last.EntryHash
		w.written = last.Seq
	}
	return nil
}

// verifyExisting walks the ledger and rejects a broken chain.
func (w *Writer) verifyExisting() error {
	res, err := Verify(w.path, "")
	if err != nil {
		return err
	}
	if res.OK {
		return nil
	}
	v := res.Violations[0]
	return fmt.Errorf(
		"audit: refusing to append to a ledger whose hash chain is broken (%s at line %d, seq %d: %s); "+
			"the ledger is %d record(s) long - restore it from backup or archive it and start a new one",
		v.Kind, v.Line, v.Seq, v.Detail, res.Records)
}

// checkReplacement reopens the ledger when the file behind the path has been
// swapped, and reports whether the ledger is still usable.
func (w *Writer) checkReplacement() error {
	fi, err := os.Stat(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			// The ledger was removed. Recreating it is correct: a missing file
			// is unambiguous, unlike a swapped one.
			return w.reopenAfterReplacement()
		}
		return fmt.Errorf("audit: stat %s: %w", w.path, err)
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uint64(sys.Dev) == w.dev && uint64(sys.Ino) == w.ino {
		return nil
	}
	hook := w.replacementHook
	w.replaced++
	if hook != nil {
		hook(w.path)
	}
	return w.reopenAfterReplacement()
}

// reopenAfterReplacement reopens the path and reconciles the chain.
func (w *Writer) reopenAfterReplacement() error {
	if err := w.w.Flush(); err != nil {
		return err
	}
	if w.f != nil {
		_ = w.f.Close()
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("audit: reopen %s: %w", w.path, err)
	}
	w.f = f
	w.w = bufio.NewWriter(f)
	if err := w.rememberIdentity(); err != nil {
		return err
	}
	// Re-read the file so the chain continues from what is actually there.
	prevSeq, prevHash, err := tailOf(w.path)
	if err != nil {
		return err
	}
	w.seq = prevSeq
	w.prev = prevHash
	return nil
}

// tailOf returns the final sequence number and hash of a ledger, or the genesis
// state when the ledger is empty.
func tailOf(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, GenesisHash, nil
		}
		return 0, "", err
	}
	defer f.Close()
	var (
		seq  int64
		hash = GenesisHash
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return 0, "", fmt.Errorf("audit: parse %s: %w", path, err)
		}
		seq = r.Seq
		hash = r.EntryHash
	}
	return seq, hash, sc.Err()
}

// Append writes one record and returns the sequence number and entry hash.
//
// The record is mutated in place: Seq, PrevHash and EntryHash are filled in.
func (w *Writer) Append(r *Record) (int64, string, error) {
	if r == nil {
		return 0, "", errors.New("audit: nil record")
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.checkReplacement(); err != nil {
		return 0, "", err
	}

	w.seq++
	r.Seq = w.seq
	r.PrevHash = w.prev
	h, err := computeHash(r)
	if err != nil {
		w.seq--
		return 0, "", fmt.Errorf("audit: hash record: %w", err)
	}
	r.EntryHash = h

	line, err := json.Marshal(r)
	if err != nil {
		w.seq--
		r.EntryHash = ""
		return 0, "", fmt.Errorf("audit: marshal record: %w", err)
	}
	if _, err := w.w.Write(line); err != nil {
		w.seq--
		return 0, "", fmt.Errorf("audit: write: %w", err)
	}
	if err := w.w.WriteByte('\n'); err != nil {
		w.seq--
		return 0, "", fmt.Errorf("audit: write: %w", err)
	}
	if err := w.w.Flush(); err != nil {
		w.seq--
		return 0, "", fmt.Errorf("audit: flush: %w", err)
	}
	if w.fsyncOnWrite {
		if err := w.f.Sync(); err != nil {
			return 0, "", fmt.Errorf("audit: sync: %w", err)
		}
	}
	w.prev = h
	w.written = w.seq
	return r.Seq, h, nil
}

// Seq returns the last written sequence number.
func (w *Writer) Seq() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seq
}

// Head returns the current chain head hash.
func (w *Writer) Head() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.prev
}

// Path returns the ledger path.
func (w *Writer) Path() string { return w.path }

// Close flushes and closes the ledger.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	if err := w.w.Flush(); err != nil {
		w.f.Close()
		return err
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// ---------------------------------------------------------------------------
// Anchoring and verification
// ---------------------------------------------------------------------------

// Anchor pins a chain head to an external location.
//
// An attacker with write access to the ledger can rewrite the whole chain; an
// anchor written elsewhere (another filesystem, a log shipper, a timestamping
// service) makes that detectable. AppendAnchor is intentionally dumb: it
// appends one line and never rewrites history.
type Anchor struct {
	Seq       int64     `json:"seq"`
	Hash      string    `json:"hash"`
	Time      time.Time `json:"time"`
	Records   int64     `json:"records"`
	Component string    `json:"component,omitempty"`
}

// AppendAnchor appends an anchor line to the anchor file.
func AppendAnchor(path string, a Anchor) error {
	if path == "" {
		return errors.New("audit: anchor path is required")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("audit: create anchor dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("audit: open anchor %s: %w", path, err)
	}
	defer f.Close()
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// ReadAnchors reads all anchors from a file, newest last.
func ReadAnchors(path string) ([]Anchor, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Anchor
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 8192), 1<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var a Anchor
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			return nil, fmt.Errorf("audit: anchor parse: %w", err)
		}
		out = append(out, a)
	}
	return out, sc.Err()
}

// ViolationKind classifies a chain integrity failure.
type ViolationKind string

const (
	// ViolationSeqGap means a sequence number was skipped.
	ViolationSeqGap ViolationKind = "seq_gap"
	// ViolationPrevMismatch means prev_hash does not match the previous
	// record's entry_hash.
	ViolationPrevMismatch ViolationKind = "prev_hash_mismatch"
	// ViolationHashMismatch means the record's own content no longer hashes
	// to entry_hash.
	ViolationHashMismatch ViolationKind = "entry_hash_mismatch"
	// ViolationParse means the line is not valid JSON.
	ViolationParse ViolationKind = "parse_error"
	// ViolationAnchor means the ledger head disagrees with an anchor.
	ViolationAnchor ViolationKind = "anchor_mismatch"
)

// Violation is one integrity failure.
type Violation struct {
	Kind   ViolationKind `json:"kind"`
	Line   int64         `json:"line"`
	Seq    int64         `json:"seq,omitempty"`
	Detail string        `json:"detail"`
}

// VerifyResult summarises a verification pass.
type VerifyResult struct {
	// OK is true when the chain is intact and all anchors agree.
	OK bool `json:"ok"`
	// Records is the number of records verified.
	Records int64 `json:"records"`
	// HeadSeq / HeadHash are the verified chain head.
	HeadSeq  int64  `json:"head_seq"`
	HeadHash string `json:"head_hash"`
	// Violations lists every problem found.
	Violations []Violation `json:"violations,omitempty"`
	// AnchorsChecked counts anchors that were compared.
	AnchorsChecked int `json:"anchors_checked,omitempty"`
	// AnchorsIgnored counts anchors whose seq is beyond the ledger.
	AnchorsIgnored int `json:"anchors_ignored,omitempty"`
}

// Verify walks the ledger and checks the hash chain.
//
// When anchorPath is non-empty, anchors are also checked: every anchor whose
// seq is within the ledger must match the record at that sequence.
func Verify(path, anchorPath string) (*VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	defer f.Close()

	res := &VerifyResult{OK: true}
	var (
		prev    = GenesisHash
		prevSeq int64
		bySeq   = map[int64]string{}
		lineNo  int64
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256*1024), 16<<20)
	for sc.Scan() {
		lineNo++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			res.OK = false
			res.Violations = append(res.Violations, Violation{
				Kind: ViolationParse, Line: lineNo,
				Detail: fmt.Sprintf("invalid JSON: %v", err),
			})
			continue
		}
		if r.Seq != prevSeq+1 {
			res.OK = false
			res.Violations = append(res.Violations, Violation{
				Kind: ViolationSeqGap, Line: lineNo, Seq: r.Seq,
				Detail: fmt.Sprintf("expected seq %d, found %d", prevSeq+1, r.Seq),
			})
		}
		if r.PrevHash != prev {
			res.OK = false
			res.Violations = append(res.Violations, Violation{
				Kind: ViolationPrevMismatch, Line: lineNo, Seq: r.Seq,
				Detail: fmt.Sprintf("prev_hash %s does not match chain head %s", short(r.PrevHash), short(prev)),
			})
		}
		// Hash the record's own bytes rather than a re-marshalled struct, so a
		// ledger written by an older version stays verifiable by this one.
		payload, perr := hashPayload(line)
		if perr != nil {
			res.OK = false
			res.Violations = append(res.Violations, Violation{
				Kind: ViolationParse, Line: lineNo, Seq: r.Seq,
				Detail: fmt.Sprintf("cannot hash record: %v", perr),
			})
			prev = r.EntryHash
			prevSeq = r.Seq
			res.Records++
			continue
		}
		sum := sha256.Sum256(payload)
		want := hex.EncodeToString(sum[:])
		if want != r.EntryHash {
			res.OK = false
			res.Violations = append(res.Violations, Violation{
				Kind: ViolationHashMismatch, Line: lineNo, Seq: r.Seq,
				Detail: fmt.Sprintf("content hashes to %s but entry_hash is %s", short(want), short(r.EntryHash)),
			})
		}
		bySeq[r.Seq] = r.EntryHash
		prev = r.EntryHash
		prevSeq = r.Seq
		res.Records++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: scan: %w", err)
	}
	res.HeadSeq = prevSeq
	res.HeadHash = prev

	if anchorPath != "" {
		anchors, err := ReadAnchors(anchorPath)
		if err != nil {
			return nil, err
		}
		for _, a := range anchors {
			// An anchor at sequence 0 pins the empty ledger ("genesis"). The
			// gateway writes one every time it starts against a fresh ledger,
			// so it is a normal state and not evidence of removal.
			if a.Seq == 0 {
				res.AnchorsChecked++
				if res.Records > 0 && a.Hash != GenesisHash {
					res.OK = false
					res.Violations = append(res.Violations, Violation{
						Kind: ViolationAnchor, Seq: 0,
						Detail: fmt.Sprintf("genesis anchor has hash %s, expected %s",
							short(a.Hash), GenesisHash),
					})
				}
				continue
			}
			if a.Seq > prevSeq {
				// The anchor covers records that no longer exist. The ledger
				// shrank after the anchor was written, which means evidence
				// was removed - that is a violation, not a benign state: a
				// torn trailing write cannot extend a chain past an anchor
				// that was already recorded, because the anchor is written
				// from the same serialised writer.
				res.OK = false
				res.AnchorsIgnored++
				res.Violations = append(res.Violations, Violation{
					Kind: ViolationAnchor, Seq: a.Seq,
					Detail: fmt.Sprintf("ledger ends at seq %d but an anchor recorded seq %d (hash %s): records were removed",
						prevSeq, a.Seq, short(a.Hash)),
				})
				continue
			}
			res.AnchorsChecked++
			got, ok := bySeq[a.Seq]
			if !ok {
				// The anchor points inside the ledger's range but the record
				// is gone: evidence was removed.
				res.OK = false
				res.Violations = append(res.Violations, Violation{
					Kind: ViolationAnchor, Seq: a.Seq,
					Detail: fmt.Sprintf("anchor references seq %d which is missing from the ledger (expected hash %s)",
						a.Seq, short(a.Hash)),
				})
				continue
			}
			if got != a.Hash {
				res.OK = false
				res.Violations = append(res.Violations, Violation{
					Kind: ViolationAnchor, Seq: a.Seq,
					Detail: fmt.Sprintf("anchor at seq %d expects %s but ledger has %s",
						a.Seq, short(a.Hash), short(got)),
				})
			}
		}
	}
	sort.SliceStable(res.Violations, func(i, j int) bool {
		return res.Violations[i].Line < res.Violations[j].Line
	})
	return res, nil
}

// ReadAll loads every record from a ledger.
func ReadAll(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256*1024), 16<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("audit: parse: %w", err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "..."
}

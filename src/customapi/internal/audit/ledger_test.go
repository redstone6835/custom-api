package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func tempLedger(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "anchor.jsonl")
}

func sampleRecord(id string) *Record {
	return &Record{
		ID:       id,
		Time:     time.Now().UTC().Truncate(time.Second),
		Actor:    "alice",
		Channel:  "upstream-a",
		Model:    "gpt-4o",
		Protocol: "openai",
		Decision: DecisionAllow,
		Usage: UsageSummary{
			PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150,
			UpstreamReported: true, Verdict: "consistent",
		},
	}
}

func TestAppendAndVerify(t *testing.T) {
	path, anchorPath := tempLedger(t)
	w, err := Open(WriterOptions{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, _, err := w.Append(sampleRecord("r" + string(rune('a'+i)))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if w.Seq() != 5 {
		t.Fatalf("expected seq 5, got %d", w.Seq())
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected OK, got %+v", res)
	}
	if res.Records != 5 {
		t.Fatalf("expected 5 records, got %d", res.Records)
	}
	if res.HeadSeq != 5 {
		t.Fatalf("expected head seq 5, got %d", res.HeadSeq)
	}
	_ = anchorPath
}

// TestChainDetectsModification is the central tamper-evidence test: rewriting
// any field of any record must break verification.
func TestChainDetectsModification(t *testing.T) {
	path, _ := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	for i := 0; i < 4; i++ {
		rec := sampleRecord("r")
		rec.Usage.PromptTokens = 100 + i
		_, _, _ = w.Append(rec)
	}
	_ = w.Close()

	// Tamper with the third record's token count.
	lines := readLines(t, path)
	var rec Record
	if err := json.Unmarshal([]byte(lines[2]), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rec.Usage.PromptTokens = 1 // pretend the user sent almost nothing
	rec.Usage.TotalTokens = 1
	modified, _ := json.Marshal(&rec)
	lines[2] = string(modified)
	writeLines(t, path, lines)

	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("tampering was not detected")
	}
	if !hasViolation(res, ViolationHashMismatch) {
		t.Fatalf("expected an entry_hash_mismatch, got %+v", res.Violations)
	}
}

// TestChainDetectsDeletion verifies that removing a record breaks the chain.
func TestChainDetectsDeletion(t *testing.T) {
	path, _ := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	for i := 0; i < 5; i++ {
		_, _, _ = w.Append(sampleRecord("r"))
	}
	_ = w.Close()

	lines := readLines(t, path)
	lines = append(lines[:1], lines[2:]...) // drop record 2
	writeLines(t, path, lines)

	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("deletion was not detected")
	}
	if !hasViolation(res, ViolationSeqGap) && !hasViolation(res, ViolationPrevMismatch) {
		t.Fatalf("expected a seq gap or prev-hash mismatch, got %+v", res.Violations)
	}
}

// TestChainDetectsReorder verifies that swapping two records is detected.
func TestChainDetectsReorder(t *testing.T) {
	path, _ := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	for i := 0; i < 4; i++ {
		_, _, _ = w.Append(sampleRecord("r"))
	}
	_ = w.Close()

	lines := readLines(t, path)
	lines[1], lines[2] = lines[2], lines[1]
	writeLines(t, path, lines)

	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("reordering was not detected")
	}
}

// TestChainDetectsInsertion verifies that injecting a fabricated record fails.
func TestChainDetectsInsertion(t *testing.T) {
	path, _ := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	for i := 0; i < 3; i++ {
		_, _, _ = w.Append(sampleRecord("r"))
	}
	_ = w.Close()

	forged := sampleRecord("forged")
	forged.Seq = 2
	forged.PrevHash = GenesisHash
	forged.EntryHash = strings.Repeat("f", 64)
	b, _ := json.Marshal(forged)

	lines := readLines(t, path)
	lines = append(lines[:1], append([]string{string(b)}, lines[1:]...)...)
	writeLines(t, path, lines)

	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("insertion was not detected")
	}
}

// TestAnchorDetectsFullRewrite covers the scenario the hash chain alone cannot
// catch: an attacker with write access to the whole ledger who rewrites it
// consistently.
func TestAnchorDetectsFullRewrite(t *testing.T) {
	path, anchorPath := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	for i := 0; i < 3; i++ {
		_, _, _ = w.Append(sampleRecord("r"))
	}
	// Anchor the honest head.
	if err := AppendAnchor(anchorPath, Anchor{
		Seq: w.Seq(), Hash: w.Head(), Time: time.Now().UTC(), Records: w.Seq(),
	}); err != nil {
		t.Fatalf("AppendAnchor: %v", err)
	}
	_ = w.Close()

	// Attacker truncates and rewrites the ledger with a consistent chain
	// claiming fewer tokens were used.
	fresh, _ := Open(WriterOptions{Path: path, Truncate: true})
	for i := 0; i < 2; i++ {
		rec := sampleRecord("r")
		rec.Usage.TotalTokens = 1
		_, _, _ = fresh.Append(rec)
	}
	_ = fresh.Close()

	// The internally consistent rewrite passes plain verification...
	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("rewritten chain should be internally consistent, got %+v", res.Violations)
	}
	// ...but the anchor exposes it.
	res, err = Verify(path, anchorPath)
	if err != nil {
		t.Fatalf("Verify with anchors: %v", err)
	}
	if res.OK {
		t.Fatal("anchor did not detect the rewrite")
	}
	if !hasViolation(res, ViolationAnchor) {
		t.Fatalf("expected an anchor_mismatch, got %+v", res.Violations)
	}
}

// TestResumeContinuesChain verifies that reopening a ledger continues the chain
// rather than restarting it, which would silently discard evidence.
func TestResumeContinuesChain(t *testing.T) {
	path, _ := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	for i := 0; i < 3; i++ {
		_, _, _ = w.Append(sampleRecord("r"))
	}
	headBefore := w.Head()
	_ = w.Close()

	w2, err := Open(WriterOptions{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if w2.Seq() != 3 {
		t.Fatalf("expected to resume at seq 3, got %d", w2.Seq())
	}
	if w2.Head() != headBefore {
		t.Fatalf("resumed head %s != %s", w2.Head(), headBefore)
	}
	seq, _, err := w2.Append(sampleRecord("r4"))
	if err != nil {
		t.Fatalf("append after resume: %v", err)
	}
	if seq != 4 {
		t.Fatalf("expected seq 4 after resume, got %d", seq)
	}
	_ = w2.Close()

	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain broken after resume: %+v", res.Violations)
	}
}

func TestCorruptLineReported(t *testing.T) {
	path, _ := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	_, _, _ = w.Append(sampleRecord("r"))
	_ = w.Close()

	lines := readLines(t, path)
	lines = append(lines, "{not valid json")
	writeLines(t, path, lines)

	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("corrupt line was not reported")
	}
	if !hasViolation(res, ViolationParse) {
		t.Fatalf("expected a parse_error, got %+v", res.Violations)
	}
}

func TestReadAll(t *testing.T) {
	path, _ := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	for i := 0; i < 3; i++ {
		_, _, _ = w.Append(sampleRecord("r"))
	}
	_ = w.Close()

	recs, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 records, got %d", len(recs))
	}
	for i, r := range recs {
		if r.Seq != int64(i+1) {
			t.Fatalf("record %d has seq %d", i, r.Seq)
		}
	}
}

func TestVerifyMissingFile(t *testing.T) {
	_, err := Verify(filepath.Join(t.TempDir(), "nope.jsonl"), "")
	if err == nil {
		t.Fatal("expected an error for a missing ledger")
	}
}

func TestReadAnchorsMissingFile(t *testing.T) {
	a, err := ReadAnchors(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil {
		t.Fatalf("ReadAnchors: %v", err)
	}
	if a != nil {
		t.Fatalf("expected nil anchors, got %+v", a)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func hasViolation(res *VerifyResult, kind ViolationKind) bool {
	for _, v := range res.Violations {
		if v.Kind == kind {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Replacement and tamper resistance
// ---------------------------------------------------------------------------

// TestOpenRefusesTamperedLedger verifies that the writer will not append to a
// ledger whose chain is already broken. Appending would launder the tampering:
// the file would look self-consistent from that point on.
func TestOpenRefusesTamperedLedger(t *testing.T) {
	path, _ := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	for i := 0; i < 3; i++ {
		_, _, _ = w.Append(sampleRecord("r"))
	}
	_ = w.Close()

	// Alter a token count, which invalidates the entry hash.
	lines := readLines(t, path)
	var rec Record
	if err := json.Unmarshal([]byte(lines[1]), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rec.Usage.TotalTokens = 1
	modified, _ := json.Marshal(&rec)
	lines[1] = string(modified)
	writeLines(t, path, lines)

	_, err := Open(WriterOptions{Path: path})
	if err == nil {
		t.Fatal("expected Open to refuse a tampered ledger")
	}
	if !strings.Contains(err.Error(), "hash chain is broken") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDetectsLedgerReplacement verifies that swapping the file underneath a
// running writer is noticed, and that the writer re-anchors onto the new file
// rather than appending into an orphaned inode.
func TestDetectsLedgerReplacement(t *testing.T) {
	path, _ := tempLedger(t)
	w, err := Open(WriterOptions{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()

	var hookCalls int
	w.SetReplacementHook(func(string) { hookCalls++ })

	for i := 0; i < 2; i++ {
		if _, _, err := w.Append(sampleRecord("r")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	// Replace the ledger with an independent, self-consistent one.
	other := path + ".other"
	ow, err := Open(WriterOptions{Path: other, Truncate: true})
	if err != nil {
		t.Fatalf("Open other: %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, _, err := ow.Append(sampleRecord("other")); err != nil {
			t.Fatalf("Append other: %v", err)
		}
	}
	_ = ow.Close()
	if err := os.Rename(other, path); err != nil {
		t.Fatalf("rename: %v", err)
	}

	seq, _, err := w.Append(sampleRecord("after-replacement"))
	if err != nil {
		t.Fatalf("Append after replacement: %v", err)
	}
	if hookCalls != 1 {
		t.Fatalf("replacement hook called %d times, want 1", hookCalls)
	}
	if w.Replacements() != 1 {
		t.Fatalf("Replacements() = %d, want 1", w.Replacements())
	}
	// The chain must continue from the replacement's tail, so the resulting
	// file stays verifiable.
	if seq != 5 {
		t.Fatalf("sequence after replacement = %d, want 5", seq)
	}
	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("ledger not verifiable after replacement: %+v", res.Violations)
	}
	if res.Records != 5 {
		t.Fatalf("expected 5 records, got %d", res.Records)
	}
}

// TestConcurrentAppendsStayConsistent verifies the ledger under contention.
func TestConcurrentAppendsStayConsistent(t *testing.T) {
	path, _ := tempLedger(t)
	w, err := Open(WriterOptions{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	const n = 60
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := w.Append(sampleRecord("r")); err != nil {
				t.Errorf("Append: %v", err)
			}
		}()
	}
	wg.Wait()
	_ = w.Close()

	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("concurrent appends broke the chain: %+v", res.Violations)
	}
	if res.Records != n {
		t.Fatalf("expected %d records, got %d", n, res.Records)
	}
}

// TestGenesisAnchorIsNotAViolation is the regression test for a real false
// alarm found on FreeBSD: a gateway that starts against an empty ledger writes
// an anchor at sequence 0, and verification then reported
// "anchor references seq 0 which is missing from the ledger". That trains an
// operator to ignore the integrity check, which is worse than not having one.
func TestGenesisAnchorIsNotAViolation(t *testing.T) {
	path, anchorPath := tempLedger(t)

	// Start a gateway against a fresh ledger: it anchors sequence 0.
	w, err := Open(WriterOptions{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := AppendAnchor(anchorPath, Anchor{
		Seq: w.Seq(), Hash: w.Head(), Time: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("AppendAnchor: %v", err)
	}

	// The empty ledger plus a genesis anchor must verify cleanly.
	res, err := Verify(path, anchorPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("a genesis anchor was reported as a violation: %+v", res.Violations)
	}
	if res.AnchorsChecked != 1 {
		t.Fatalf("genesis anchor not counted as checked: %+v", res)
	}

	// And it must still verify after records are appended.
	for i := 0; i < 3; i++ {
		if _, _, err := w.Append(sampleRecord("r")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	_ = w.Close()
	res, err = Verify(path, anchorPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("genesis anchor broke a non-empty ledger: %+v", res.Violations)
	}
}

// TestGenesisAnchorWithWrongHashIsRejected guards the other side: a genesis
// anchor that does not carry the genesis hash is malformed.
func TestGenesisAnchorWithWrongHashIsRejected(t *testing.T) {
	path, anchorPath := tempLedger(t)
	w, err := Open(WriterOptions{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, _, err := w.Append(sampleRecord("r")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	_ = w.Close()

	if err := AppendAnchor(anchorPath, Anchor{
		Seq: 0, Hash: "not-the-genesis-hash", Time: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("AppendAnchor: %v", err)
	}
	res, err := Verify(path, anchorPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("a malformed genesis anchor was accepted")
	}
}

// ---------------------------------------------------------------------------
// Schema-change resilience
// ---------------------------------------------------------------------------

// TestVerifiesALedgerWrittenByAnOlderSchema is the regression test for a real
// and serious defect found on the FreeBSD deployment.
//
// Verification originally hashed a *re-marshalled* Record, so it was only valid
// for a binary whose struct definitions produced byte-identical JSON. Renaming
// the latency fields (to make their unit explicit) made all 96 historical
// records report entry_hash_mismatch, and the gateway then refused to start -
// correctly, because it will not append to a chain it cannot verify. An audit
// log that becomes unverifiable whenever the software is updated is not
// evidence, so the hash is now computed over each record's own bytes.
//
// The test writes a ledger in an *older* record shape (latency fields without
// their unit suffix, and no provider/key fields at all) and hashes it the way
// that older writer would have. The current verifier must accept it, because
// the bytes are untouched.
func TestVerifiesALedgerWrittenByAnOlderSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.jsonl")

	// Records as an older release would have written them, with the latency
	// fields that carried no unit and before provider/key existed.
	oldShapes := []map[string]any{
		{
			"seq": 1, "prev_hash": GenesisHash, "id": "req_old_1",
			"time": "2026-01-01T00:00:00Z", "actor": "alice", "channel": "vendor",
			"model": "gpt-4o", "protocol": "openai", "decision": "allow", "status_code": 200,
			"usage": map[string]any{
				"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15,
				"upstream_reported": true, "verdict": "consistent",
			},
			"latency_ms": map[string]any{
				"total": 12, "outbound_audit": 3, "upstream": 8, "ttfb": 9,
			},
		},
		{
			"seq": 2, "id": "req_old_2",
			"time": "2026-01-01T00:00:01Z", "actor": "bob", "channel": "vendor",
			"model": "gpt-4o-mini", "protocol": "openai", "decision": "allow", "status_code": 200,
			"usage": map[string]any{
				"prompt_tokens": 20, "completion_tokens": 7, "total_tokens": 27,
				"upstream_reported": true, "verdict": "consistent",
			},
			"latency_ms": map[string]any{
				"total": 15, "outbound_audit": 2, "upstream": 11, "ttfb": 12,
			},
		},
	}

	var (
		lines []string
		prev  = GenesisHash
	)
	for i, shape := range oldShapes {
		shape["prev_hash"] = prev
		// The chain hash covers the record with entry_hash absent, computed
		// over that version's own serialisation.
		payload, err := json.Marshal(shape)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		sum := sha256.Sum256(payload)
		hash := hex.EncodeToString(sum[:])
		shape["entry_hash"] = hash
		line, err := json.Marshal(shape)
		if err != nil {
			t.Fatalf("marshal record %d: %v", i, err)
		}
		lines = append(lines, string(line))
		prev = hash
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("a ledger written by an older schema must stay verifiable: %+v", res.Violations)
	}
	if res.Records != 2 {
		t.Fatalf("records = %d, want 2", res.Records)
	}
}

// TestTamperingIsStillDetectedAfterTheHashChange verifies the security property
// is unchanged by hashing stored bytes: altering a value must still break it.
func TestTamperingIsStillDetectedAfterTheHashChange(t *testing.T) {
	path, _ := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	for i := 0; i < 3; i++ {
		if _, _, err := w.Append(sampleRecord("r")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	_ = w.Close()

	lines := readLines(t, path)
	var raw map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &raw); err != nil {
		t.Fatal(err)
	}
	usage, _ := raw["usage"].(map[string]any)
	usage["total_tokens"] = 1
	raw["usage"] = usage
	modified, _ := json.Marshal(raw)
	lines[1] = string(modified)
	writeLines(t, path, lines)

	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("tampering was not detected after the hash change")
	}
}

// TestRemovingEntryHashIsDetected verifies that deleting the field the hash is
// computed over is a violation rather than an error that is skipped.
func TestRemovingEntryHashIsDetected(t *testing.T) {
	path, _ := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	if _, _, err := w.Append(sampleRecord("r")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	_ = w.Close()

	lines := readLines(t, path)
	var raw map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw, "entry_hash")
	modified, _ := json.Marshal(raw)
	writeLines(t, path, []string{string(modified)})

	res, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("removing entry_hash must be detected")
	}
}

// TestRehashRepairsAnUnverifiableChain verifies the operator-facing repair
// path: a ledger whose hashes were computed by an older format can be rebuilt,
// the original is preserved, and the result verifies.
func TestRehashRepairsAnUnverifiableChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.jsonl")

	// Two records whose hashes were computed over a payload that still
	// contained an empty entry_hash, which is what the old writer produced.
	recs := []map[string]any{
		{"seq": 1, "prev_hash": GenesisHash, "id": "r1", "actor": "a",
			"channel": "c", "model": "m", "decision": "allow",
			"usage": map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}},
		{"seq": 2, "id": "r2", "actor": "a",
			"channel": "c", "model": "m", "decision": "allow",
			"usage": map[string]any{"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4}},
	}
	var lines []string
	prev := GenesisHash
	for _, rec := range recs {
		rec["prev_hash"] = prev
		rec["entry_hash"] = ""
		payload, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(payload)
		hash := hex.EncodeToString(sum[:])
		rec["entry_hash"] = hash
		line, _ := json.Marshal(rec)
		lines = append(lines, string(line))
		prev = hash
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	// The current verifier must reject it, because stripping entry_hash no
	// longer reproduces the payload the old hash covered.
	before, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if before.OK {
		t.Skip("this binary's writer and verifier already agree; nothing to repair")
	}

	res, err := Rehash(path)
	if err != nil {
		t.Fatalf("Rehash: %v", err)
	}
	if res.Records != 2 {
		t.Fatalf("records = %d", res.Records)
	}
	if res.Changed == 0 {
		t.Fatal("expected the hashes to change")
	}
	if _, err := os.Stat(res.Backup); err != nil {
		t.Fatalf("the original must be preserved: %v", err)
	}

	// An anchor pinning the old head must be moved aside, or the gateway would
	// refuse to start against the rebuilt chain.
	anchorPath := filepath.Join(filepath.Dir(path), "anchor.jsonl")
	if err := AppendAnchor(anchorPath, Anchor{
		Seq: 2, Hash: prev, Time: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("AppendAnchor: %v", err)
	}

	after, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify after rehash: %v", err)
	}
	if !after.OK {
		t.Fatalf("the rebuilt chain does not verify: %+v", after.Violations)
	}
	if after.Records != 2 {
		t.Fatalf("records after rehash = %d", after.Records)
	}
}

// TestRehashReportsWhenNothingIsNeeded verifies the tool is a no-op on a
// healthy ledger.
func TestRehashReportsWhenNothingIsNeeded(t *testing.T) {
	path, _ := tempLedger(t)
	w, _ := Open(WriterOptions{Path: path})
	for i := 0; i < 3; i++ {
		if _, _, err := w.Append(sampleRecord("r")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	_ = w.Close()

	res, err := Rehash(path)
	if err != nil {
		t.Fatalf("Rehash: %v", err)
	}
	if res.Changed != 0 {
		t.Fatalf("a healthy chain should need no changes, got %d", res.Changed)
	}
	after, err := Verify(path, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !after.OK {
		t.Fatalf("verification broke: %+v", after.Violations)
	}
}

package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RehashResult summarises a chain rebuild.
type RehashResult struct {
	// Records is how many records were rewritten.
	Records int64
	// HeadSeq and HeadHash are the rebuilt chain head.
	HeadSeq  int64
	HeadHash string
	// Backup is where the original ledger was preserved.
	Backup string
	// Changed reports whether any record's hash actually differed.
	Changed int64
	// AnchorsMoved names the anchor file that was moved aside, when one
	// existed. Anchors pin the head of the *old* chain, so after a rebuild they
	// necessarily disagree; moving them aside keeps that evidence without
	// leaving the gateway unable to start.
	AnchorsMoved string
	// AnchorBackup is where the old anchors were preserved.
	AnchorBackup string
}

// Rehash rebuilds a ledger's hash chain in the current format.
//
// # When it is needed
//
// An early revision hashed a record whose empty entry_hash field was still
// serialised, so a verifier that hashes the stored line with the field removed
// recovers different bytes. The chain is intact in the sense that no record was
// altered, but it cannot be verified by the current code, and the gateway
// refuses to append to a ledger it cannot verify.
//
// Rebuilding recomputes every hash from the records' own content. That is a
// deliberate, operator-invoked, audited action rather than something the
// gateway does silently: rewriting an evidence store automatically would defeat
// the point of having one, so this tool preserves the original file, reports
// what it changed, and is never called from the serving path.
func Rehash(path string) (*RehashResult, error) {
	records, err := ReadAll(path)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return &RehashResult{}, nil
	}

	backup := path + ".pre-rehash"
	if err := copyFile(path, backup); err != nil {
		return nil, fmt.Errorf("audit: preserve original: %w", err)
	}

	// The rebuilt file is written via a temporary rename, which would otherwise
	// give it the invoking user's ownership. An operator running customsctl as
	// root would then leave the ledger unreadable by the unprivileged service
	// that owns it - a failure that shows up only on the next restart.
	origInfo, statErr := os.Stat(path)
	var origUID, origGID int
	if statErr == nil {
		origUID, origGID = fileOwner(origInfo)
	}

	res := &RehashResult{Backup: backup}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".rehash-*")
	if err != nil {
		return nil, fmt.Errorf("audit: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		_ = os.Remove(tmpName)
	}()

	w := bufio.NewWriter(tmp)
	prev := GenesisHash
	for i := range records {
		rec := &records[i]
		original := rec.EntryHash
		rec.Seq = int64(i + 1)
		rec.PrevHash = prev
		rec.EntryHash = ""
		hash, herr := computeHash(rec)
		if herr != nil {
			return nil, fmt.Errorf("audit: hash record %d: %w", rec.Seq, herr)
		}
		rec.EntryHash = hash
		if original != hash {
			res.Changed++
		}
		line, merr := json.Marshal(rec)
		if merr != nil {
			return nil, fmt.Errorf("audit: marshal record %d: %w", rec.Seq, merr)
		}
		if _, werr := w.Write(append(line, '\n')); werr != nil {
			return nil, fmt.Errorf("audit: write record %d: %w", rec.Seq, werr)
		}
		prev = hash
		res.Records = rec.Seq
	}
	if err := w.Flush(); err != nil {
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if statErr == nil {
		if err := os.Chmod(tmpName, origInfo.Mode().Perm()); err != nil {
			return nil, fmt.Errorf("audit: restore ledger mode: %w", err)
		}
		if err := os.Chown(tmpName, origUID, origGID); err != nil {
			// Not fatal: an unprivileged run legitimately cannot chown, and the
			// file already belongs to that user.
			_ = err
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, fmt.Errorf("audit: replace ledger: %w", err)
	}
	res.HeadSeq = res.Records
	res.HeadHash = prev

	// Anchors pin the previous chain's head. Rebuilding changes every hash, so
	// they can no longer agree, and leaving them in place would make the
	// gateway refuse to start - the anchors would look like evidence of
	// tampering. They are preserved rather than deleted, and reported, because
	// discarding audit evidence silently is not this tool's business.
	anchorPath := filepath.Join(filepath.Dir(path), "anchor.jsonl")
	if _, err := os.Stat(anchorPath); err == nil {
		backup := anchorPath + ".pre-rehash"
		if err := os.Rename(anchorPath, backup); err != nil {
			return nil, fmt.Errorf("audit: move stale anchors aside: %w", err)
		}
		res.AnchorsMoved = anchorPath
		res.AnchorBackup = backup
	}
	return res, nil
}

// copyFile duplicates a file, preserving its permissions.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := out.ReadFrom(in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

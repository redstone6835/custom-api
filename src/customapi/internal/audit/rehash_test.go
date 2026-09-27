package audit

import (
	"os"
	"testing"
)

// An operator typically runs customsctl as root while the service that owns the
// ledger runs unprivileged. Rewriting the chain must not transfer ownership of
// the file to root, otherwise the next service start fails to open its own
// evidence store with "permission denied".
func TestRehashPreservesLedgerOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership can only be reassigned as root")
	}
	path, _ := tempLedger(t)
	w, err := Open(WriterOptions{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, _, err := w.Append(sampleRecord("r1")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A service account other than the invoking one (this test runs as root),
	// with the restrictive mode the deployment uses. Choosing a different owner
	// is what makes the assertion meaningful: a rewritten file that is not
	// explicitly re-chowned comes back as root.
	const wantUID, wantGID = 65534, 65534 // nobody:nogroup
	if err := os.Chown(path, wantUID, wantGID); err != nil {
		t.Fatalf("Chown: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	// Damage the chain so Rehash has real work to do; without that it is a
	// no-op and would never touch the file.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	damaged := append([]byte(`{"seq":9999,"decision":"allow"}`+"\n"), raw...)
	if err := os.WriteFile(path, damaged, 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := Rehash(path)
	if err != nil {
		t.Fatalf("Rehash: %v", err)
	}
	if res.Changed == 0 {
		t.Fatal("the forged record should have been reported as repaired")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("mode = %o, want 640", perm)
	}
	if uid, gid := fileOwner(info); uid != wantUID || gid != wantGID {
		t.Errorf("owner = %d:%d, want %d:%d", uid, gid, wantUID, wantGID)
	}
}

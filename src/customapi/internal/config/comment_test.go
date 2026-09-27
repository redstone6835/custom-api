package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommentFieldAccepted(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	body := `{"_comment":["line one","line two"],"server":{},"channels":[{"name":"a","base_url":"http://x"}],"users":[]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatalf("array _comment rejected: %v", err)
	}
}

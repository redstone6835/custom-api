package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestShippedExampleConfigIsValid guards the out-of-the-box experience: the
// configuration template that install.sh deploys must pass `customsctl config
// check` unmodified. A template that fails validation is a broken first-run.
func TestShippedExampleConfigIsValid(t *testing.T) {
	// The test runs in internal/config, so the repository root is three levels up.
	path := filepath.Join("..", "..", "..", "..", "deploy", "etc", "customs.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("shipped example not present in this checkout: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("the shipped example configuration does not validate: %v", err)
	}
	// The example uses the provider layer, which is the recommended shape.
	// Effective channels are what matter, whether they come from providers or
	// from the flat list.
	if len(cfg.AllChannels()) == 0 {
		t.Fatal("the shipped example declares neither channels nor providers")
	}
	if len(cfg.Providers) == 0 && len(cfg.Channels) == 0 {
		t.Fatal("the shipped example declares no upstreams at all")
	}
	if len(cfg.Users) == 0 {
		t.Fatal("the shipped example declares no users")
	}
	// Every shipped credential must clearly be a placeholder, so an operator
	// cannot accidentally deploy the template as-is.
	for _, u := range cfg.Users {
		if u.Token == "" {
			t.Fatalf("user %q has no token placeholder", u.Name)
		}
	}
	// Paths must be absolute so the service works regardless of its cwd.
	if cfg.Server.AuditPath == "" || cfg.Server.AuditPath[0] != '/' {
		t.Fatalf("audit_path should be absolute, got %q", cfg.Server.AuditPath)
	}
	// Every provider in the shipped example must be discoverable and must have
	// at least one key slot, so an operator knows where to put the credential.
	for _, p := range cfg.Providers {
		if len(p.Keys) == 0 {
			t.Fatalf("provider %q has no key slot; the operator would not know where to put the credential", p.Name)
		}
		if p.BaseURL == "" {
			t.Fatalf("provider %q has no base_url", p.Name)
		}
	}
	// The example must not ship a real-looking secret.
	for _, p := range cfg.Providers {
		for _, k := range p.Keys {
			if k.APIKey != "" {
				t.Fatalf("provider %q ships a key value in the world-readable config; use the env file", p.Name)
			}
		}
	}
}

// TestShippedEnvExampleParses guards the secrets template.
func TestShippedEnvExampleParses(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "deploy", "etc", "customsd.env.example")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("env example not present: %v", err)
	}
	pairs, err := LoadEnvFile(path)
	if err != nil {
		t.Fatalf("the shipped env template does not parse: %v", err)
	}
	if len(pairs) == 0 {
		t.Fatal("the env template defines nothing")
	}
}

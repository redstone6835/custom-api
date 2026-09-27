package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEnv(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoadEnvFile(t *testing.T) {
	p := writeEnv(t, `# upstream credentials
CUSTOMS_CHANNEL_UPSTREAM_A_APIKEY=sk-abc123
CUSTOMS_CHANNEL_UPSTREAM_A_BASEURL="https://api.example.com/v1"

# a value that itself contains an equals sign (base64 padding)
CUSTOMS_USER_ALICE_TOKEN=abc==

EMPTY=
`)
	pairs, err := LoadEnvFile(p)
	if err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	if pairs["CUSTOMS_CHANNEL_UPSTREAM_A_APIKEY"] != "sk-abc123" {
		t.Fatalf("apikey = %q", pairs["CUSTOMS_CHANNEL_UPSTREAM_A_APIKEY"])
	}
	if pairs["CUSTOMS_CHANNEL_UPSTREAM_A_BASEURL"] != "https://api.example.com/v1" {
		t.Fatalf("quoted value not unquoted: %q", pairs["CUSTOMS_CHANNEL_UPSTREAM_A_BASEURL"])
	}
	if pairs["CUSTOMS_USER_ALICE_TOKEN"] != "abc==" {
		t.Fatalf("value containing '=' mangled: %q", pairs["CUSTOMS_USER_ALICE_TOKEN"])
	}
	if v, ok := pairs["EMPTY"]; !ok || v != "" {
		t.Fatalf("empty value not recorded: %q %v", v, ok)
	}
}

func TestLoadEnvFileSingleQuotes(t *testing.T) {
	p := writeEnv(t, `KEY='value with spaces'
`)
	pairs, err := LoadEnvFile(p)
	if err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	if pairs["KEY"] != "value with spaces" {
		t.Fatalf("KEY = %q", pairs["KEY"])
	}
}

// TestLoadEnvFileRejectsMalformed is the important safety property: a broken
// secrets file must fail loudly rather than leaving a channel unauthenticated.
func TestLoadEnvFileRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"no equals":        "THIS_IS_NOT_AN_ASSIGNMENT\n",
		"empty key":        "=value\n",
		"invalid key char": "BAD-KEY=value\n",
		"leading digit":    "1KEY=value\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadEnvFile(writeEnv(t, body)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestLoadEnvFileMissing(t *testing.T) {
	if _, err := LoadEnvFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected an error for a missing env file")
	}
}

// TestEnvFileOverridesConfigAndEnvironment verifies the documented precedence.
func TestEnvFileOverridesConfigAndEnvironment(t *testing.T) {
	cfgPath := writeConfig(t, `{
		"server": {},
		"channels": [{"name": "upstream_a", "base_url": "http://from-config", "api_key": "config-key"}],
		"users": [{"name": "alice", "token": "config-token"}]
	}`)
	t.Setenv("CUSTOMS_CHANNEL_UPSTREAM_A_APIKEY", "from-environment")

	envPath := writeEnv(t, `CUSTOMS_CHANNEL_UPSTREAM_A_APIKEY=from-envfile
CUSTOMS_USER_ALICE_TOKEN=envfile-token
`)

	cfg, err := LoadWithEnvFile(cfgPath, envPath)
	if err != nil {
		t.Fatalf("LoadWithEnvFile: %v", err)
	}
	if cfg.Channels[0].APIKey != "from-envfile" {
		t.Fatalf("env file did not win over the environment: %q", cfg.Channels[0].APIKey)
	}
	if cfg.Channels[0].BaseURL != "http://from-config" {
		t.Fatalf("unrelated field was disturbed: %q", cfg.Channels[0].BaseURL)
	}
	if cfg.Users[0].Token != "envfile-token" {
		t.Fatalf("user token not overridden: %q", cfg.Users[0].Token)
	}
}

// TestEnvFileOnlyAffectsNamedSubjects verifies that an entry for an unknown
// channel is inert rather than creating one.
func TestEnvFileOnlyAffectsNamedSubjects(t *testing.T) {
	cfgPath := writeConfig(t, minimalConfig)
	envPath := writeEnv(t, "CUSTOMS_CHANNEL_GHOST_APIKEY=sk-ghost\n")

	cfg, err := LoadWithEnvFile(cfgPath, envPath)
	if err != nil {
		t.Fatalf("LoadWithEnvFile: %v", err)
	}
	if len(cfg.Channels) != 1 {
		t.Fatalf("env file created a channel: %d", len(cfg.Channels))
	}
	if strings.Contains(cfg.Channels[0].APIKey, "ghost") {
		t.Fatal("env file leaked into the wrong channel")
	}
}

// TestLoadWithoutEnvFileStillWorks guards the default path.
func TestLoadWithoutEnvFileStillWorks(t *testing.T) {
	cfg, err := LoadWithEnvFile(writeConfig(t, minimalConfig), "")
	if err != nil {
		t.Fatalf("LoadWithEnvFile: %v", err)
	}
	if len(cfg.Channels) != 1 {
		t.Fatal("basic loading broke")
	}
}

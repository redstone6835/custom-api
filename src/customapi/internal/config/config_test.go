package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "customs.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

const minimalConfig = `{
  "server": {"listen": "127.0.0.1:8080"},
  "channels": [
    {"name": "a", "base_url": "http://a.example", "api_key": "k1"}
  ],
  "users": [
    {"name": "alice", "token": "tok-alice"}
  ]
}`

func TestLoadMinimal(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Channels) != 1 || len(cfg.Users) != 1 {
		t.Fatalf("unexpected shape: %+v", cfg)
	}
	// Defaults must be applied.
	if cfg.Server.AdminListen == "" {
		t.Fatal("admin_listen default not applied")
	}
	if cfg.Server.RouteStrategy != "value" {
		t.Fatalf("route strategy default = %q", cfg.Server.RouteStrategy)
	}
	if cfg.Server.FailMode != "open" {
		t.Fatalf("fail mode default = %q", cfg.Server.FailMode)
	}
	if cfg.Policy.Metering.Tolerance != 0.25 {
		t.Fatalf("tolerance default = %v, want 0.25", cfg.Policy.Metering.Tolerance)
	}
	// Trust must default to untrusted: the plan's core premise.
	if cfg.Channels[0].TrustLevel() != TrustUntrusted {
		t.Fatalf("channel trust defaulted to %q", cfg.Channels[0].TrustLevel())
	}
	if cfg.Users[0].TrustLevel() != TrustUntrusted {
		t.Fatalf("user trust defaulted to %q", cfg.Users[0].TrustLevel())
	}
	// Protocol defaults to the OpenAI-compatible surface.
	if cfg.Channels[0].Protocol != "openai" {
		t.Fatalf("protocol default = %q", cfg.Channels[0].Protocol)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("expected an error for a missing config")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	_, err := Load(writeConfig(t, `{"server":{},"channels":[],"users":[],"typo_field":1}`))
	if err == nil {
		t.Fatal("expected an error for an unknown field, so typos are caught")
	}
}

func TestLoadRejectsInvalidJSON(t *testing.T) {
	_, err := Load(writeConfig(t, `{not json`))
	if err == nil {
		t.Fatal("expected a parse error")
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func TestValidateRequiresChannel(t *testing.T) {
	_, err := Load(writeConfig(t, `{"server":{},"channels":[],"users":[{"name":"a","token":"t"}]}`))
	if err == nil || !strings.Contains(err.Error(), "at least one channel") {
		t.Fatalf("expected a channel requirement error, got %v", err)
	}
}

func TestValidateRequiresBaseURL(t *testing.T) {
	_, err := Load(writeConfig(t, `{"server":{},"channels":[{"name":"a"}],"users":[]}`))
	if err == nil || !strings.Contains(err.Error(), "base_url") {
		t.Fatalf("expected a base_url error, got %v", err)
	}
}

func TestValidateRejectsDuplicateChannel(t *testing.T) {
	_, err := Load(writeConfig(t, `{"server":{},"channels":[
		{"name":"a","base_url":"http://x"},{"name":"a","base_url":"http://y"}],"users":[]}`))
	if err == nil || !strings.Contains(err.Error(), "duplicate channel") {
		t.Fatalf("expected a duplicate channel error, got %v", err)
	}
}

// TestValidateRejectsDuplicateToken guards against two users sharing a
// credential, which would make the audit ledger ambiguous.
func TestValidateRejectsDuplicateToken(t *testing.T) {
	_, err := Load(writeConfig(t, `{"server":{},"channels":[{"name":"a","base_url":"http://x"}],
		"users":[{"name":"u1","token":"same"},{"name":"u2","token":"same"}]}`))
	if err == nil || !strings.Contains(err.Error(), "duplicate user token") {
		t.Fatalf("expected a duplicate token error, got %v", err)
	}
}

func TestValidateRejectsEmptyToken(t *testing.T) {
	_, err := Load(writeConfig(t, `{"server":{},"channels":[{"name":"a","base_url":"http://x"}],
		"users":[{"name":"u1"}]}`))
	if err == nil || !strings.Contains(err.Error(), "token must not be empty") {
		t.Fatalf("expected a token error, got %v", err)
	}
}

func TestValidateRejectsBadProtocol(t *testing.T) {
	_, err := Load(writeConfig(t, `{"server":{},"channels":[{"name":"a","base_url":"http://x","protocol":"soap"}],"users":[]}`))
	if err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("expected a protocol error, got %v", err)
	}
}

func TestValidateRejectsBadEnums(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"fail_mode", `{"server":{"fail_mode":"maybe"},"channels":[{"name":"a","base_url":"http://x"}],"users":[]}`, "fail_mode"},
		{"strategy", `{"server":{"route_strategy":"vibes"},"channels":[{"name":"a","base_url":"http://x"}],"users":[]}`, "route_strategy"},
		{"period", `{"server":{},"channels":[{"name":"a","base_url":"http://x"}],"users":[{"name":"u","token":"t","period":"hourly"}]}`, "period"},
		{"trust", `{"server":{},"channels":[{"name":"a","base_url":"http://x","trust":"sorta"}],"users":[]}`, "trust"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Secrets via environment
// ---------------------------------------------------------------------------

// TestEnvironmentOverridesSecrets verifies that upstream credentials can be
// kept out of the configuration file.
func TestEnvironmentOverridesSecrets(t *testing.T) {
	p := writeConfig(t, `{
		"server": {},
		"channels": [{"name": "upstream_a", "base_url": "http://old.example"}],
		"users": [{"name": "alice", "token": "placeholder"}]
	}`)
	t.Setenv("CUSTOMS_CHANNEL_UPSTREAM_A_APIKEY", "sk-real-secret")
	t.Setenv("CUSTOMS_CHANNEL_UPSTREAM_A_BASEURL", "http://new.example")
	t.Setenv("CUSTOMS_USER_ALICE_TOKEN", "tok-from-env")

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Channels[0].APIKey != "sk-real-secret" {
		t.Fatalf("channel api key not overridden: %q", cfg.Channels[0].APIKey)
	}
	if cfg.Channels[0].BaseURL != "http://new.example" {
		t.Fatalf("channel base url not overridden: %q", cfg.Channels[0].BaseURL)
	}
	if cfg.Users[0].Token != "tok-from-env" {
		t.Fatalf("user token not overridden: %q", cfg.Users[0].Token)
	}
}

func TestEnvironmentServerOverrides(t *testing.T) {
	p := writeConfig(t, minimalConfig)
	t.Setenv("CUSTOMS_SERVER_LISTEN", "0.0.0.0:9999")
	t.Setenv("CUSTOMS_SERVER_LOG_LEVEL", "debug")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != "0.0.0.0:9999" {
		t.Fatalf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.LogLevel != "debug" {
		t.Fatalf("log level = %q", cfg.Server.LogLevel)
	}
}

// ---------------------------------------------------------------------------
// Duration
// ---------------------------------------------------------------------------

func TestDurationParsing(t *testing.T) {
	cases := map[string]time.Duration{
		`"30s"`:   30 * time.Second,
		`"2m"`:    2 * time.Minute,
		`"1h30m"`: 90 * time.Minute,
		`45`:      45 * time.Second,
		`""`:      0,
		`null`:    0,
	}
	for in, want := range cases {
		var d Duration
		if err := json.Unmarshal([]byte(in), &d); err != nil {
			t.Fatalf("unmarshal %s: %v", in, err)
		}
		if d.D() != want {
			t.Fatalf("%s parsed to %v, want %v", in, d.D(), want)
		}
	}
	var d Duration
	if err := json.Unmarshal([]byte(`"nonsense"`), &d); err == nil {
		t.Fatal("expected an error for an invalid duration")
	}
}

func TestDurationRoundTrip(t *testing.T) {
	d := Duration(45 * time.Second)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `"45s"` {
		t.Fatalf("marshal = %s", b)
	}
}

// ---------------------------------------------------------------------------
// Lookups and model policy
// ---------------------------------------------------------------------------

func TestChannelByName(t *testing.T) {
	cfg := &Config{Channels: []Channel{{Name: "a"}, {Name: "b"}}}
	if ch, ok := cfg.ChannelByName("b"); !ok || ch.Name != "b" {
		t.Fatal("lookup failed")
	}
	if _, ok := cfg.ChannelByName("z"); ok {
		t.Fatal("expected a miss")
	}
}

func TestUserByToken(t *testing.T) {
	cfg := &Config{Users: []User{{Name: "a", Token: "tok-a"}, {Name: "b", Token: "tok-bb"}}}
	if u, ok := cfg.UserByToken("tok-bb"); !ok || u.Name != "b" {
		t.Fatalf("lookup failed: %+v %v", u, ok)
	}
	if _, ok := cfg.UserByToken("tok-b"); ok {
		t.Fatal("a prefix of a token must not authenticate")
	}
	if _, ok := cfg.UserByToken(""); ok {
		t.Fatal("an empty token must not authenticate")
	}
}

func TestAllowsModel(t *testing.T) {
	u := User{Models: []string{"gpt-4o", "claude-*"}}
	cases := map[string]bool{
		"gpt-4o":            true,
		"claude-3-5-sonnet": true,
		"claude-opus-4":     true,
		"gpt-4o-mini":       false,
		"gemini-pro":        false,
	}
	for model, want := range cases {
		if got := u.AllowsModel(model); got != want {
			t.Fatalf("AllowsModel(%q) = %v, want %v", model, got, want)
		}
	}
	// An empty list means no restriction.
	if !(User{}).AllowsModel("anything") {
		t.Fatal("an empty model list should allow everything")
	}
}

// ---------------------------------------------------------------------------
// Channel model translation
// ---------------------------------------------------------------------------

// TestUpstreamModelDeclaration documents the three cases that matter for
// routing correctness.
func TestUpstreamModelDeclaration(t *testing.T) {
	// Declared catalogue: an unlisted model is refused, so the router can
	// exclude the channel instead of provoking an upstream error.
	declared := Channel{Models: map[string]string{"gpt-4o": "openai/gpt-4o-2024-11-20"}}
	if got := declared.UpstreamModel("gpt-4o"); got != "openai/gpt-4o-2024-11-20" {
		t.Fatalf("alias not applied: %q", got)
	}
	if got := declared.UpstreamModel("gemini-pro"); got != "" {
		t.Fatalf("unlisted model should be refused, got %q", got)
	}

	// Empty catalogue: explicit pass-through.
	passthrough := Channel{}
	if got := passthrough.UpstreamModel("anything"); got != "anything" {
		t.Fatalf("passthrough channel should forward the name, got %q", got)
	}
}

func TestCanonicalModelInverse(t *testing.T) {
	ch := Channel{Models: map[string]string{"gpt-4o": "openai/gpt-4o-2024-11-20"}}
	if got := ch.CanonicalModel("openai/gpt-4o-2024-11-20"); got != "gpt-4o" {
		t.Fatalf("inverse mapping = %q", got)
	}
	if got := ch.CanonicalModel("unknown"); got != "unknown" {
		t.Fatalf("unknown model should pass through, got %q", got)
	}
}

func TestIsEnabled(t *testing.T) {
	if !(Channel{}).IsEnabled() {
		t.Fatal("a channel with no enabled field should default to enabled")
	}
	f := false
	if (Channel{Enabled: &f}).IsEnabled() {
		t.Fatal("explicitly disabled channel reported as enabled")
	}
}

func TestPriceFor(t *testing.T) {
	cfg := &Config{Prices: []PriceEntry{
		{Channel: "a", Model: "m", Price: PriceModel{InputPerM: 1}},
	}}
	if pm, ok := cfg.PriceFor("a", "m"); !ok || pm.InputPerM != 1 {
		t.Fatal("price lookup failed")
	}
	if _, ok := cfg.PriceFor("a", "other"); ok {
		t.Fatal("expected a miss")
	}
}

func TestResolve(t *testing.T) {
	if got := Resolve("/base", "rel/path"); got != "/base/rel/path" {
		t.Fatalf("Resolve = %q", got)
	}
	if got := Resolve("/base", "/abs/path"); got != "/abs/path" {
		t.Fatalf("absolute path should be preserved, got %q", got)
	}
	if got := Resolve("/base", ""); got != "" {
		t.Fatalf("empty path should stay empty, got %q", got)
	}
}

// TestAdminRemoteIsOffUnlessConfigured pins the default: the management API is
// dangerous enough that remote reachability must be an explicit decision, and
// the environment override must be able to turn it on for a deployed instance.
func TestAdminRemoteIsOffUnlessConfigured(t *testing.T) {
	p := writeConfig(t, `{"server": {}, "channels": [{"name": "c", "base_url": "http://x"}]}`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.AdminRemote {
		t.Fatal("admin_remote must default to false")
	}

	t.Setenv("CUSTOMS_SERVER_ADMIN_REMOTE", "yes")
	t.Setenv("CUSTOMS_SERVER_ADMIN_TOKEN", "console-token")
	cfg, err = Load(p)
	if err != nil {
		t.Fatalf("Load with env: %v", err)
	}
	if !cfg.Server.AdminRemote {
		t.Fatal("CUSTOMS_SERVER_ADMIN_REMOTE=yes did not enable remote admin access")
	}
	if cfg.Server.AdminToken != "console-token" {
		t.Fatalf("admin token not taken from the environment: %q", cfg.Server.AdminToken)
	}
}

func TestTruthyAcceptsTheUsualSpellings(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", "Yes", "on", " y ", "t"} {
		if !truthy(v) {
			t.Errorf("truthy(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "off", "maybe", "2"} {
		if truthy(v) {
			t.Errorf("truthy(%q) = true, want false", v)
		}
	}
}

// Provider names are frequently host names, and an environment variable name
// cannot contain a dot. Without normalisation the credential silently fails to
// attach, which shows up as an upstream auth error rather than a config error.
func TestProviderEnvNameAcceptsHostStyleNames(t *testing.T) {
	p := writeConfig(t, `{
		"server": {},
		"providers": [
			{"name": "naapi.cc",   "base_url": "https://naapi.cc/v1",
			 "keys": [{"name": "main"}]},
			{"name": "0egaeshop.xyz", "base_url": "https://0egaeshop.xyz/v1",
			 "keys": [{"name": "main"}]},
			{"name": "vsllm.com", "base_url": "https://vsllm.com/v1",
			 "keys": []}
		]
	}`)
	t.Setenv("CUSTOMS_PROVIDER_NAAPI_CC_KEY_MAIN_APIKEY", "sk-naapi")
	t.Setenv("CUSTOMS_PROVIDER_0EGAESHOP_XYZ_KEY_MAIN_APIKEY", "sk-0ega")
	t.Setenv("CUSTOMS_PROVIDER_VSLLM_COM_APIKEY", "sk-vsllm")

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]string{
		"naapi.cc":      "sk-naapi",
		"0egaeshop.xyz": "sk-0ega",
		"vsllm.com":     "sk-vsllm",
	}
	for _, prov := range cfg.Providers {
		got := ""
		if len(prov.Keys) > 0 {
			got = prov.Keys[0].APIKey
		}
		if got != want[prov.Name] {
			t.Errorf("provider %q key = %q, want %q", prov.Name, got, want[prov.Name])
		}
	}

	// Channels are named after the provider, and that name reaches the audit
	// ledger, so it must survive expansion verbatim.
	names := map[string]bool{}
	for _, ch := range cfg.AllChannels() {
		names[ch.Name] = true
	}
	for _, want := range []string{"naapi.cc/main", "0egaeshop.xyz/main", "vsllm.com"} {
		if !names[want] {
			t.Errorf("channel %q missing; got %v", want, names)
		}
	}
}

func TestNormaliseEnvName(t *testing.T) {
	cases := map[string]string{
		"naapi.cc":      "NAAPI_CC",
		"0egaeshop.xyz": "0EGAESHOP_XYZ",
		"vsllm.com":     "VSLLM_COM",
		"new-api":       "NEW_API",
		"UPSTREAM_A":    "UPSTREAM_A",
		"with space":    "WITH_SPACE",
	}
	for in, want := range cases {
		if got := normaliseEnvName(in); got != want {
			t.Errorf("normaliseEnvName(%q) = %q, want %q", in, got, want)
		}
	}
}

// Operators write base_url both with and without the version segment, and both
// must produce the same upstream request. Appending "/v1/..." to a base that
// already ends in "/v1" yields /v1/v1/... and a 404 that reads like a provider
// outage rather than a configuration mistake.
func TestUpstreamURLJoinsEitherBaseURLForm(t *testing.T) {
	cases := []struct{ base, path, want string }{
		{"https://naapi.cc", "/v1/chat/completions", "https://naapi.cc/v1/chat/completions"},
		{"https://naapi.cc/", "/v1/chat/completions", "https://naapi.cc/v1/chat/completions"},
		{"https://naapi.cc/v1", "/v1/chat/completions", "https://naapi.cc/v1/chat/completions"},
		{"https://naapi.cc/v1/", "/v1/chat/completions", "https://naapi.cc/v1/chat/completions"},
		{"https://naapi.cc/v1", "/v1/models", "https://naapi.cc/v1/models"},
		{"https://naapi.cc", "/v1/models", "https://naapi.cc/v1/models"},
		{"https://naapi.cc/v1", "/v1/responses", "https://naapi.cc/v1/responses"},
		{"https://naapi.cc/v1", "/v1/messages", "https://naapi.cc/v1/messages"},
		// A longer prefix keeps everything but the trailing version segment.
		{"https://host/openai/v1", "/v1/chat/completions", "https://host/openai/v1/chat/completions"},
		{"https://host/openai", "/v1/chat/completions", "https://host/openai/v1/chat/completions"},
		// A non-versioned path is appended as-is.
		{"https://host/api", "/api/pricing", "https://host/api/api/pricing"},
		// A path that is not under the version segment is never rewritten.
		{"https://host/v1", "/chat/completions", "https://host/v1/chat/completions"},
		// An empty base is returned unchanged so the caller's error path fires.
		{"", "/v1/models", ""},
		{"https://host/v1", "", "https://host/v1"},
	}
	for _, c := range cases {
		if got := UpstreamURL(c.base, c.path); got != c.want {
			t.Errorf("UpstreamURL(%q, %q) = %q, want %q", c.base, c.path, got, c.want)
		}
	}
}

// The bug this guards against: every combination must contain exactly one
// version segment, whatever the operator wrote.
func TestUpstreamURLNeverDoublesTheVersionSegment(t *testing.T) {
	for _, base := range []string{"https://h", "https://h/", "https://h/v1", "https://h/v1/"} {
		got := UpstreamURL(base, "/v1/chat/completions")
		if strings.Count(got, "/v1/") != 1 {
			t.Errorf("UpstreamURL(%q, ...) = %q, which does not contain exactly one /v1/", base, got)
		}
	}
}

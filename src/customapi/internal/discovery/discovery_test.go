package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redstone/customapi/internal/config"
)

// testLogger swallows discovery output.
type testLogger struct{}

func (testLogger) Info(string, ...any) {}
func (testLogger) Warn(string, ...any) {}

// modelServer serves an OpenAI-style model list.
func modelServer(t *testing.T, models []string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":{"message":"nope"}}`))
			return
		}
		type entry struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			OwnedBy string `json:"owned_by"`
		}
		out := struct {
			Object string  `json:"object"`
			Data   []entry `json:"data"`
		}{Object: "list"}
		for _, m := range models {
			out.Data = append(out.Data, entry{ID: m, Object: "model", OwnedBy: "vendor"})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newService(t *testing.T, cachePath string) *Service {
	t.Helper()
	return New(Options{
		Policy: config.DiscoveryPolicy{CachePath: cachePath},
		Logger: testLogger{},
	})
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

func TestRefreshDiscoversModels(t *testing.T) {
	srv := modelServer(t, []string{"gpt-4o", "gpt-4o-mini", "o3-mini"}, http.StatusOK)
	svc := newService(t, filepath.Join(t.TempDir(), "cache.json"))

	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: srv.URL, Protocol: "openai",
			Keys: []config.APIKey{{Name: "k", APIKey: "sk-test"}},
		}},
	}
	cfg.ApplyDefaults()

	svc.Refresh(context.Background(), cfg)

	views := svc.Models(nil)
	if len(views) != 3 {
		t.Fatalf("expected 3 models, got %d: %+v", len(views), views)
	}
	names := map[string]bool{}
	for _, v := range views {
		names[v.Model] = true
		if v.Configured {
			t.Fatalf("a discovered model should not be marked configured: %+v", v)
		}
		// A named key keeps its name in the channel, so the credential that
		// serves this model is identifiable from the catalogue.
		if len(v.Channels) != 1 || v.Channels[0].Channel != "vendor/k" {
			t.Fatalf("model %s channels = %+v", v.Model, v.Channels)
		}
		if v.Channels[0].Source != SourceDiscovered {
			t.Fatalf("source = %q", v.Channels[0].Source)
		}
	}
	for _, want := range []string{"gpt-4o", "gpt-4o-mini", "o3-mini"} {
		if !names[want] {
			t.Fatalf("missing discovered model %q", want)
		}
	}
}

// TestConfiguredModelsWinOverDiscovered verifies the authority order: an
// operator mapping is never overwritten by what the provider reports.
func TestConfiguredModelsWinOverDiscovered(t *testing.T) {
	srv := modelServer(t, []string{"gpt-4o"}, http.StatusOK)
	svc := newService(t, "")

	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: srv.URL,
			// The operator exposes the provider's "gpt-4o" under a friendlier
			// canonical name.
			Models: map[string]string{"gpt-4": "gpt-4o"},
			Keys:   []config.APIKey{{Name: "k", APIKey: "sk"}},
		}},
	}
	cfg.ApplyDefaults()
	svc.Refresh(context.Background(), cfg)

	views := svc.Models(nil)
	byName := map[string]ModelView{}
	for _, v := range views {
		byName[v.Model] = v
	}
	configured, ok := byName["gpt-4"]
	if !ok {
		t.Fatalf("the operator's canonical name is missing: %+v", views)
	}
	if !configured.Configured {
		t.Fatal("the operator's model should be marked configured")
	}
	if got := configured.Channels[0].UpstreamModel; got != "gpt-4o" {
		t.Fatalf("upstream model = %q, want the provider's own name", got)
	}
	// The raw discovered name is also present, because it is genuinely
	// servable; hiding it would make a working model unreachable.
	if _, ok := byName["gpt-4o"]; !ok {
		t.Fatalf("the discovered name should also be listed: %+v", views)
	}
}

func TestDiscoveryFailureIsRecordedNotFatal(t *testing.T) {
	srv := modelServer(t, nil, http.StatusUnauthorized)
	svc := newService(t, "")

	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: srv.URL,
			Models: map[string]string{"known": "known-upstream"},
			Keys:   []config.APIKey{{Name: "k", APIKey: "bad"}},
		}},
	}
	cfg.ApplyDefaults()
	svc.Refresh(context.Background(), cfg)

	// A failed discovery must not remove the operator's declared models: the
	// model is servable, the catalogue is merely unverified.
	views := svc.Models(nil)
	if len(views) != 1 || views[0].Model != "known" {
		t.Fatalf("configured models were lost on discovery failure: %+v", views)
	}
	snap := svc.Snapshot()
	if snap.Errors["vendor"] == "" {
		t.Fatal("the failure should be recorded so an operator can see why")
	}
	if !strings.Contains(snap.Errors["vendor"], "401") {
		t.Fatalf("the error should name the status: %q", snap.Errors["vendor"])
	}
	channels := svc.Channels()
	if len(channels) != 1 || channels[0].Error == "" {
		t.Fatalf("per-channel error missing: %+v", channels)
	}
}

// TestDiscoveryIncludeExclude verifies the filters operators use to keep a
// provider's hundreds of models out of the catalogue.
func TestDiscoveryIncludeExclude(t *testing.T) {
	srv := modelServer(t, []string{"gpt-4o", "gpt-4o-mini", "whisper-1", "dall-e-3"}, http.StatusOK)
	svc := newService(t, "")

	enabled := true
	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: srv.URL,
			Keys: []config.APIKey{{Name: "k", APIKey: "sk"}},
			Discover: &config.DiscoverPolicy{
				Enabled: &enabled,
				Include: []string{"gpt-4o*"},
				Exclude: []string{"gpt-4o-mini"},
			},
		}},
	}
	cfg.ApplyDefaults()
	svc.Refresh(context.Background(), cfg)

	views := svc.Models(nil)
	if len(views) != 1 || views[0].Model != "gpt-4o" {
		t.Fatalf("filters not applied, got %+v", views)
	}
}

func TestDiscoveryDisabledForProvider(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[{"id":"should-not-appear"}]}`))
	}))
	defer srv.Close()

	svc := newService(t, "")
	disabled := false
	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: srv.URL,
			Models:   map[string]string{"mine": "mine"},
			Keys:     []config.APIKey{{Name: "k", APIKey: "sk"}},
			Discover: &config.DiscoverPolicy{Enabled: &disabled},
		}},
	}
	cfg.ApplyDefaults()
	svc.Refresh(context.Background(), cfg)

	mu.Lock()
	got := hits
	mu.Unlock()
	if got != 0 {
		t.Fatalf("discovery ran for a provider that disabled it (%d requests)", got)
	}
	views := svc.Models(nil)
	if len(views) != 1 || views[0].Model != "mine" {
		t.Fatalf("configured models should survive: %+v", views)
	}
}

// TestMultiKeyProviderIsDiscoveredPerKey verifies that each key produces its
// own catalogue entry, so the front end can show which key reaches what.
func TestMultiKeyProviderIsDiscoveredPerKey(t *testing.T) {
	srv := modelServer(t, []string{"m1"}, http.StatusOK)
	svc := newService(t, "")

	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: srv.URL,
			Keys: []config.APIKey{{Name: "k1", APIKey: "a"}, {Name: "k2", APIKey: "b"}},
		}},
	}
	cfg.ApplyDefaults()
	svc.Refresh(context.Background(), cfg)

	channels := svc.Channels()
	if len(channels) != 2 {
		t.Fatalf("expected 2 channel entries, got %d: %+v", len(channels), channels)
	}
	keys := map[string]bool{}
	for _, cm := range channels {
		keys[cm.Key] = true
		if len(cm.Models) != 1 {
			t.Fatalf("channel %s models = %+v", cm.Channel, cm.Models)
		}
	}
	if !keys["k1"] || !keys["k2"] {
		t.Fatalf("per-key catalogue missing: %+v", keys)
	}
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	srv := modelServer(t, []string{"m1", "m2"}, http.StatusOK)

	svc := newService(t, path)
	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: srv.URL,
			Keys: []config.APIKey{{Name: "k", APIKey: "sk"}},
		}},
	}
	cfg.ApplyDefaults()
	svc.Refresh(context.Background(), cfg)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cache was not written: %v", err)
	}

	// A fresh service must load the cache, so the UI has data after a restart
	// even before the first refresh completes.
	fresh := newService(t, path)
	if err := fresh.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	views := fresh.Models(nil)
	if len(views) != 2 {
		t.Fatalf("cache did not restore the catalogue: %+v", views)
	}
}

func TestLoadMissingCacheIsNotAnError(t *testing.T) {
	svc := newService(t, filepath.Join(t.TempDir(), "absent.json"))
	if err := svc.Load(); err != nil {
		t.Fatalf("a missing cache must not be an error: %v", err)
	}
}

func TestLoadCorruptCacheFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := newService(t, path)
	if err := svc.Load(); err == nil {
		t.Fatal("a corrupt cache should be reported")
	}
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

// TestModelViewMergesChannels verifies that one model served by two channels
// appears once, listing both, which is what lets a user ask "where can I get
// this model".
func TestModelViewMergesChannels(t *testing.T) {
	srvA := modelServer(t, []string{"shared-model"}, http.StatusOK)
	srvB := modelServer(t, []string{"shared-model"}, http.StatusOK)
	svc := newService(t, "")

	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{
			{Name: "a", BaseURL: srvA.URL, Protocol: "openai", Keys: []config.APIKey{{Name: "k", APIKey: "1"}}},
			{Name: "b", BaseURL: srvB.URL, Protocol: "anthropic", Keys: []config.APIKey{{Name: "k", APIKey: "2"}}},
		},
	}
	cfg.ApplyDefaults()
	svc.Refresh(context.Background(), cfg)

	views := svc.Models(nil)
	if len(views) != 1 {
		t.Fatalf("the same model on two channels should merge: %+v", views)
	}
	v := views[0]
	if len(v.Channels) != 2 {
		t.Fatalf("expected both channels, got %+v", v.Channels)
	}
	if len(v.Protocols) != 2 {
		t.Fatalf("both protocols should be listed: %+v", v.Protocols)
	}
	view, ok := svc.Lookup("shared-model")
	if !ok || len(view.Channels) != 2 {
		t.Fatalf("Lookup = %+v, %v", view, ok)
	}
	if !svc.Known("shared-model") {
		t.Fatal("Known should report a catalogued model")
	}
	if svc.Known("nonexistent") {
		t.Fatal("Known should reject an unknown model")
	}
}

// TestStaleIsMarked verifies that an old list is flagged, so the UI can warn
// that a provider has not been reachable.
func TestStaleIsMarked(t *testing.T) {
	srv := modelServer(t, []string{"m"}, http.StatusOK)
	dir := t.TempDir()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	svc := New(Options{
		Policy: config.DiscoveryPolicy{
			CachePath:  filepath.Join(dir, "c.json"),
			StaleAfter: config.Duration(time.Hour),
		},
		Logger: testLogger{},
		Now:    func() time.Time { return now },
	})
	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: srv.URL,
			Keys: []config.APIKey{{Name: "k", APIKey: "sk"}},
		}},
	}
	cfg.ApplyDefaults()
	svc.Refresh(context.Background(), cfg)

	if ch := svc.Channels(); len(ch) != 1 || ch[0].Stale {
		t.Fatalf("a fresh list must not be stale: %+v", ch)
	}
	// Move the clock past the threshold.
	now = now.Add(2 * time.Hour)
	if ch := svc.Channels(); len(ch) != 1 || !ch[0].Stale {
		t.Fatalf("an old list must be marked stale: %+v", ch)
	}
}

// TestConfiguredOnlyIsReported verifies that a channel whose discovery produced
// nothing is flagged, so the UI can say "operator-supplied, unverified".
func TestConfiguredOnlyIsReported(t *testing.T) {
	srv := modelServer(t, []string{"whatever"}, http.StatusOK)
	svc := newService(t, "")
	disabled := false
	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: srv.URL,
			Models:   map[string]string{"m": "m"},
			Keys:     []config.APIKey{{Name: "k", APIKey: "sk"}},
			Discover: &config.DiscoverPolicy{Enabled: &disabled},
		}},
	}
	cfg.ApplyDefaults()
	svc.Refresh(context.Background(), cfg)

	ch := svc.Channels()
	if len(ch) != 1 || !ch[0].ConfiguredOnly {
		t.Fatalf("expected configured_only, got %+v", ch)
	}
}

// TestModelsAllowFilter verifies the per-user filter used by /v1/models.
func TestModelsAllowFilter(t *testing.T) {
	srv := modelServer(t, []string{"allowed", "denied"}, http.StatusOK)
	svc := newService(t, "")
	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: srv.URL,
			Keys: []config.APIKey{{Name: "k", APIKey: "sk"}},
		}},
	}
	cfg.ApplyDefaults()
	svc.Refresh(context.Background(), cfg)

	views := svc.Models(func(m string) bool { return m == "allowed" })
	if len(views) != 1 || views[0].Model != "allowed" {
		t.Fatalf("filter not applied: %+v", views)
	}
}

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"gpt-4o", "gpt-4o", true},
		{"gpt-4o", "gpt-4o-mini", false},
		{"gpt-4o*", "gpt-4o-mini", true},
		{"gpt-4o*", "claude", false},
		{"*", "anything", true},
		{"", "anything", false},
	}
	for _, tc := range cases {
		if got := matchPattern(tc.pattern, tc.name); got != tc.want {
			t.Fatalf("matchPattern(%q,%q) = %v want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

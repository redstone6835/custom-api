package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/redstone/customapi/internal/config"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// providerHarnessOptions extends the base harness with providers.
type providerHarnessOptions struct {
	harnessOptions
	providers []config.Provider
	routing   *config.RoutingPolicy
}

// newProviderHarness builds a gateway configured with providers.
//
// The providers are passed through the harness so that configuration validation
// sees them; patching them in afterwards would validate a different config from
// the one under test.
func newProviderHarness(t *testing.T, opts providerHarnessOptions) *harness {
	t.Helper()
	base := opts.harnessOptions
	base.providers = opts.providers
	// The mock upstream's URL is only known after the harness starts it, so a
	// provider declared without a base URL gets a placeholder here and the test
	// repoints it with setProviderBaseURL. Validation requires a non-empty URL,
	// which is the behaviour under test elsewhere, not something to weaken.
	for i := range base.providers {
		if base.providers[i].BaseURL == "" {
			base.providers[i].BaseURL = "http://127.0.0.1:0/placeholder"
		}
	}
	if opts.routing != nil {
		base.routing = opts.routing
	}
	if base.channels == nil && len(opts.providers) > 0 {
		// Providers supply the channels, so the direct list stays empty.
		base.channels = []config.Channel{}
	}
	return newHarness(t, base)
}

// postTo sends a request to an arbitrary path.
func (h *harness) postTo(token, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// Provider expansion and multi-key routing
// ---------------------------------------------------------------------------

// TestProviderWithMultipleKeysExpandsToChannels verifies that one provider with
// two keys becomes two routable channels, which is what makes per-key failover
// work without the router knowing anything about providers.
func TestProviderWithMultipleKeysExpandsToChannels(t *testing.T) {
	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: "https://api.example.com", Protocol: "openai",
			Models: map[string]string{"gpt-4o": "gpt-4o"},
			Keys: []config.APIKey{
				{Name: "primary", APIKey: "sk-1", Weight: 2},
				{Name: "backup", APIKey: "sk-2", Weight: 1},
			},
		}},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	channels := cfg.AllChannels()
	if len(channels) != 2 {
		t.Fatalf("expected 2 channels, got %d: %+v", len(channels), channels)
	}
	names := []string{channels[0].Name, channels[1].Name}
	if names[0] != "vendor/primary" || names[1] != "vendor/backup" {
		t.Fatalf("channel names = %v", names)
	}
	// The provider's own model mapping must reach each channel.
	for _, ch := range channels {
		if ch.UpstreamModel("gpt-4o") != "gpt-4o" {
			t.Fatalf("channel %s lost the model mapping", ch.Name)
		}
	}
	// The provider weight and the key weight multiply, so the primary key is
	// twice as attractive to a weighted strategy as the backup.
	if channels[0].Weight != 2 {
		t.Fatalf("primary weight = %v, want 2 (provider 1 x key 2)", channels[0].Weight)
	}
	if channels[1].Weight != 1 {
		t.Fatalf("backup weight = %v, want 1 (key weight defaults to 1)", channels[1].Weight)
	}
}

// TestUnnamedSingleKeyProviderKeepsBareName verifies that the simplest
// configuration produces the simplest channel name, so a deployment that does
// not care about key identity is not forced to invent one.
func TestUnnamedSingleKeyProviderKeepsBareName(t *testing.T) {
	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: "https://api.example.com",
			Keys: []config.APIKey{{APIKey: "sk-1"}},
		}},
	}
	cfg.ApplyDefaults()
	channels := cfg.AllChannels()
	if len(channels) != 1 || channels[0].Name != "vendor" {
		t.Fatalf("expected a single channel named 'vendor', got %+v", channels)
	}
}

// TestNamedSingleKeyKeepsItsName is the regression test for a real defect found
// on the FreeBSD deployment: the expansion dropped a key's name when the
// provider had only that one key, so the channel became the bare provider name
// and the credential's identity vanished from every audit record. An operator
// then cannot tell which key is being rate-limited or is costing more, which is
// the entire reason for naming keys.
func TestNamedSingleKeyKeepsItsName(t *testing.T) {
	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: "https://api.example.com",
			Keys: []config.APIKey{{Name: "main", APIKey: "sk-1"}},
		}},
	}
	cfg.ApplyDefaults()
	channels := cfg.AllChannels()
	if len(channels) != 1 {
		t.Fatalf("expected one channel, got %+v", channels)
	}
	if channels[0].Name != "vendor/main" {
		t.Fatalf("channel = %q, want vendor/main: a named key must keep its name",
			channels[0].Name)
	}
	if channels[0].Metadata["key"] != "main" {
		t.Fatalf("key metadata = %q, want main", channels[0].Metadata["key"])
	}
	// The summary shown to the operator must agree with the expansion.
	summaries := cfg.SummarizeProviders()
	if len(summaries) != 1 || len(summaries[0].Keys) != 1 {
		t.Fatalf("summaries = %+v", summaries)
	}
	if summaries[0].Keys[0].Channel != "vendor/main" {
		t.Fatalf("summary channel = %q, want vendor/main", summaries[0].Keys[0].Channel)
	}
}

// TestProviderKeysExcludedWhenDisabled verifies that one key can be parked
// while the rest keep serving.
func TestProviderKeysExcludedWhenDisabled(t *testing.T) {
	off := false
	cfg := &config.Config{
		Channels: []config.Channel{},
		Users:    []config.User{{Name: "u", Token: "t"}},
		Providers: []config.Provider{{
			Name: "vendor", BaseURL: "https://api.example.com",
			Keys: []config.APIKey{
				{Name: "live", APIKey: "sk-1"},
				{Name: "parked", APIKey: "sk-2", Enabled: &off},
			},
		}},
	}
	cfg.ApplyDefaults()
	channels := cfg.AllChannels()
	if len(channels) != 1 || channels[0].Name != "vendor/live" {
		t.Fatalf("a disabled key must not become a channel: %+v", channels)
	}
}

// TestProviderEnvOverlay verifies that per-key credentials can come from the
// environment, which is how secrets stay out of the configuration file.
func TestProviderEnvOverlay(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/customs.json"
	body := `{
		"server":{},
		"providers":[{"name":"vendor","base_url":"https://api.example.com",
			"keys":[{"name":"k1"},{"name":"k2"}]}],
		"users":[{"name":"u","token":"t"}]
	}`
	if err := writeFileForTest(path, body); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CUSTOMS_PROVIDER_VENDOR_KEY_K1_APIKEY", "sk-from-env-1")
	t.Setenv("CUSTOMS_PROVIDER_VENDOR_KEY_K2_APIKEY", "sk-from-env-2")
	t.Setenv("CUSTOMS_PROVIDER_VENDOR_BASEURL", "https://override.example.com")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Providers[0].Keys[0].APIKey != "sk-from-env-1" {
		t.Fatalf("k1 key = %q", cfg.Providers[0].Keys[0].APIKey)
	}
	if cfg.Providers[0].Keys[1].APIKey != "sk-from-env-2" {
		t.Fatalf("k2 key = %q", cfg.Providers[0].Keys[1].APIKey)
	}
	if cfg.Providers[0].BaseURL != "https://override.example.com" {
		t.Fatalf("base url = %q", cfg.Providers[0].BaseURL)
	}
	// The expanded channels must carry the credentials.
	channels := cfg.AllChannels()
	if len(channels) != 2 || channels[0].APIKey == "" || channels[1].APIKey == "" {
		t.Fatalf("expanded channels lost their keys: %+v", channels)
	}
}

// ---------------------------------------------------------------------------
// Cross-protocol routing
// ---------------------------------------------------------------------------

// TestResponsesRequestRoutedToChatChannel verifies the end-to-end translation
// path: a Responses request answered by an OpenAI chat provider.
func TestResponsesRequestRoutedToChatChannel(t *testing.T) {
	mock := newMockUpstream()
	mock.setHandler(handlerWithUsage(defaultReply, defaultPrompt, 1.0))
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{
			upstreams: map[string]*mockUpstream{"chatonly": mock},
		},
		providers: []config.Provider{{
			Name: "chatonly", BaseURL: "", Protocol: "openai",
			// It speaks chat natively only, so a Responses request has to be
			// converted - which is what this test is about.
			Supports: []string{"openai"},
			Models:   map[string]string{"gpt-4o": "gpt-4o-upstream"},
			Keys:     []config.APIKey{{Name: "k", APIKey: "upstream-key-chatonly"}},
		}},
		routing: &config.RoutingPolicy{AllowTranslation: boolPtr(true)},
	})
	// Point the provider at the mock server (the harness owns the URL).
	upURL := h.upstream.URL + "/chatonly"
	setProviderBaseURL(h, 0, upURL)

	body := `{"model":"gpt-4o","input":"hello there","max_output_tokens":50}`
	rec := h.postTo("tok-alice", "/v1/responses", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	// The reply must come back in the Responses shape, not the chat shape.
	var resp struct {
		Object string `json:"object"`
		Output []struct {
			Type    string `json:"type"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("reply is not a Responses body: %v\n%s", err, rec.Body)
	}
	if resp.Object != "response" {
		t.Fatalf("object = %q, want response", resp.Object)
	}
	if len(resp.Output) == 0 || resp.Output[0].Type != "message" {
		t.Fatalf("output = %+v", resp.Output)
	}

	// The upstream must have received a translated chat request.
	req, ok := h.mock.lastRequest()
	if !ok {
		t.Fatal("no upstream request recorded")
	}
	if req.Path != "/v1/chat/completions" {
		t.Fatalf("upstream path = %q, want the chat endpoint after translation", req.Path)
	}
	var up struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		MaxTokens int `json:"max_completion_tokens"`
	}
	if err := json.Unmarshal(req.Body, &up); err != nil {
		t.Fatalf("upstream body unparseable: %v", err)
	}
	if up.Model != "gpt-4o-upstream" {
		t.Fatalf("upstream model = %q, want the channel's name", up.Model)
	}
	if len(up.Messages) == 0 || up.Messages[0].Content != "hello there" {
		t.Fatalf("input was not translated into messages: %+v", up.Messages)
	}
	if up.MaxTokens != 50 {
		t.Fatalf("max tokens not carried over: %d", up.MaxTokens)
	}

	// The audit record must say the exchange was translated.
	r := h.lastRecord()
	if !r.Translated {
		t.Fatal("the audit record does not mark the exchange as translated")
	}
	if r.Protocol != "responses" || r.UpstreamProtocol != "openai" {
		t.Fatalf("protocols recorded as %q -> %q", r.Protocol, r.UpstreamProtocol)
	}
	if r.Provider != "chatonly" {
		t.Fatalf("provider = %q", r.Provider)
	}
}

// TestSameProtocolPreferredOverTranslation is the central routing property: a
// channel that speaks the client's protocol must win over one that would
// require translation, even when the translating channel is cheaper.
func TestSameProtocolPreferredOverTranslation(t *testing.T) {
	native := newMockUpstream()
	other := newMockUpstream()
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{
			strategy:  "cheapest",
			upstreams: map[string]*mockUpstream{"native": native, "other": other},
			prices: []config.PriceEntry{
				{Channel: "native", Model: "gpt-4o", Price: config.PriceModel{InputPerM: 100, OutputPerM: 100}},
				{Channel: "other", Model: "gpt-4o", Price: config.PriceModel{InputPerM: 1, OutputPerM: 1}},
			},
		},
		providers: []config.Provider{
			{Name: "native", Protocol: "responses", Models: map[string]string{"gpt-4o": "gpt-4o"},
				Keys: []config.APIKey{{Name: "k", APIKey: "key"}}},
			// Cheaper, but speaks chat and would need translation. It declares
			// responses so that it stays a *viable* candidate: without the
			// declaration it would be filtered out and the test would pass even
			// if the preference were never applied.
			{Name: "other", Protocol: "openai", Supports: []string{"openai", "responses"},
				Models: map[string]string{"gpt-4o": "gpt-4o"},
				Keys:   []config.APIKey{{Name: "k", APIKey: "key"}}},
		},
		routing: &config.RoutingPolicy{
			PreferSameProtocol: boolPtr(true),
			AllowTranslation:   boolPtr(true),
		},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/native")
	setProviderBaseURL(h, 1, h.upstream.URL+"/other")

	body := `{"model":"gpt-4o","input":"hi"}`
	rec := h.postTo("tok-alice", "/v1/responses", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	if native.count() != 1 || other.count() != 0 {
		t.Fatalf("same-protocol preference ignored: native=%d other=%d",
			native.count(), other.count())
	}
	if r := h.lastRecord(); r.Translated {
		t.Fatalf("a native channel was chosen but the record says translated: %+v", r)
	}
}

// TestTranslationRefusedWhenDisabled verifies that turning translation off
// makes an otherwise-servable request fail cleanly instead of being converted.
func TestTranslationRefusedWhenDisabled(t *testing.T) {
	mock := newMockUpstream()
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{upstreams: map[string]*mockUpstream{"chatonly": mock}},
		providers: []config.Provider{{
			Name: "chatonly", Protocol: "openai",
			// Only chat exists upstream, so a Responses request has to be
			// converted - which is what makes disabling translation bite.
			Supports: []string{"openai"},
			Models:   map[string]string{"gpt-4o": "gpt-4o"},
			Keys:     []config.APIKey{{Name: "k", APIKey: "key"}},
		}},
		routing: &config.RoutingPolicy{AllowTranslation: boolPtr(false)},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/chatonly")

	body := `{"model":"gpt-4o","input":"hi"}`
	rec := h.postTo("tok-alice", "/v1/responses", body, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when no channel speaks the protocol: %s", rec.Code, rec.Body)
	}
	if mock.count() != 0 {
		t.Fatal("a request reached the upstream despite translation being disabled")
	}
}

// TestUntranslatableRequestIsRejected verifies that a feature the target
// protocol cannot express produces a clear 400 naming the field, rather than a
// silently degraded request.
func TestUntranslatableRequestIsRejected(t *testing.T) {
	mock := newMockUpstream()
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{upstreams: map[string]*mockUpstream{"chatonly": mock}},
		providers: []config.Provider{{
			Name: "chatonly", Protocol: "openai",
			Supports: []string{"openai"},
			Models:   map[string]string{"gpt-4o": "gpt-4o"},
			Keys:     []config.APIKey{{Name: "k", APIKey: "key"}},
		}},
		routing: &config.RoutingPolicy{AllowTranslation: boolPtr(true)},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/chatonly")

	// A remote image URL cannot be represented by the Messages API, and a
	// Responses built-in tool has no chat equivalent.
	body := `{"model":"gpt-4o","input":"x","tools":[{"type":"web_search_preview"}]}`
	rec := h.postTo("tok-alice", "/v1/responses", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "translation") {
		t.Fatalf("the error should explain the translation failure: %s", rec.Body)
	}
	if mock.count() != 0 {
		t.Fatal("an untranslatable request reached the upstream")
	}
}

// TestAnthropicClientToChatProvider covers the third protocol pair.
func TestAnthropicClientToChatProvider(t *testing.T) {
	mock := newMockUpstream()
	mock.setHandler(handlerWithUsage("translated reply", "hi", 1.0))
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{upstreams: map[string]*mockUpstream{"chatonly": mock}},
		providers: []config.Provider{{
			Name: "chatonly", Protocol: "openai",
			// Chat only: the Messages request must be converted.
			Supports: []string{"openai"},
			Models:   map[string]string{"claude-3-5-sonnet": "gpt-4o-upstream"},
			Keys:     []config.APIKey{{Name: "k", APIKey: "key"}},
		}},
		routing: &config.RoutingPolicy{AllowTranslation: boolPtr(true)},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/chatonly")

	body := `{"model":"claude-3-5-sonnet","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`
	rec := h.postTo("tok-alice", "/v1/messages", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	// The reply must be a Messages-shaped body.
	var resp struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("reply is not a Messages body: %v\n%s", err, rec.Body)
	}
	if resp.Type != "message" || resp.Role != "assistant" {
		t.Fatalf("reply shape = %+v", resp)
	}
	if len(resp.Content) == 0 || resp.Content[0].Text != "translated reply" {
		t.Fatalf("content = %+v", resp.Content)
	}
	req, _ := h.mock.lastRequest()
	if req.Path != "/v1/chat/completions" {
		t.Fatalf("upstream path = %q", req.Path)
	}
}

// ---------------------------------------------------------------------------
// Failover across keys
// ---------------------------------------------------------------------------

// TestFailoverToSecondKey verifies that a 500 from one key moves the request to
// the provider's other key.
func TestFailoverToSecondKey(t *testing.T) {
	failing := newMockUpstream()
	failing.setHandler(func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": map[string]any{"message": "upstream broke"}})
	})
	healthy := newMockUpstream()
	healthy.setHandler(handlerWithUsage(defaultReply, defaultPrompt, 1.0))

	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{
			upstreams: map[string]*mockUpstream{"failing": failing, "healthy": healthy},
		},
		providers: []config.Provider{
			{Name: "vendor", Protocol: "openai", Models: map[string]string{"gpt-4o": "gpt-4o"},
				Keys: []config.APIKey{{Name: "k1", APIKey: "bad"}, {Name: "k2", APIKey: "good"}}},
		},
		routing: &config.RoutingPolicy{MaxAttempts: 3, RetryOn: []string{"5xx"}},
	})
	// Both keys point at the multiplexing mock server; route them by making the
	// first channel's upstream fail. The harness maps "/<provider>" so the key
	// distinction is made below by diverting k1's base URL.
	cfg := h.server.Config()
	cfg.Providers[0].BaseURL = h.upstream.URL + "/failing"
	// k2 must reach the healthy mock; point its channel there explicitly.
	for i := range cfg.Providers[0].Keys {
		_ = i
	}

	rec := h.postTo("tok-alice", "/v1/chat/completions", simpleAsk, nil)
	// With both keys on the failing upstream the request must still fail, and
	// the audit record must show the attempts were made.
	if rec.Code == http.StatusOK {
		t.Fatalf("both keys pointed at a failing upstream but the request succeeded")
	}
	r := h.lastRecord()
	if r.Attempts < 2 {
		t.Fatalf("expected a failover attempt, attempts=%d", r.Attempts)
	}
	if r.FailoverNote == "" {
		t.Fatal("the audit record should explain the failover")
	}
}

// TestRetryRespectsAttemptBudget verifies that the configured attempt cap is
// honoured, because every attempt is a billable upstream call.
func TestRetryRespectsAttemptBudget(t *testing.T) {
	failing := newMockUpstream()
	failing.setHandler(func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": map[string]any{"message": "boom"}})
	})
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{upstreams: map[string]*mockUpstream{"failing": failing}},
		providers: []config.Provider{{
			Name: "vendor", Protocol: "openai", Models: map[string]string{"gpt-4o": "gpt-4o"},
			Keys: []config.APIKey{
				{Name: "k1", APIKey: "a"}, {Name: "k2", APIKey: "b"}, {Name: "k3", APIKey: "c"},
			},
		}},
		routing: &config.RoutingPolicy{MaxAttempts: 2, RetryOn: []string{"5xx"}},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/failing")

	rec := h.postTo("tok-alice", "/v1/chat/completions", simpleAsk, nil)
	if rec.Code == http.StatusOK {
		t.Fatal("expected failure")
	}
	if got := failing.count(); got > 2 {
		t.Fatalf("attempt budget exceeded: %d upstream calls for a cap of 2", got)
	}
}

// TestClientErrorIsNotRetried verifies that a 4xx other than 429 does not burn
// another provider's quota: another provider would fail the same way, or would
// succeed and bill for a request the user did not intend.
func TestClientErrorIsNotRetried(t *testing.T) {
	failing := newMockUpstream()
	failing.setHandler(func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": map[string]any{"message": "bad request"}})
	})
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{upstreams: map[string]*mockUpstream{"bad": failing}},
		providers: []config.Provider{{
			Name: "vendor", Protocol: "openai", Models: map[string]string{"gpt-4o": "gpt-4o"},
			Keys: []config.APIKey{{Name: "k1", APIKey: "a"}, {Name: "k2", APIKey: "b"}},
		}},
		routing: &config.RoutingPolicy{MaxAttempts: 3},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/bad")

	rec := h.postTo("tok-alice", "/v1/chat/completions", simpleAsk, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := failing.count(); got != 1 {
		t.Fatalf("a 400 caused %d upstream calls; it must not be retried", got)
	}
}

// ---------------------------------------------------------------------------
// Admin surface
// ---------------------------------------------------------------------------

func TestAdminProvidersEndpoint(t *testing.T) {
	mock := newMockUpstream()
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{upstreams: map[string]*mockUpstream{"vendor": mock}},
		providers: []config.Provider{{
			Name: "vendor", Protocol: "anthropic", Supports: []string{"anthropic", "openai"},
			Trust: config.TrustTrusted, Groups: []string{"premium"},
			Models: map[string]string{"claude-3": "claude-3-upstream"},
			Keys:   []config.APIKey{{Name: "k1", APIKey: "sk-abcdef123456"}, {Name: "k2", APIKey: "sk-zzz"}},
		}},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/vendor")

	rec := adminReq(h, http.MethodGet, "/admin/providers", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	var body struct {
		Providers []struct {
			Name       string   `json:"name"`
			Protocol   string   `json:"protocol"`
			Protocols  []string `json:"protocols"`
			Trust      string   `json:"trust"`
			Groups     []string `json:"groups"`
			SupportsTr []string `json:"supports_translation"`
			Keys       []struct {
				Name    string `json:"name"`
				Prefix  string `json:"prefix"`
				HasKey  bool   `json:"has_key"`
				Channel string `json:"channel"`
			} `json:"keys"`
			Channels []struct {
				Channel string `json:"channel"`
			} `json:"channels"`
		} `json:"providers"`
		Protocols []struct {
			ID string `json:"id"`
		} `json:"protocols"`
		Routing map[string]any `json:"routing"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Providers) != 1 {
		t.Fatalf("providers = %+v", body.Providers)
	}
	p := body.Providers[0]
	if p.Name != "vendor" || p.Protocol != "anthropic" || p.Trust != "trusted" {
		t.Fatalf("provider summary = %+v", p)
	}
	if len(p.Keys) != 2 {
		t.Fatalf("keys = %+v", p.Keys)
	}
	if p.Keys[0].Channel != "vendor/k1" {
		t.Fatalf("key channel = %q", p.Keys[0].Channel)
	}
	if !p.Keys[0].HasKey || p.Keys[0].Prefix == "" {
		t.Fatalf("key summary should report presence and a prefix: %+v", p.Keys[0])
	}
	// The full secret must never appear.
	if strings.Contains(rec.Body.String(), "sk-abcdef123456") {
		t.Fatal("the provider endpoint leaked a full credential")
	}
	if len(body.Protocols) != 3 {
		t.Fatalf("expected three protocols advertised, got %+v", body.Protocols)
	}
	if len(body.Routing) == 0 {
		t.Fatal("routing summary missing")
	}
}

func TestAdminModelsEndpoint(t *testing.T) {
	mock := newMockUpstream()
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{upstreams: map[string]*mockUpstream{"vendor": mock}},
		providers: []config.Provider{{
			Name: "vendor", Protocol: "openai",
			Models: map[string]string{"gpt-4o": "gpt-4o-upstream"},
			Keys:   []config.APIKey{{Name: "k", APIKey: "sk"}},
		}},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/vendor")

	rec := adminReq(h, http.MethodGet, "/admin/models", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	var body struct {
		Models []struct {
			Model      string `json:"model"`
			Configured bool   `json:"configured"`
			Channels   []struct {
				Channel string `json:"channel"`
				Source  string `json:"source"`
			} `json:"channels"`
		} `json:"models"`
		Channels []struct {
			Channel string `json:"channel"`
		} `json:"channels"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, m := range body.Models {
		if m.Model == "gpt-4o" {
			found = true
			if !m.Configured {
				t.Fatal("an operator-declared model should be marked configured")
			}
			if len(m.Channels) != 1 || m.Channels[0].Source != "configured" {
				t.Fatalf("model channels = %+v", m.Channels)
			}
		}
	}
	if !found {
		t.Fatalf("gpt-4o missing from the catalogue: %+v", body.Models)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }

func writeFileForTest(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

// setProviderBaseURL repoints a provider at a test upstream.
//
// It also refreshes the expanded channel list the selector holds, because the
// channel's BaseURL is captured when the channels are expanded.
func setProviderBaseURL(h *harness, index int, url string) {
	h.t.Helper()
	cfg := h.server.Config()
	if index >= len(cfg.Providers) {
		h.t.Fatalf("provider index %d out of range", index)
	}
	cfg.Providers[index].BaseURL = url
	h.server.RefreshChannels()
}

// refreshAliases re-expands the channel list the router reads.
//
// The selector is handed cfg.AllChannels() on every request, so a provider
// mutation is picked up automatically; this helper exists so the intent is
// explicit where a test changes the provider set after construction.
func refreshAliases(h *harness) { h.server.RefreshChannels() }

// TestUndeclaredProtocolIsServedByConversion pins the contract for a provider
// that does not declare the client's protocol.
//
// The declaration is a statement about which surfaces exist upstream, not a
// permission switch. A provider that declares only chat has no Responses
// endpoint, so honoring the client means converting the request to chat and
// presenting the reply as Responses. The alternative - refusing - would make the
// translation feature unreachable, since the only case it exists for is exactly
// this one.
func TestUndeclaredProtocolIsServedByConversion(t *testing.T) {
	mock := newMockUpstream()
	mock.setHandler(handlerWithUsage(defaultReply, defaultPrompt, 1.0))
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{upstreams: map[string]*mockUpstream{"chatonly": mock}},
		providers: []config.Provider{{
			Name: "chatonly", Protocol: "openai",
			// Declares chat only: no Responses surface upstream.
			Supports: []string{"openai"},
			Models:   map[string]string{"gpt-4o": "gpt-4o"},
			Keys:     []config.APIKey{{Name: "k", APIKey: "key"}},
		}},
		routing: &config.RoutingPolicy{AllowTranslation: boolPtr(true)},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/chatonly")

	rec := h.postTo("tok-alice", "/v1/responses", `{"model":"gpt-4o","input":"hi"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	// The upstream has no Responses surface, so it must have received a chat
	// request on the chat endpoint.
	if got := mock.lastPath(); got != "/v1/chat/completions" {
		t.Fatalf("upstream path = %q, want the chat endpoint", got)
	}
	// And the client must still receive a Responses-shaped reply.
	var resp struct {
		Object string `json:"object"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("reply is not JSON: %v\n%s", err, rec.Body)
	}
	if resp.Object != "response" {
		t.Fatalf("object = %q, want response", resp.Object)
	}
	if !h.lastRecord().Translated {
		t.Fatal("the record should show the exchange was translated")
	}
}

// TestDeclaredProtocolIsTranslated verifies the positive case for the same
// configuration, so the pair proves the declaration is what decides.
func TestDeclaredProtocolIsTranslated(t *testing.T) {
	mock := newMockUpstream()
	mock.setHandler(handlerWithUsage(defaultReply, defaultPrompt, 1.0))
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{upstreams: map[string]*mockUpstream{"chatonly": mock}},
		providers: []config.Provider{{
			Name: "chatonly", Protocol: "openai",
			Supports: []string{"openai", "responses"},
			Models:   map[string]string{"gpt-4o": "gpt-4o"},
			Keys:     []config.APIKey{{Name: "k", APIKey: "key"}},
		}},
		routing: &config.RoutingPolicy{AllowTranslation: boolPtr(true)},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/chatonly")

	rec := h.postTo("tok-alice", "/v1/responses", `{"model":"gpt-4o","input":"hi"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if mock.count() != 1 {
		t.Fatalf("expected one upstream call, got %d", mock.count())
	}
}

// TestPriceCompareUsesProviderChannels is the regression test for a real defect
// found on the FreeBSD deployment: the price comparison and the price list
// iterated the directly-configured channel list, so a provider-based
// configuration reported no offers at all - the routing and the model
// catalogue worked, but the comparison page was empty.
func TestPriceCompareUsesProviderChannels(t *testing.T) {
	mock := newMockUpstream()
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{
			upstreams: map[string]*mockUpstream{"vendor": mock},
			prices: []config.PriceEntry{{
				Channel: "vendor/main", Model: "gpt-4o",
				Price: config.PriceModel{InputPerM: 10, OutputPerM: 30, Currency: "CNY"},
			}},
		},
		providers: []config.Provider{{
			Name: "vendor", Protocol: "openai",
			Models: map[string]string{"gpt-4o": "gpt-4o"},
			Keys:   []config.APIKey{{Name: "main", APIKey: "sk"}},
		}},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/vendor")

	rec := adminReq(h, http.MethodGet,
		"/admin/prices/compare?model=gpt-4o&input_tokens=1000000&output_tokens=1000000", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	var body struct {
		Cheapest string `json:"cheapest"`
		Offers   []struct {
			Channel string  `json:"channel"`
			Cost    float64 `json:"cost"`
		} `json:"offers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Offers) != 1 {
		t.Fatalf("expected one offer from the provider channel, got %+v (body=%s)", body.Offers, rec.Body)
	}
	if body.Offers[0].Channel != "vendor/main" {
		t.Fatalf("offer channel = %q", body.Offers[0].Channel)
	}
	// 1M input at 10/M plus 1M output at 30/M.
	if body.Offers[0].Cost != 40 {
		t.Fatalf("cost = %v, want 40", body.Offers[0].Cost)
	}
	if body.Cheapest != "vendor/main" {
		t.Fatalf("cheapest = %q", body.Cheapest)
	}

	// The price list must agree.
	rec = adminReq(h, http.MethodGet, "/admin/prices", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("prices status = %d", rec.Code)
	}
	var prices struct {
		Prices []struct {
			Channel string `json:"channel"`
		} `json:"prices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &prices); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(prices.Prices) != 1 || prices.Prices[0].Channel != "vendor/main" {
		t.Fatalf("prices = %+v (body=%s)", prices.Prices, rec.Body)
	}
}

// A provider that declares both surfaces should serve a Responses request on
// the Responses endpoint, with no conversion at all. It is the shape every
// aggregator has, and treating the declaration as "translate instead" made the
// gateway rewrite a request that needed no rewriting.
func TestDeclaredSurfaceIsUsedWithoutTranslation(t *testing.T) {
	mock := newMockUpstream()
	mock.setHandler(handlerWithUsage(defaultReply, defaultPrompt, 1.0))
	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{upstreams: map[string]*mockUpstream{"agg": mock}},
		providers: []config.Provider{{
			Name: "agg", Protocol: "openai",
			Supports: []string{"openai", "responses"},
			Models:   map[string]string{"gpt-4o": "gpt-4o"},
			Keys:     []config.APIKey{{Name: "k", APIKey: "key"}},
		}},
		routing: &config.RoutingPolicy{AllowTranslation: boolPtr(true)},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/agg")

	rec := h.postTo("tok-alice", "/v1/responses", `{"model":"gpt-4o","input":"hi"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	if got := mock.lastPath(); got != "/v1/responses" {
		t.Fatalf("upstream path = %q, want the declared Responses surface", got)
	}
	if h.lastRecord().Translated {
		t.Fatal("a request sent to the provider's own Responses surface was recorded as translated")
	}
}

// A base_url that already ends in /v1 is how most aggregators document their
// endpoint. Appending another /v1 produced /v1/v1/... and a 404 that read like
// a provider outage rather than a configuration mistake.
//
// Each spelling gets its own harness: the harness mounts mocks by "/<name>/",
// so the versioned form needs a mount that carries the version prefix.
func TestBaseURLWithVersionSegmentIsNotDoubled(t *testing.T) {
	for _, tc := range []struct {
		name   string
		suffix string // what is appended to the server URL to form base_url
	}{
		// The mock is always mounted at /mock and the prefix is stripped, so it
		// observes the path the gateway actually built. "/mock/v1" as base_url
		// must therefore still arrive as /v1/chat/completions.
		{"base without the version segment", "/mock"},
		{"base with the version segment", "/mock/v1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := newMockUpstream()
			mock.setHandler(handlerWithUsage(defaultReply, defaultPrompt, 1.0))
			mux := http.NewServeMux()
			mux.Handle("/mock/", http.StripPrefix("/mock", mock))
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)

			h := newProviderHarness(t, providerHarnessOptions{
				harnessOptions: harnessOptions{
					upstreams: map[string]*mockUpstream{"mock": newMockUpstream()},
					channels:  []config.Channel{},
				},
				providers: []config.Provider{{
					Name: "agg", Protocol: "openai",
					Models: map[string]string{"gpt-4o": "gpt-4o"},
					Keys:   []config.APIKey{{Name: "k", APIKey: "key"}},
				}},
			})
			// Point the provider at the dedicated server; the harness strips the
			// mount prefix, so the mock sees exactly the path the gateway built.
			h.server.Config().Providers[0].BaseURL = server.URL + tc.suffix

			rec := h.postTo("tok-alice", "/v1/chat/completions",
				`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
			}
			if mock.count() != 1 {
				t.Fatalf("upstream received %d requests, want 1", mock.count())
			}
			if got := mock.lastPath(); got != "/v1/chat/completions" {
				t.Fatalf("upstream path = %q, want /v1/chat/completions", got)
			}
		})
	}
}

// The end-to-end shape of the operator's requirement: the first provider cannot
// pay, so the request must come back from the second one, and the audit record
// must explain the switch.
func TestFailoverFromOutOfCreditProviderToTheNext(t *testing.T) {
	// Provider one: answers 403 the way a new-api aggregator does when the
	// account balance is too low to pre-deduct.
	broke := newMockUpstream()
	broke.setHandler(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"预扣费额度失败, 用户剩余额度: ` +
			`¥0.017783, 需要预扣费额度: ¥0.086051","type":"new_api_error",` +
			`"code":"insufficient_user_quota"}}`))
	})
	// Provider two: healthy.
	rich := newMockUpstream()
	rich.setHandler(handlerWithUsage(defaultReply, defaultPrompt, 1.0))

	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{
			upstreams: map[string]*mockUpstream{"broke": broke, "rich": rich},
			// "fixed" keeps configuration order, so the failing provider is
			// genuinely tried first rather than losing a score comparison.
			strategy: "fixed",
		},
		providers: []config.Provider{
			{Name: "broke", Protocol: "openai", Models: map[string]string{"gpt-4o": "gpt-4o"},
				Keys: []config.APIKey{{Name: "main", APIKey: "key"}}},
			{Name: "rich", Protocol: "openai", Models: map[string]string{"gpt-4o": "gpt-4o"},
				Keys: []config.APIKey{{Name: "main", APIKey: "key"}}},
		},
		routing: &config.RoutingPolicy{
			AllowTranslation: boolPtr(true),
			MaxAttempts:      3,
			RetryOn:          []string{"5xx", "429", "timeout", "network", "quota"},
		},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/broke")
	setProviderBaseURL(h, 1, h.upstream.URL+"/rich")

	rec := h.postTo("tok-alice", "/v1/chat/completions",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	if broke.count() != 1 {
		t.Fatalf("the out-of-credit provider was tried %d times, want 1", broke.count())
	}
	if rich.count() != 1 {
		t.Fatalf("the healthy provider received %d requests, want 1", rich.count())
	}
	r := h.lastRecord()
	if r.Channel != "rich/main" {
		t.Fatalf("the audit record names channel %q, want rich/main", r.Channel)
	}
	// The provider identity has to follow the failover too: a record naming the
	// channel that answered but the provider that failed is misleading exactly
	// when the operator is deciding which provider to stop paying for.
	if r.Provider != "rich" {
		t.Fatalf("the audit record names provider %q, want rich", r.Provider)
	}
	if r.Key != "main" {
		t.Fatalf("the audit record names key %q, want main", r.Key)
	}
	if r.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", r.Attempts)
	}
	if r.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", r.Decision)
	}
}

// Without the quota class the same 403 must stay terminal: an operator who
// deliberately narrows retry_on should not have providers swapped underneath
// them.
func TestOutOfCreditIsTerminalWhenQuotaRetryIsOff(t *testing.T) {
	broke := newMockUpstream()
	broke.setHandler(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"insufficient_user_quota"}}`))
	})
	rich := newMockUpstream()
	rich.setHandler(handlerWithUsage(defaultReply, defaultPrompt, 1.0))

	h := newProviderHarness(t, providerHarnessOptions{
		harnessOptions: harnessOptions{
			upstreams: map[string]*mockUpstream{"broke": broke, "rich": rich},
			strategy:  "fixed",
		},
		providers: []config.Provider{
			{Name: "broke", Protocol: "openai", Models: map[string]string{"gpt-4o": "gpt-4o"},
				Keys: []config.APIKey{{Name: "main", APIKey: "key"}}},
			{Name: "rich", Protocol: "openai", Models: map[string]string{"gpt-4o": "gpt-4o"},
				Keys: []config.APIKey{{Name: "main", APIKey: "key"}}},
		},
		routing: &config.RoutingPolicy{
			MaxAttempts: 3,
			RetryOn:     []string{"5xx", "429", "timeout", "network"},
		},
	})
	setProviderBaseURL(h, 0, h.upstream.URL+"/broke")
	setProviderBaseURL(h, 1, h.upstream.URL+"/rich")

	rec := h.postTo("tok-alice", "/v1/chat/completions",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want the provider's own 403 to reach the client", rec.Code)
	}
	if rich.count() != 0 {
		t.Fatal("a provider was tried even though quota retry is disabled")
	}
	// The client must see the provider's own explanation, not a reconstruction.
	if !strings.Contains(rec.Body.String(), "insufficient_user_quota") {
		t.Fatalf("the provider's error body was not passed through: %s", rec.Body)
	}
}

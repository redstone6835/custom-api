package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The management API can suspend users and read the audit ledger, so its
// reachability policy is security-relevant and deserves direct tests rather
// than being taken on trust from the listener's bind address.

func TestAdminAllowsLoopbackWithoutAToken(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.RemoteAddr = "127.0.0.1:51234"
	h.server.AdminHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback caller refused: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAdminRefusesRemoteCallersByDefault(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.RemoteAddr = "10.10.1.50:41000"
	h.server.AdminHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("remote caller accepted by default: %d %s", rec.Code, rec.Body.String())
	}
}

// X-Forwarded-For is caller-supplied. If the access check honoured it, anyone
// could claim to be the loopback interface and reach the management API.
func TestAdminIgnoresSpoofedForwardedFor(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.RemoteAddr = "10.10.1.50:41000"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	h.server.AdminHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a spoofed X-Forwarded-For was trusted: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAdminRemoteRequiresTheConfiguredToken(t *testing.T) {
	cases := []struct {
		name    string
		token   string // configured
		present string // supplied
		want    int
	}{
		// 401 rather than 403 tells the console that a credential would help.
		{"no credential", "s3cret", "", http.StatusUnauthorized},
		{"wrong credential", "s3cret", "nope", http.StatusUnauthorized},
		{"right credential", "s3cret", "s3cret", http.StatusOK},
		// An unset token is a misconfiguration, not an invitation: an empty
		// credential must never match it.
		{"unset token, empty credential", "", "", http.StatusUnauthorized},
		{"unset token, any credential", "", "anything", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{})
			h.server.Config().Server.AdminRemote = true
			h.server.Config().Server.AdminToken = tc.token

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
			req.RemoteAddr = "10.10.1.50:41000"
			if tc.present != "" {
				req.Header.Set("Authorization", "Bearer "+tc.present)
			}
			h.server.AdminHandler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// The console's own files must stay reachable, or a remote operator could never
// load the page that asks for the credential. Only the API is gated.
func TestAdminGateLetsTheConsoleLoadButNotItsData(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	// The shell loads...
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.10.1.50:41000"
	h.server.AdminHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the console shell was refused to a remote caller: %d", rec.Code)
	}

	// ...but every API call behind it is refused, so the page has no data and
	// its credential prompt is what the operator sees.
	for _, path := range []string{"/admin", "/admin/", "/admin/stats", "/admin/users", "/admin/audit"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "10.10.1.50:41000"
		h.server.AdminHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s answered a remote caller: %d", path, rec.Code)
		}
	}
}

// With remote access enabled the shell still loads and the API answers 401, so
// the console can tell "enter a token" apart from "remote access is off".
func TestAdminGateShellLoadsWhenRemoteAccessIsOn(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.server.Config().Server.AdminRemote = true
	h.server.Config().Server.AdminToken = "s3cret"

	for _, path := range []string{"/", "/ui/", "/assets/index.js"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "10.10.1.50:41000"
		h.server.AdminHandler().ServeHTTP(rec, req)
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("%s was gated: %d", path, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.RemoteAddr = "10.10.1.50:41000"
	h.server.AdminHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API call = %d, want 401", rec.Code)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080": true,
		"127.0.0.5:1":    true,
		"[::1]:8080":     true,
		"localhost:80":   true,
		"10.10.1.5:80":   false,
		"[fe80::1]:80":   false,
		"127.0.0.1":      true,
		"":               false,
		"garbage":        false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Provider-side failure classification
// ---------------------------------------------------------------------------

// A provider whose account cannot pay answers 403 with an explanation. That is
// not a client error: the request is fine and another provider can serve it, so
// it must be retryable or a multi-provider deployment gains nothing.
func TestProviderOutOfCreditIsRecognised(t *testing.T) {
	// Verbatim shape from a new-api based aggregator, which is what the
	// deployment targets.
	naapi := []byte(`{"error":{"message":"预扣费额度失败, 用户剩余额度: ¥0.017783, ` +
		`需要预扣费额度: ¥0.086051 (request id: 202609221153595165019158268d9d6CNSAIOeM)",` +
		`"type":"new_api_error","param":"","code":"insufficient_user_quota"}}`)
	openai := []byte(`{"error":{"message":"You exceeded your current quota, please check your plan and billing details.","type":"insufficient_quota","code":"insufficient_quota"}}`)
	english := []byte(`{"error":{"message":"Insufficient balance","type":"invalid_request_error"}}`)

	for name, body := range map[string][]byte{
		"new-api insufficient_user_quota": naapi,
		"openai insufficient_quota":       openai,
		"insufficient balance":            english,
	} {
		if !providerOutOfCredit(body) {
			t.Errorf("%s: not recognised as a credit failure", name)
		}
	}

	// A bare 403 or an unrelated error must NOT be treated as a credit problem:
	// retrying a banned key on every provider multiplies failures.
	for name, body := range map[string][]byte{
		"empty":             nil,
		"bad key":           []byte(`{"error":{"message":"Invalid token","code":"invalid_api_key"}}`),
		"model not allowed": []byte(`{"error":{"message":"This model is not available in your region","code":"model_not_found"}}`),
		"rate limited":      []byte(`{"error":{"message":"Too many requests","code":"rate_limit_exceeded"}}`),
	} {
		if providerOutOfCredit(body) {
			t.Errorf("%s: wrongly treated as a credit failure", name)
		}
	}
}

func TestFailureClassTreatsCreditAsRetryable(t *testing.T) {
	quota := []byte(`{"error":{"code":"insufficient_user_quota"}}`)
	if got := failureClass(403, nil, quota); got != "quota" {
		t.Fatalf("403 with a credit body = %q, want quota", got)
	}
	if got := failureClass(403, nil, []byte(`{"error":{"code":"invalid_api_key"}}`)); got != "" {
		t.Fatalf("403 with an auth body = %q, want terminal", got)
	}
	if got := failureClass(403, nil, nil); got != "" {
		t.Fatalf("bare 403 = %q, want terminal", got)
	}
	if got := failureClass(402, nil, quota); got != "quota" {
		t.Fatalf("402 with a credit body = %q, want quota", got)
	}
	if got := failureClass(429, nil, nil); got != "429" {
		t.Fatalf("429 = %q, want 429", got)
	}
	if got := failureClass(503, nil, nil); got != "5xx" {
		t.Fatalf("503 = %q, want 5xx", got)
	}
}

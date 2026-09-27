// Package gateway implements the customs proxy: the single insertion point
// between the user-facing gateway (new-api) and the upstream access points.
//
// Responsibilities, matching the project plan's sections A, B and C:
//
//	A outbound - inspect the user's request, detect abuse, intercept dangerous
//	             tool calls, redact secrets before persisting evidence.
//	B inbound  - verify the upstream's reported usage, fingerprint the model
//	             that actually answered, detect prompt injection and leaked
//	             credentials, and withhold a response that fails policy.
//	C metering - recount tokens locally, price the exchange, and write an
//	             independent, tamper-evident audit record for every request.
package gateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/config"
	"github.com/redstone/customapi/internal/discovery"
	"github.com/redstone/customapi/internal/meter"
	"github.com/redstone/customapi/internal/policy"
	"github.com/redstone/customapi/internal/route"
	"github.com/redstone/customapi/internal/store"
	"github.com/redstone/customapi/internal/version"
)

// Server is the customs gateway.
//
// All mutable fields are guarded: the configuration can be reloaded while
// requests are in flight, and counters are updated from many goroutines.
type Server struct {
	mu  sync.RWMutex
	cfg *config.Config
	// base is the configuration directory, used to resolve relative paths.
	base string

	engine   *policy.Engine
	redactor *policy.Redactor
	pricer   *meter.Pricer
	selector *route.Selector
	scores   *route.MapScoreBook
	health   *route.HealthTracker
	store    *store.Manager
	ledger   *audit.Writer
	// catalogue is the discovered and configured model catalogue. It is a view
	// only: routing never consults it, so a discovery outage cannot take models
	// out of service.
	catalogue *discovery.Service
	// discoveryCancel stops the background discovery loop.
	discoveryCancel context.CancelFunc
	log             *slog.Logger

	client *http.Client

	// rate limiting state per user
	limiters sync.Map // name -> *limiter

	// running counters, exposed on /healthz and the admin API
	stats Stats

	// startedAt is process start time.
	startedAt time.Time
	// ready is closed once the server is serving.
	ready chan struct{}
}

// Stats are live counters.
type Stats struct {
	Requests        atomic.Int64
	BlockedOutbound atomic.Int64
	BlockedInbound  atomic.Int64
	UpstreamErrors  atomic.Int64
	StreamedReqs    atomic.Int64
	OverBilled      atomic.Int64
	FingerprintMiss atomic.Int64
	Degraded        atomic.Int64
	BytesIn         atomic.Int64
	BytesOut        atomic.Int64
}

// Snapshot renders the counters for reporting.
func (s *Stats) Snapshot() map[string]int64 {
	return map[string]int64{
		"requests":          s.Requests.Load(),
		"blocked_outbound":  s.BlockedOutbound.Load(),
		"blocked_inbound":   s.BlockedInbound.Load(),
		"upstream_errors":   s.UpstreamErrors.Load(),
		"streamed_requests": s.StreamedReqs.Load(),
		"over_billed":       s.OverBilled.Load(),
		"fingerprint_miss":  s.FingerprintMiss.Load(),
		"degraded":          s.Degraded.Load(),
		"bytes_in":          s.BytesIn.Load(),
		"bytes_out":         s.BytesOut.Load(),
	}
}

// Options configures a Server.
type Options struct {
	// Config is the loaded configuration.
	Config *config.Config
	// BaseDir resolves relative paths in the configuration.
	BaseDir string
	// Logger receives structured logs.
	Logger *slog.Logger
	// Scores seeds the routing scorebook.
	Scores map[string]map[string]route.Scores
	// Client overrides the upstream HTTP client (used by tests).
	Client *http.Client
}

// New builds a gateway server, opening the audit ledger and restoring quota
// state.
func New(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("gateway: config is required")
	}
	cfg := opts.Config
	base := opts.BaseDir
	if base == "" {
		base = "."
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	engine, err := policy.New(policy.Options{
		Policy:   cfg.Policy,
		FailMode: cfg.Server.FailMode,
	})
	if err != nil {
		return nil, err
	}
	redactor, err := policy.NewRedactor(cfg.Policy.Outbound.RedactPatterns)
	if err != nil {
		return nil, err
	}

	tz := time.Local
	pricer := meter.NewPricer(cfg.Prices, tz)
	scores := route.NewMapScoreBook(opts.Scores)

	ledgerPath := config.Resolve(base, cfg.Server.AuditPath)
	ledger, err := audit.Open(audit.WriterOptions{Path: ledgerPath, Sync: false})
	if err != nil {
		return nil, err
	}

	st := store.NewManager(cfg.Users, config.Resolve(base, cfg.Server.StatePath))
	if err := st.Load(); err != nil {
		ledger.Close()
		return nil, err
	}
	st.SetOnChange(func() {
		if err := st.Save(); err != nil {
			log.Error("state save failed", "err", err)
		}
	})

	client := opts.Client
	if client == nil {
		client = newUpstreamClient(cfg.Server.UpstreamTimeout.D())
	}

	catalogue := discovery.New(discovery.Options{
		Policy: cfg.Discovery,
		Logger: log,
	})

	s := &Server{
		cfg:       cfg,
		base:      base,
		engine:    engine,
		redactor:  redactor,
		pricer:    pricer,
		scores:    scores,
		selector:  route.New(route.Options{Pricer: pricer, Scores: scores, Strategy: cfg.Server.RouteStrategy}),
		health:    route.NewHealthTracker(3, 20*time.Second),
		store:     st,
		ledger:    ledger,
		catalogue: catalogue,
		log:       log,
		client:    client,
		startedAt: time.Now(),
		ready:     make(chan struct{}),
	}
	// Seed the catalogue with the configured models immediately.
	//
	// Discovery is asynchronous and may never succeed (an unreachable upstream
	// is a normal state), but a model the operator declared is servable
	// regardless. Seeding here means the catalogue is never empty while waiting
	// for a network round trip.
	catalogue.SetConfigured(cfg.AllChannels())
	return s, nil
}

// newUpstreamClient builds an HTTP client tuned for proxying LLM traffic.
func newUpstreamClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// LLM responses are streamed; disabling compression avoids having to
		// decompress just to audit, and keeps byte accounting honest.
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   0, // per-request context carries the deadline
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// RefreshChannels re-seeds the catalogue from the current channel list.
//
// It exists for the admin "refresh models" path and for tests that mutate the
// provider set after construction. Routing reads the configuration directly, so
// only the catalogue needs refreshing.
func (s *Server) RefreshChannels() {
	s.catalogue.SetConfigured(s.Config().AllChannels())
}

// Config returns the active configuration.
func (s *Server) Config() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Store exposes the quota manager.
func (s *Server) Store() *store.Manager { return s.store }

// Ledger exposes the audit writer.
func (s *Server) Ledger() *audit.Writer { return s.ledger }

// StatsSnapshot exposes the counters.
func (s *Server) StatsSnapshot() map[string]int64 { return s.stats.Snapshot() }

// Uptime returns how long the process has been running.
func (s *Server) Uptime() time.Duration { return time.Since(s.startedAt) }

// Close releases resources.
func (s *Server) Close() error {
	if s.discoveryCancel != nil {
		s.discoveryCancel()
	}
	if err := s.store.Save(); err != nil {
		s.log.Error("final state save failed", "err", err)
	}
	return s.ledger.Close()
}

// Catalogue exposes the model catalogue.
func (s *Server) Catalogue() *discovery.Service { return s.catalogue }

// StartDiscovery begins background model discovery.
//
// It is separate from New so that a caller can decide when discovery runs: the
// market data it gathers is useful for the UI, but a gateway must be able to
// serve traffic whether or not an upstream is reachable.
func (s *Server) StartDiscovery(ctx context.Context) {
	cfg := s.Config()
	if err := s.catalogue.Load(); err != nil {
		s.log.Warn("discovery cache load failed", "err", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	s.discoveryCancel = cancel
	go s.catalogue.Run(ctx, cfg, cfg.Discovery.IntervalD())
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

// Handler returns the user-facing HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/v1/models", s.handleModels)
	mux.HandleFunc("/v1/customs/usage", s.handleMyUsage)
	mux.HandleFunc("/v1/customs/prices", s.handlePriceCompare)
	// The proxy endpoints. Any other /v1 path is forwarded verbatim so that
	// endpoints the gateway does not model (embeddings, images, audio) still
	// work, just with less inspection.
	mux.HandleFunc("/v1/chat/completions", s.handleProxy)
	mux.HandleFunc("/v1/completions", s.handleProxy)
	mux.HandleFunc("/v1/messages", s.handleProxy)
	// The Responses API is served natively, not aliased to chat completions:
	// it has its own request, response and streaming event shapes.
	mux.HandleFunc("/v1/responses", s.handleProxy)
	mux.HandleFunc("/v1/", s.handleProxy)
	mux.HandleFunc("/", s.handleRoot)
	return s.withRecovery(s.withAccessLog(mux))
}

// AdminHandler returns the management API handler.
//
// Reachability is deliberately narrow. The handler refuses non-loopback callers
// unless the operator opts in with server.admin_remote, because the management
// API can suspend users, read the audit ledger and rewrite the price catalogue.
// Loopback callers are trusted without a token: anything that can reach the
// loopback interface already runs on this host. When admin_remote is on, every
// non-loopback caller must present server.admin_token as a bearer credential.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/healthz", s.handleHealth)
	mux.HandleFunc("/admin/version", s.handleVersion)
	mux.HandleFunc("/admin/stats", s.handleStats)
	mux.HandleFunc("/admin/config", s.handleConfigSummary)
	mux.HandleFunc("/admin/users", s.handleUsers)
	mux.HandleFunc("/admin/users/", s.handleUserAction)
	mux.HandleFunc("/admin/channels", s.handleChannels)
	mux.HandleFunc("/admin/audit", s.handleAudit)
	mux.HandleFunc("/admin/audit/verify", s.handleAuditVerify)
	mux.HandleFunc("/admin/usage", s.handleUsage)
	mux.HandleFunc("/admin/prices", s.handlePrices)
	mux.HandleFunc("/admin/prices/compare", s.handlePriceCompare)
	mux.HandleFunc("/admin/scores", s.handleScores)
	mux.HandleFunc("/admin/fingerprints", s.handleFingerprints)
	mux.HandleFunc("/admin/providers", s.handleProviders)
	mux.HandleFunc("/admin/models", s.handleAdminModels)
	mux.HandleFunc("/admin/models/refresh", s.handleModelsRefresh)
	mux.HandleFunc("/admin/", s.handleAdminIndex)

	// The UI is mounted last so that every API route above wins. Its own
	// handler falls back to index.html for unknown paths, which is what makes
	// client-side routing survive a refresh on a deep link.
	mux.Handle("/ui/", http.StripPrefix("/ui/", s.spaHandler()))
	mux.Handle("/", s.spaHandler())
	return s.withRecovery(s.withAccessLog(s.withAdminAccess(mux)))
}

// withAdminAccess enforces the management listener's reachability policy.
//
// Only the API is gated, not the console's own files. Gating those too looks
// tidier but does not work: the browser would be refused the page whose job is
// to ask for the credential, so a remote operator could never authenticate.
// The shell is a static bundle containing no configuration, no credentials and
// no data; every byte of actual content comes from /admin/*, which is gated.
func (s *Server) withAdminAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// The prefix is checked without its trailing slash so that a bare
		// /admin cannot be used to probe for the API's existence.
		case !strings.HasPrefix(r.URL.Path, "/admin"),
			s.adminAllowed(r):
			next.ServeHTTP(w, r)
			return
		}
		s.log.Warn("admin access refused", "remote", r.RemoteAddr, "path", r.URL.Path)
		if !s.Config().Server.AdminRemote {
			writeJSONError(w, http.StatusForbidden, "admin_forbidden",
				"the management API only answers the loopback interface; "+
					"set server.admin_remote and server.admin_token to allow remote callers")
			return
		}
		// Remote access is enabled, so the caller is simply not (or not
		// correctly) authenticated. The distinction matters to the console: it
		// asks for a credential on admin_unauthorized, whereas admin_forbidden
		// means no credential can help.
		w.Header().Set("WWW-Authenticate", `Bearer realm="customapi-admin"`)
		writeJSONError(w, http.StatusUnauthorized, "admin_unauthorized",
			"the management API requires the server.admin_token credential")
	})
}

// adminAllowed reports whether a request may reach the management API.
//
// It deliberately inspects r.RemoteAddr rather than clientIP(): clientIP honours
// X-Forwarded-For, which is caller-supplied, so trusting it here would let
// anyone claim to be 127.0.0.1 and walk straight into the management API.
func (s *Server) adminAllowed(r *http.Request) bool {
	if isLoopbackAddr(r.RemoteAddr) {
		return true
	}
	cfg := s.Config()
	if !cfg.Server.AdminRemote {
		return false
	}
	// A remote caller must authenticate. An empty configured token is a
	// misconfiguration rather than an invitation, so it denies instead of
	// matching an empty credential.
	want := cfg.Server.AdminToken
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(bearerToken(r)), []byte(want)) == 1
}

// isLoopbackAddr reports whether a "host:port" peer address is the loopback
// interface.
func isLoopbackAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeJSONError(w, http.StatusNotFound, "not_found", "unknown endpoint "+r.URL.Path)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service": "customapi-customs",
		"version": version.String(),
		"endpoints": []string{
			"/healthz", "/readyz", "/v1/models",
			"/v1/chat/completions", "/v1/completions", "/v1/responses", "/v1/messages",
		},
	})
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic in handler", "path", r.URL.Path, "panic", rec)
				writeJSONError(w, http.StatusInternalServerError, "internal_error", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Flush forwards to the underlying writer so streaming still works when the
// access log wraps the handler.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		// Health checks are noisy; log them only at debug level.
		level := slog.LevelInfo
		if strings.HasSuffix(r.URL.Path, "healthz") || strings.HasSuffix(r.URL.Path, "readyz") {
			level = slog.LevelDebug
		}
		s.log.Log(r.Context(), level, "http",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"bytes", rec.bytes, "dur_ms", time.Since(start).Milliseconds())
	})
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":         "ok",
		"version":        version.Version,
		"uptime_s":       int64(s.Uptime().Seconds()),
		"channels":       len(cfg.AllChannels()),
		"users":          len(cfg.Users),
		"outbound_rules": s.engine.OutboundRuleCount(),
		"inbound_rules":  s.engine.InboundRuleCount(),
		"fail_mode":      s.engine.FailMode(),
		"audit_seq":      s.ledger.Seq(),
		"stats":          s.stats.Snapshot(),
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	select {
	case <-s.ready:
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	default:
		writeJSONError(w, http.StatusServiceUnavailable, "not_ready", "still starting")
	}
}

// MarkReady signals that the server is serving.
func (s *Server) MarkReady() {
	select {
	case <-s.ready:
	default:
		close(s.ready)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writeJSONError emits an OpenAI-compatible error envelope so that any client
// library understands a gateway rejection.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    code,
			"code":    code,
		},
	})
}

// writeAuditError emits an error envelope that also carries the audit id, so a
// user can quote it and an operator can find the evidence.
func writeAuditError(w http.ResponseWriter, status int, code, message, recordID string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Customs-Audit-Id", recordID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    code,
			"code":    code,
		},
		"customs_audit_id": recordID,
	})
}

// bearerToken extracts the caller credential, accepting both the OpenAI
// Authorization header and the Anthropic x-api-key header.
func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if v, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(h, "bearer "); ok {
			return strings.TrimSpace(v)
		}
	}
	if k := r.Header.Get("x-api-key"); k != "" {
		return strings.TrimSpace(k)
	}
	if k := r.Header.Get("api-key"); k != "" {
		return strings.TrimSpace(k)
	}
	return ""
}

// clientIP extracts the best-effort caller address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// auditPath returns the configured ledger path.
func (s *Server) auditPath() string {
	return config.Resolve(s.base, s.Config().Server.AuditPath)
}

// anchorPath returns the anchor file beside the ledger.
func (s *Server) anchorPath() string {
	p := s.auditPath()
	return filepath.Join(filepath.Dir(p), "anchor.jsonl")
}

// contextWithDeadline attaches the configured upstream timeout.
func (s *Server) contextWithDeadline(r *http.Request) (context.Context, context.CancelFunc) {
	d := s.Config().Server.UpstreamTimeout.D()
	if d <= 0 {
		d = 120 * time.Second
	}
	return context.WithTimeout(r.Context(), d)
}

// sanitizeHeaderValue strips characters that would break header framing.
func sanitizeHeaderValue(v string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, v)
}

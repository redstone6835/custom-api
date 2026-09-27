package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/meter"
	"github.com/redstone/customapi/internal/route"
	"github.com/redstone/customapi/internal/store"
	"github.com/redstone/customapi/internal/version"
)

// ---------------------------------------------------------------------------
// User-facing: model catalogue with live pricing
// ---------------------------------------------------------------------------

// handleModels serves the model catalogue.
//
// It is OpenAI-shaped (`{"object":"list","data":[...]}`) so any client library
// can enumerate models, with customs extensions attached under "customs" for
// clients that understand them. The catalogue is built from the providers'
// declared models plus whatever discovery found, so a model appears here only
// if some channel can actually serve it.
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	user, ok := s.Config().UserByToken(token)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid_api_key",
			"the provided API key is not valid for this gateway")
		return
	}

	// A user restricted to a set of models sees only those, so the catalogue
	// never advertises something the caller would be refused.
	var allow func(string) bool
	if len(user.Models) > 0 {
		allow = user.AllowsModel
	}
	views := s.catalogue.Models(allow)

	// Serve a plain list by default; include the routing detail only when the
	// caller asks, because the extra keys confuse some strict clients.
	verbose := r.URL.Query().Get("detail") == "true"

	type modelEntry struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		OwnedBy string `json:"owned_by"`
		Customs any    `json:"customs,omitempty"`
	}
	out := make([]modelEntry, 0, len(views))
	for _, v := range views {
		s.priceForModel(v.Model, &v)
		entry := modelEntry{ID: v.Model, Object: "model", OwnedBy: "customapi-customs"}
		if verbose {
			entry.Customs = map[string]any{
				"channels":   v.Channels,
				"protocols":  v.Protocols,
				"configured": v.Configured,
				"cheapest":   v.Cheapest,
				"unit_price": v.UnitPrice,
				"currency":   v.Currency,
			}
		} else {
			entry.Customs = map[string]any{
				"channels":  len(v.Channels),
				"protocols": v.Protocols,
			}
		}
		out = append(out, entry)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": out})
}

// handleMyUsage reports the caller's own quota and usage.
func (s *Server) handleMyUsage(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	user, ok := s.Config().UserByToken(token)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "invalid_api_key", "invalid API key")
		return
	}
	st, _ := s.store.Get(user.Name)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user":              st.Name,
		"quota":             st.Quota,
		"consumed":          st.Consumed,
		"remaining":         st.Remaining(),
		"unlimited":         st.Quota <= 0,
		"period":            st.Period,
		"period_start":      st.PeriodStart,
		"requests":          st.Requests,
		"spend":             st.Spend,
		"currency":          st.Currency,
		"lifetime_consumed": st.LifetimeConsumed,
		"last_seen":         st.LastSeen,
	})
}

// ---------------------------------------------------------------------------
// Admin: identity, stats, config
// ---------------------------------------------------------------------------

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version": version.String(),
		"commit":  version.Commit,
		"built":   version.BuildTime,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"uptime_s":      int64(s.Uptime().Seconds()),
		"stats":         s.stats.Snapshot(),
		"channels":      len(cfg.AllChannels()),
		"users":         len(cfg.Users),
		"audit_seq":     s.ledger.Seq(),
		"audit_head":    s.ledger.Head(),
		"audit_path":    s.auditPath(),
		"strategy":      s.selector.Strategy(),
		"outbound_mode": s.engine.OutboundMode(),
		"inbound_mode":  s.engine.InboundMode(),
		"fail_mode":     s.engine.FailMode(),
	})
}

func (s *Server) handleConfigSummary(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	type chanView struct {
		Name     string   `json:"name"`
		BaseURL  string   `json:"base_url"`
		Protocol string   `json:"protocol"`
		Trust    string   `json:"trust"`
		Enabled  bool     `json:"enabled"`
		Weight   float64  `json:"weight"`
		HasKey   bool     `json:"has_key"`
		Models   []string `json:"models,omitempty"`
	}
	all := cfg.AllChannels()
	chans := make([]chanView, 0, len(all))
	for _, ch := range all {
		var models []string
		for k := range ch.Models {
			models = append(models, k)
		}
		sort.Strings(models)
		chans = append(chans, chanView{
			Name: ch.Name, BaseURL: ch.BaseURL, Protocol: ch.Protocol,
			Trust: string(ch.TrustLevel()), Enabled: ch.IsEnabled(), Weight: ch.Weight,
			HasKey: ch.APIKey != "", Models: models,
		})
	}
	// Secrets are never echoed; only their presence is reported.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"server": map[string]any{
			"listen":           cfg.Server.Listen,
			"admin_listen":     cfg.Server.AdminListen,
			"route_strategy":   cfg.Server.RouteStrategy,
			"fail_mode":        cfg.Server.FailMode,
			"upstream_timeout": cfg.Server.UpstreamTimeout.D().String(),
		},
		"policy": map[string]any{
			"outbound_mode":  cfg.Policy.Outbound.Mode,
			"inbound_mode":   cfg.Policy.Inbound.Mode,
			"tool_policy":    cfg.Policy.Inbound.ToolCallPolicy,
			"tolerance":      cfg.Policy.Metering.Tolerance,
			"outbound_rules": s.engine.OutboundRuleCount(),
			"inbound_rules":  s.engine.InboundRuleCount(),
		},
		"channels": chans,
	})
}

func (s *Server) handleChannels(w http.ResponseWriter, r *http.Request) {
	s.handleConfigSummary(w, r)
}

// ---------------------------------------------------------------------------
// Admin: users and quota
// ---------------------------------------------------------------------------

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users := s.store.List()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"users": users, "count": len(users)})
	case http.MethodPost:
		s.handleUserAction(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
	}
}

// userActionRequest is the body accepted by the user management endpoint.
type userActionRequest struct {
	// User names the subject.
	User string `json:"user"`
	// Action is one of: grant, set_quota, add_quota, suspend, resume,
	// set_period.
	Action string `json:"action"`
	// Quota is the target allowance for grant/set_quota/add_quota.
	Quota int64 `json:"quota"`
	// Period is the reset schedule for set_period.
	Period string `json:"period"`
}

func (s *Server) handleUserAction(w http.ResponseWriter, r *http.Request) {
	var req userActionRequest

	// Accept both POST /admin/users with a body and
	// POST /admin/users/<name> with a body.
	if name := strings.TrimPrefix(r.URL.Path, "/admin/users/"); name != "" && name != r.URL.Path {
		req.User = name
	}
	if r.Method == http.MethodPost && r.Body != nil {
		var body userActionRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err.Error() != "EOF" {
			writeJSONError(w, http.StatusBadRequest, "invalid_body", "could not parse request body")
			return
		}
		if body.User != "" {
			req.User = body.User
		}
		if body.Action != "" {
			req.Action = body.Action
		}
		req.Quota = body.Quota
		if body.Period != "" {
			req.Period = body.Period
		}
	}
	if req.User == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_user", "user is required")
		return
	}
	if req.Action == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_action", "action is required")
		return
	}

	var (
		st  store.UserState
		err error
	)
	switch req.Action {
	case "grant", "set_quota":
		st, err = s.store.SetQuota(req.User, req.Quota)
	case "add_quota":
		st, err = s.store.AddQuota(req.User, req.Quota)
	case "suspend":
		st, err = s.store.SetEnabled(req.User, false)
	case "resume":
		st, err = s.store.SetEnabled(req.User, true)
	case "set_period":
		st, err = s.store.SetPeriod(req.User, req.Period)
	default:
		writeJSONError(w, http.StatusBadRequest, "unknown_action",
			fmt.Sprintf("action %q is not recognised", req.Action))
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "user_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "action": req.Action, "user": st})
}

// ---------------------------------------------------------------------------
// Admin: audit
// ---------------------------------------------------------------------------

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	records, err := audit.ReadAll(s.auditPath())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "audit_read_error", err.Error())
		return
	}
	filtered := filterRecords(records, q.Get("actor"), q.Get("channel"), q.Get("model"),
		q.Get("decision"), q.Get("verdict"))
	// Newest first, then paginate.
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].Seq > filtered[j].Seq })

	limit := intParam(q.Get("limit"), 100)
	if limit > 1000 {
		limit = 1000
	}
	offset := intParam(q.Get("offset"), 0)
	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := filtered[offset:end]

	// Strip samples unless explicitly asked for: an operator browsing the
	// list should not accidentally read user content.
	if q.Get("include_samples") != "true" {
		for i := range page {
			page[i].Sample = nil
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"records": page, "total": total, "limit": limit, "offset": offset,
	})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	res, err := audit.Verify(s.auditPath(), s.anchorPath())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "verify_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !res.OK {
		w.WriteHeader(http.StatusConflict)
	}
	_ = json.NewEncoder(w).Encode(res)
}

// filterRecords applies the query filters used by the audit browser.
func filterRecords(in []audit.Record, actor, channel, model, decision, verdict string) []audit.Record {
	if actor == "" && channel == "" && model == "" && decision == "" && verdict == "" {
		return in
	}
	out := make([]audit.Record, 0, len(in))
	for _, r := range in {
		if actor != "" && r.Actor != actor {
			continue
		}
		if channel != "" && r.Channel != channel {
			continue
		}
		if model != "" && r.Model != model {
			continue
		}
		if decision != "" && string(r.Decision) != decision {
			continue
		}
		if verdict != "" && r.Usage.Verdict != verdict {
			continue
		}
		out = append(out, r)
	}
	return out
}

// ---------------------------------------------------------------------------
// Admin: usage aggregates
// ---------------------------------------------------------------------------

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	records, err := audit.ReadAll(s.auditPath())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "audit_read_error", err.Error())
		return
	}
	records = filterRecords(records, r.URL.Query().Get("actor"), r.URL.Query().Get("channel"),
		r.URL.Query().Get("model"), "", "")
	models, channels := store.Aggregate(records)
	users := s.store.List()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"models": models, "channels": channels, "users": users, "records": len(records),
	})
}

// ---------------------------------------------------------------------------
// Admin: prices
// ---------------------------------------------------------------------------

func (s *Server) handlePrices(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	now := time.Now()
	type row struct {
		Channel string  `json:"channel"`
		Model   string  `json:"model"`
		Trust   string  `json:"trust"`
		Input   float64 `json:"input_per_m"`
		Output  float64 `json:"output_per_m"`
		Unit    float64 `json:"effective_unit_price"`
		Cur     string  `json:"currency"`
		Scheme  string  `json:"scheme,omitempty"`
		Source  string  `json:"source,omitempty"`
	}
	var rows []row
	for _, ch := range cfg.AllChannels() {
		for _, m := range s.pricer.Models(ch.Name) {
			pm, _ := s.pricer.Lookup(ch.Name, m)
			rows = append(rows, row{
				Channel: ch.Name, Model: m, Trust: string(ch.TrustLevel()),
				Input: pm.InputPerM, Output: pm.OutputPerM,
				Unit: meter.EffectiveUnitPrice(pm, meter.Tokens{}, now, time.Local),
				Cur:  pm.Currency, Scheme: pm.Scheme, Source: pm.Source,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Model != rows[j].Model {
			return rows[i].Model < rows[j].Model
		}
		return rows[i].Unit < rows[j].Unit
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"prices": rows})
}

// handlePriceCompare answers "what would this cost, and which channel is
// cheapest" for a concrete token mix - the comparison the plan wants users to
// be able to browse.
func (s *Server) handlePriceCompare(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	model := q.Get("model")
	in := int64(intParam(q.Get("input_tokens"), 1000))
	out := int64(intParam(q.Get("output_tokens"), 500))
	at := time.Now()
	if t := q.Get("at"); t != "" {
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			at = parsed
		}
	}
	tokens := meter.Tokens{Input: in, Output: out}

	type offer struct {
		Channel     string                   `json:"channel"`
		Currency    string                   `json:"currency"`
		Cost        float64                  `json:"cost"`
		ListCost    float64                  `json:"list_cost"`
		DiscountPct float64                  `json:"discount_pct"`
		UnitPrice   float64                  `json:"unit_price"`
		Promotions  []meter.AppliedPromotion `json:"promotions,omitempty"`
		Trust       string                   `json:"trust"`
	}
	var offers []offer
	cfg := s.Config()
	for _, ch := range cfg.AllChannels() {
		if !ch.IsEnabled() {
			continue
		}
		if model != "" && ch.UpstreamModel(model) == "" {
			continue
		}
		pm, ok := s.pricer.Lookup(ch.Name, model)
		if !ok {
			continue
		}
		quote := meter.PriceWith(pm, tokens, at, time.Local)
		unit := 0.0
		if tokens.Total() > 0 {
			unit = quote.Cost / (float64(tokens.Total()) / 1e6)
		}
		offers = append(offers, offer{
			Channel: ch.Name, Currency: quote.Currency, Cost: quote.Cost,
			ListCost: quote.ListCost, DiscountPct: quote.DiscountPct,
			UnitPrice: unit, Promotions: quote.Applied, Trust: string(ch.TrustLevel()),
		})
	}
	sort.Slice(offers, func(i, j int) bool { return offers[i].Cost < offers[j].Cost })

	resp := map[string]any{
		"model": model, "input_tokens": in, "output_tokens": out,
		"at": at.Format(time.RFC3339), "offers": offers,
	}
	if len(offers) > 0 {
		resp["cheapest"] = offers[0].Channel
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------------
// Admin: intelligence views
// ---------------------------------------------------------------------------

func (s *Server) handleScores(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	type row struct {
		Channel string       `json:"channel"`
		Model   string       `json:"model"`
		Scores  route.Scores `json:"scores"`
	}
	var rows []row
	for _, ch := range cfg.AllChannels() {
		models := map[string]bool{}
		for _, m := range s.pricer.Models(ch.Name) {
			models[m] = true
		}
		for m := range ch.Models {
			models[m] = true
		}
		for m := range models {
			if sc, ok := s.scores.Score(ch.Name, m); ok {
				rows = append(rows, row{Channel: ch.Name, Model: m, Scores: sc})
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Model != rows[j].Model {
			return rows[i].Model < rows[j].Model
		}
		return rows[i].Channel < rows[j].Channel
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"scores": rows})
}

// handleFingerprints reports the model-identity evidence collected from audit.
func (s *Server) handleFingerprints(w http.ResponseWriter, r *http.Request) {
	records, err := audit.ReadAll(s.auditPath())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "audit_read_error", err.Error())
		return
	}
	type agg struct {
		Channel   string  `json:"channel"`
		Model     string  `json:"model"`
		Checked   int64   `json:"checked"`
		Mismatch  int64   `json:"mismatch"`
		MeanScore float64 `json:"mean_score"`
	}
	idx := map[string]*agg{}
	for _, rec := range records {
		if !rec.Fingerprint.Checked {
			continue
		}
		k := rec.Channel + "\x00" + rec.Model
		a, ok := idx[k]
		if !ok {
			a = &agg{Channel: rec.Channel, Model: rec.Model}
			idx[k] = a
		}
		a.Checked++
		a.MeanScore += (rec.Fingerprint.Score - a.MeanScore) / float64(a.Checked)
		if rec.Fingerprint.Verdict == "mismatch" {
			a.Mismatch++
		}
	}
	out := make([]agg, 0, len(idx))
	for _, a := range idx {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Channel != out[j].Channel {
			return out[i].Channel < out[j].Channel
		}
		return out[i].Model < out[j].Model
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"fingerprints": out})
}

// handleAdminIndex renders a small service map.
func (s *Server) handleAdminIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service": "customapi-customs-admin",
		"endpoints": []string{
			"/admin/healthz", "/admin/version", "/admin/stats", "/admin/config",
			"/admin/users", "/admin/channels", "/admin/audit", "/admin/audit/verify",
			"/admin/usage", "/admin/prices", "/admin/prices/compare",
			"/admin/scores", "/admin/fingerprints",
		},
	})
}

func intParam(s string, def int) int {
	if s == "" {
		return def
	}
	var v int
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return def
	}
	return v
}

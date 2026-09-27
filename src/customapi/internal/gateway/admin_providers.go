package gateway

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/config"
	"github.com/redstone/customapi/internal/discovery"
	"github.com/redstone/customapi/internal/meter"
	"github.com/redstone/customapi/internal/protocol"
)

// ---------------------------------------------------------------------------
// Provider management
// ---------------------------------------------------------------------------

// providerView is one provider as the front end sees it.
type providerView struct {
	config.ProviderSummary
	// Channels are the expanded channels, one per enabled key.
	Channels []providerChannelView `json:"channels"`
	// Health is per-channel runtime state.
	Health []channelHealth `json:"health,omitempty"`
	// ModelList is every model this provider can serve, from the catalogue.
	//
	// It is a list rather than a count because the front end needs the names;
	// the embedded ProviderSummary keeps the count under "models" for callers
	// that only want the number.
	ModelList []string `json:"model_list,omitempty"`
	// SupportsTranslation lists the client protocols this provider can accept
	// by conversion, i.e. every protocol it speaks other than its own.
	SupportsTranslation []string `json:"supports_translation,omitempty"`
}

// providerChannelView describes one expanded channel.
type providerChannelView struct {
	Channel     string   `json:"channel"`
	Key         string   `json:"key,omitempty"`
	Protocol    string   `json:"protocol"`
	Protocols   []string `json:"protocols"`
	HasKey      bool     `json:"has_key"`
	Enabled     bool     `json:"enabled"`
	Weight      float64  `json:"weight"`
	Groups      []string `json:"groups,omitempty"`
	ModelCount  int      `json:"model_count"`
	Discovered  string   `json:"discovered,omitempty"`
	Stale       bool     `json:"stale,omitempty"`
	DiscoverErr string   `json:"discover_error,omitempty"`
}

// channelHealth is the live state of one channel.
type channelHealth struct {
	Channel string `json:"channel"`
	// Failures is the consecutive failure count.
	Failures int `json:"failures"`
	// Healthy is false while the circuit breaker is open.
	Healthy bool `json:"healthy"`
	// Requests and Errors come from the audit ledger.
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"`
	// UsageIntegrity is 1 - clamped worst deviation, from the ledger.
	UsageIntegrity float64 `json:"usage_integrity"`
}

// handleProviders lists configured providers with their keys and live health.
func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	summaries := cfg.SummarizeProviders()
	catalogue := s.catalogue.Channels()
	byChannel := map[string]discovery.ChannelModels{}
	for _, cm := range catalogue {
		byChannel[cm.Channel] = cm
	}
	unhealthy := s.health.Unhealthy()

	// Aggregate the audit ledger once, for per-channel request counts.
	records, _ := s.readAudit()
	_, channelStats := aggregateForView(records)
	statByChannel := map[string]channelStat{}
	for _, cs := range channelStats {
		statByChannel[cs.Channel] = cs
	}

	out := make([]providerView, 0, len(summaries))
	for _, sum := range summaries {
		pv := providerView{ProviderSummary: sum}
		for _, k := range sum.Keys {
			ch, ok := cfg.ChannelByName(k.Channel)
			protocols := sum.Protocols
			view := providerChannelView{
				Channel:   k.Channel,
				Key:       k.Name,
				Protocol:  sum.Protocol,
				Protocols: protocols,
				HasKey:    k.HasKey,
				Enabled:   k.Enabled && sum.Enabled,
				Groups:    sum.Groups,
			}
			if ok {
				view.Weight = ch.Weight
				if cm, found := byChannel[k.Channel]; found {
					view.ModelCount = len(cm.Models)
					view.Stale = cm.Stale
					view.DiscoverErr = cm.Error
					view.Discovered = cm.Discovered.Format("2006-01-02 15:04:05")
				}
				for _, m := range catalogue {
					if m.Channel == k.Channel {
						for _, e := range m.Models {
							pv.ModelList = appendUnique(pv.ModelList, e.Model)
						}
					}
				}
			}
			pv.Channels = append(pv.Channels, view)

			h := channelHealth{Channel: k.Channel, Healthy: !unhealthy[k.Channel]}
			h.Failures = s.health.FailureCount(k.Channel)
			if cs, found := statByChannel[k.Channel]; found {
				h.Requests = cs.Requests
				h.Errors = cs.Errors
				h.UsageIntegrity = cs.Integrity
			}
			pv.Health = append(pv.Health, h)
		}
		// A provider can accept any protocol it speaks *and* any protocol the
		// gateway can translate into one of those.
		for _, p := range []string{"openai", "responses", "anthropic"} {
			if p == sum.Protocol {
				continue
			}
			if !containsString(sum.Protocols, p) {
				pv.SupportsTranslation = append(pv.SupportsTranslation, p)
			}
		}
		sort.Strings(pv.ModelList)
		out = append(out, pv)
	}

	// Directly-configured channels have no provider wrapper; report them so
	// nothing is invisible in the UI.
	direct := make([]providerChannelView, 0)
	for _, ch := range cfg.AllChannels() {
		if _, isProvider := cfg.ProviderByChannelName(ch.Name); isProvider {
			// Providers are reported above, with their keys and health.
			continue
		}
		view := providerChannelView{
			Channel:  ch.Name,
			Protocol: channelProtocol(ch),
			HasKey:   ch.APIKey != "",
			Enabled:  ch.IsEnabled(),
			Weight:   ch.Weight,
		}
		if cm, found := byChannel[ch.Name]; found {
			view.ModelCount = len(cm.Models)
			view.Stale = cm.Stale
			view.DiscoverErr = cm.Error
		}
		direct = append(direct, view)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"providers":       out,
		"direct_channels": direct,
		"groups":          cfg.GroupNames(),
		"protocols": []map[string]string{
			{"id": "openai", "name": protocol.ProtocolDisplayName("openai"), "endpoint": "/v1/chat/completions"},
			{"id": "responses", "name": protocol.ProtocolDisplayName("responses"), "endpoint": "/v1/responses"},
			{"id": "anthropic", "name": protocol.ProtocolDisplayName("anthropic"), "endpoint": "/v1/messages"},
		},
		"routing": map[string]any{
			"strategy":             s.selector.Strategy(),
			"prefer_same_protocol": cfg.Routing.SameProtocolPreferred(),
			"allow_translation":    cfg.Routing.TranslationAllowed(),
			"max_attempts":         cfg.Routing.Attempts(),
			"retry_on":             cfg.Routing.RetryOn,
		},
	})
}

// handleAdminModels serves the per-channel catalogue with staleness.
func (s *Server) handleAdminModels(w http.ResponseWriter, r *http.Request) {
	snap := s.catalogue.Snapshot()
	views := s.catalogue.Models(nil)

	provider := r.URL.Query().Get("provider")
	if provider != "" {
		filtered := make([]discovery.ModelView, 0, len(views))
		for _, v := range views {
			for _, c := range v.Channels {
				if c.Provider == provider {
					filtered = append(filtered, v)
					break
				}
			}
		}
		views = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"updated_at": snap.UpdatedAt,
		"channels":   s.catalogue.Channels(),
		"models":     views,
		"providers":  snap.Providers,
		"errors":     snap.Errors,
	})
}

// handleModelsRefresh forces a discovery run and returns the new catalogue.
func (s *Server) handleModelsRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	s.catalogue.Refresh(r.Context(), s.Config())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":     true,
		"models": len(s.catalogue.Models(nil)),
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// readAudit loads the audit ledger for aggregation. A missing ledger is not an
// error: a freshly started gateway simply has no records yet.
func (s *Server) readAudit() ([]audit.Record, error) {
	return audit.ReadAll(s.auditPath())
}

// channelStat is the subset of aggregate data the provider view needs.
type channelStat struct {
	Channel   string
	Requests  int64
	Errors    int64
	Integrity float64
}

// aggregateForView computes per-channel counters from the audit ledger.
func aggregateForView(records []audit.Record) (int, []channelStat) {
	type acc struct {
		requests int64
		errors   int64
		verif    int64
		sum      float64
	}
	idx := map[string]*acc{}
	var order []string
	for _, rec := range records {
		a, ok := idx[rec.Channel]
		if !ok {
			a = &acc{}
			idx[rec.Channel] = a
			order = append(order, rec.Channel)
		}
		a.requests++
		if rec.Decision == audit.DecisionUpstreamError {
			a.errors++
		}
		if rec.Usage.UpstreamReported && rec.Usage.Verdict != "not_reported" {
			a.verif++
			integrity := 1.0
			if rec.Usage.Verdict == "over_billed" || rec.Usage.Verdict == "under_billed" {
				d := rec.Usage.PromptDelta
				if v := rec.Usage.CompletionDelta; absFloat(v) > absFloat(d) {
					d = v
				}
				integrity = 1 - absFloat(d)
				if integrity < 0 {
					integrity = 0
				}
			}
			a.sum += integrity
		}
	}
	sort.Strings(order)
	out := make([]channelStat, 0, len(order))
	for _, name := range order {
		a := idx[name]
		cs := channelStat{Channel: name, Requests: a.requests, Errors: a.errors, Integrity: 1}
		if a.verif > 0 {
			cs.Integrity = a.sum / float64(a.verif)
		}
		out = append(out, cs)
	}
	return len(records), out
}

func absFloat(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	return append(list, v)
}

// priceForModel reports the cheapest effective unit price across the channels
// serving a model, which is what the comparison view sorts on.
func (s *Server) priceForModel(model string, view *discovery.ModelView) {
	now := time.Now()
	var (
		best     float64
		bestChan string
		currency string
	)
	for _, c := range view.Channels {
		pm, ok := s.pricer.Lookup(c.Channel, model)
		if !ok {
			continue
		}
		unit := meter.EffectiveUnitPrice(pm, meter.Tokens{}, now, nil)
		if unit <= 0 {
			continue
		}
		if best == 0 || unit < best {
			best, bestChan, currency = unit, c.Channel, pm.Currency
		}
	}
	view.Cheapest = bestChan
	view.UnitPrice = best
	view.Currency = currency
}

// protocolBadge renders a protocol for display.
func protocolBadge(p string) string {
	switch strings.ToLower(p) {
	case "openai":
		return "chat"
	case "responses":
		return "responses"
	case "anthropic":
		return "messages"
	}
	return p
}

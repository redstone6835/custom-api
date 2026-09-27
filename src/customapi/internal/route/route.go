// Package route chooses which upstream channel serves a request.
//
// This is where the project's "自动择优路由" requirement is implemented: the
// router combines the normalized price for the concrete token mix of *this*
// request (including time- and volume-dependent promotions) with the
// capability score measured by the intelligence layer, so that a cheap channel
// that has been serving a degraded model is not preferred merely for being
// cheap.
package route

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/redstone/customapi/internal/config"
	"github.com/redstone/customapi/internal/meter"
)

// Scores is the intelligence layer's verdict on one channel/model pair.
type Scores struct {
	// Capability is the benchmark score in [0,1]; 0 means "unmeasured".
	Capability float64 `json:"capability,omitempty"`
	// FingerprintMatch is the fraction of probes that matched the baseline,
	// in [0,1]; 1 means "always the genuine model".
	FingerprintMatch float64 `json:"fingerprint_match,omitempty"`
	// Reliability is the observed success rate in [0,1].
	Reliability float64 `json:"reliability,omitempty"`
	// UsageIntegrity is 1 - clamp(worst observed deviation), in [0,1]; a
	// channel that inflates usage is penalised regardless of price.
	UsageIntegrity float64 `json:"usage_integrity,omitempty"`
	// Benchmarks holds per-suite capability detail.
	Benchmarks map[string]float64 `json:"benchmarks,omitempty"`
	// UpdatedAt is when the score was computed.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// Samples is how many observations back this score.
	Samples int `json:"samples,omitempty"`
}

// ScoreBook resolves scores by channel and model.
type ScoreBook interface {
	Score(channel, model string) (Scores, bool)
}

// MapScoreBook is an in-memory ScoreBook, used by tests and by the
// intelligence layer's initial load.
type MapScoreBook struct {
	mu    sync.RWMutex
	byKey map[string]Scores
	// Fallback is returned when no entry exists.
	Fallback Scores
	// UseFallback enables the fallback.
	UseFallback bool
}

// NewMapScoreBook builds a score book from a nested map.
func NewMapScoreBook(in map[string]map[string]Scores) *MapScoreBook {
	m := &MapScoreBook{byKey: map[string]Scores{}}
	for ch, models := range in {
		for model, s := range models {
			m.byKey[ch+"\x00"+model] = s
		}
	}
	return m
}

// Set inserts a score.
func (m *MapScoreBook) Set(channel, model string, s Scores) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byKey == nil {
		m.byKey = map[string]Scores{}
	}
	m.byKey[channel+"\x00"+model] = s
}

// Score implements ScoreBook.
func (m *MapScoreBook) Score(channel, model string) (Scores, bool) {
	if m == nil {
		return Scores{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byKey[channel+"\x00"+model]
	if ok {
		return s, true
	}
	if m.UseFallback {
		return m.Fallback, true
	}
	return Scores{}, false
}

// ---------------------------------------------------------------------------
// Candidate scoring
// ---------------------------------------------------------------------------

// Candidate is one channel considered for a request.
type Candidate struct {
	// Channel is the resolved configuration.
	Channel config.Channel
	// UpstreamModel is the model name to send upstream.
	UpstreamModel string
	// Price is the normalized price, when known.
	Price config.PriceModel
	// HasPrice reports whether Price is meaningful.
	HasPrice bool
	// Quote is the priced cost for this request's token mix.
	Quote meter.Quote
	// UnitPrice is the blended cost per million tokens.
	UnitPrice float64
	// Scores is the intelligence verdict, when known.
	Scores Scores
	// Value is the composite ranking score for strategy "value".
	Value float64
	// Weight is the configured routing weight.
	Weight float64
	// Reason explains the ranking contribution.
	Reason string
	// Protocol is the wire protocol the channel speaks.
	Protocol string
	// Translated reports that reaching this channel requires converting the
	// request and response between protocols.
	Translated bool
}

// Request is the input to the router.
type Request struct {
	// Model is the canonical model name.
	Model string
	// Tokens is the token mix to price.
	Tokens meter.Tokens
	// At is the pricing instant (zero means now).
	At time.Time
	// Strategy overrides the configured default: "cheapest", "best_score",
	// "value", "weighted" or "fixed".
	Strategy string
	// Pin names a channel to use regardless of strategy.
	Pin string
	// Exclude lists channels that must not be used (for example after a
	// failure or when the user already tried them).
	Exclude map[string]bool
	// RequireHealthy drops channels marked unhealthy.
	Unhealthy map[string]bool

	// ClientProtocol is the protocol the caller spoke: "openai", "responses"
	// or "anthropic".
	ClientProtocol string
	// PreferSameProtocol ranks channels that already speak the client's
	// protocol above any channel reachable only by translation. Translation is
	// lossy in places, so it is a fallback rather than a default.
	PreferSameProtocol bool
	// AllowTranslation permits considering channels that speak a different
	// protocol. When false, only same-protocol channels are candidates.
	AllowTranslation bool
	// Groups restricts routing to providers in these groups.
	Groups []string
	// ExcludeProviders skips these providers entirely.
	ExcludeProviders []string
}

// Decision is the router's output.
type Decision struct {
	// Chosen is the selected candidate.
	Chosen Candidate
	// Ranked lists every admissible candidate in preference order, which the
	// failover loop uses to try alternatives.
	Ranked []Candidate
	// Strategy actually applied.
	Strategy string
	// Reason is a human-readable explanation recorded in the audit log.
	Reason string
}

// Selector performs channel selection.
//
// A Selector is safe for concurrent use: the only mutable state is the RNG
// behind the weighted strategy, which is guarded because Select runs on every
// request goroutine.
type Selector struct {
	pricer   *meter.Pricer
	scores   ScoreBook
	strategy string
	// rng is used by the weighted strategy.
	rngMu sync.Mutex
	rng   *rand.Rand
	// cheapnessFloor guards the value metric against a zero price.
	cheapnessFloor float64
	// mu guards lastProtocol, which is only used to word explanations.
	mu           sync.Mutex
	lastProtocol string
}

// Options configures a Selector.
type Options struct {
	Pricer   *meter.Pricer
	Scores   ScoreBook
	Strategy string
	// Seed makes the weighted strategy deterministic in tests.
	Seed int64
}

// New builds a Selector.
func New(opts Options) *Selector {
	s := &Selector{
		pricer:         opts.Pricer,
		scores:         opts.Scores,
		strategy:       opts.Strategy,
		cheapnessFloor: 1e-9,
	}
	if s.strategy == "" {
		s.strategy = "value"
	}
	seed := opts.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	s.rng = rand.New(rand.NewSource(seed))
	return s
}

// Strategy returns the configured default strategy.
func (s *Selector) Strategy() string { return s.strategy }

// Candidates builds and ranks the admissible candidates for a request.
func (s *Selector) Candidates(channels []config.Channel, req Request) ([]Candidate, error) {
	at := req.At
	if at.IsZero() {
		at = time.Now()
	}
	s.noteClientProtocol(req.ClientProtocol)
	var out []Candidate
	for _, ch := range channels {
		if !ch.IsEnabled() {
			continue
		}
		if req.Exclude != nil && req.Exclude[ch.Name] {
			continue
		}
		if req.Unhealthy != nil && req.Unhealthy[ch.Name] {
			continue
		}
		upstream := ch.UpstreamModel(req.Model)
		if upstream == "" {
			continue
		}
		// Group and provider filtering happens before scoring so that an
		// excluded provider never influences the ranking.
		if len(req.Groups) > 0 && !channelInGroups(ch, req.Groups) {
			continue
		}
		if len(req.ExcludeProviders) > 0 && channelInProviders(ch, req.ExcludeProviders) {
			continue
		}
		protocol := channelProtocolName(ch)
		translated := false
		if req.ClientProtocol != "" && protocol != req.ClientProtocol {
			// The provider does not prefer the protocol the caller used. Two
			// ways it can still serve the request:
			//
			//   - it declared that surface (supports=[..., responses]), in which
			//     case the request goes to that endpoint unchanged;
			//   - it did not declare it, in which case the only route is to
			//     convert the payload, which needs the operator's permission.
			//
			// Anything else is refused. Handing a converted payload to an
			// endpoint that does not implement the target surface produces an
			// upstream 404 at best and a wrong answer at worst.
			if !channelSupportsRequest(ch, req.ClientProtocol) {
				if !req.AllowTranslation {
					continue
				}
				translated = true
			}
		}
		c := Candidate{
			Channel:       ch,
			UpstreamModel: upstream,
			Weight:        ch.Weight,
			Protocol:      protocol,
			Translated:    translated,
		}
		if s.pricer != nil {
			if pm, ok := s.pricer.Lookup(ch.Name, req.Model); ok {
				c.Price = pm
				c.HasPrice = true
				c.Quote = meter.PriceWith(pm, req.Tokens, at, nil)
				total := req.Tokens.Total()
				if total > 0 {
					c.UnitPrice = c.Quote.Cost / (float64(total) / 1e6)
				} else {
					c.UnitPrice = meter.EffectiveUnitPrice(pm, req.Tokens, at, nil)
				}
			}
		}
		if s.scores != nil {
			if sc, ok := s.scores.Score(ch.Name, req.Model); ok {
				c.Scores = sc
			}
		}
		c.Value = s.value(c)
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("route: no channel can serve model %q", req.Model)
	}
	s.rank(out, req.Strategy, req.PreferSameProtocol)
	return out, nil
}

// Select returns the best candidate plus the full ranked list.
func (s *Selector) Select(channels []config.Channel, req Request) (*Decision, error) {
	cands, err := s.Candidates(channels, req)
	if err != nil {
		return nil, err
	}
	strategy := req.Strategy
	if strategy == "" {
		strategy = s.strategy
	}
	if req.Pin != "" {
		for _, c := range cands {
			if c.Channel.Name == req.Pin {
				return &Decision{
					Chosen:   c,
					Ranked:   cands,
					Strategy: "pinned",
					Reason:   fmt.Sprintf("channel %q pinned by request", req.Pin),
				}, nil
			}
		}
		return nil, fmt.Errorf("route: pinned channel %q is not available", req.Pin)
	}
	return &Decision{
		Chosen:   cands[0],
		Ranked:   cands,
		Strategy: strategy,
		Reason:   s.explain(cands[0], cands, strategy),
	}, nil
}

// value computes the composite value metric.
//
// value = capability_quality * integrity / unit_price
//
// Both quality terms default to a neutral 1.0 when unmeasured, so a new
// channel is neither advantaged nor punished by missing data. Integrity is
// squared so a channel caught inflating usage (0.5) is penalised harder than
// its linear share.
func (s *Selector) value(c Candidate) float64 {
	quality := 1.0
	if c.Scores.Capability > 0 {
		quality *= c.Scores.Capability
	}
	if c.Scores.FingerprintMatch > 0 {
		quality *= c.Scores.FingerprintMatch
	}
	if c.Scores.Reliability > 0 {
		quality *= c.Scores.Reliability
	}
	if c.Scores.UsageIntegrity > 0 {
		quality *= c.Scores.UsageIntegrity * c.Scores.UsageIntegrity
	}
	if !c.HasPrice || c.UnitPrice <= 0 {
		// Unknown price: treat as moderately expensive so a priced channel
		// wins on a tie, but the channel is not excluded.
		return quality / 1.0
	}
	v := quality / math.Max(c.UnitPrice, s.cheapnessFloor)
	// Scale by the operator's channel weight so a preferred channel can be
	// nudged upward without pinning it.
	if c.Weight > 0 {
		v *= c.Weight
	}
	return v
}

// rank orders candidates in place according to the strategy.
//
// When the caller asked for same-protocol preference, the list is first
// partitioned so that channels speaking the client's protocol come before any
// channel that would require translation. The configured strategy then orders
// within each partition, which means a translation is only ever attempted when
// no same-protocol channel is available - the property that keeps the common
// path lossless.
func (s *Selector) rank(cands []Candidate, strategy string, preferSame bool) {
	if strategy == "" {
		strategy = s.strategy
	}
	switch strategy {
	case "cheapest":
		sort.SliceStable(cands, func(i, j int) bool {
			return s.lessUnitPrice(cands[i], cands[j])
		})
	case "best_score":
		sort.SliceStable(cands, func(i, j int) bool {
			return s.capability(cands[i]) > s.capability(cands[j])
		})
	case "weighted":
		// A weighted draw over the configured weights, with the drawn
		// channel first and the rest in value order for failover.
		sort.SliceStable(cands, func(i, j int) bool { return cands[i].Value > cands[j].Value })
		if len(cands) > 1 {
			total := 0.0
			for _, c := range cands {
				if c.Weight > 0 {
					total += c.Weight
				}
			}
			if total > 0 {
				s.rngMu.Lock()
				pick := s.rng.Float64() * total
				s.rngMu.Unlock()
				acc := 0.0
				idx := 0
				for i, c := range cands {
					acc += c.Weight
					if pick <= acc {
						idx = i
						break
					}
				}
				if idx != 0 {
					chosen := cands[idx]
					cands = append(cands[:idx], cands[idx+1:]...)
					cands = append([]Candidate{chosen}, cands...)
				}
			}
		}
	case "fixed":
		// Preserve configuration order.
	default: // "value"
		sort.SliceStable(cands, func(i, j int) bool { return cands[i].Value > cands[j].Value })
	}

	// Same-protocol preference is a partition, not a tie-break: a channel that
	// serves the client's protocol without conversion is worth more than any
	// amount of cheapness, because translation is lossy (tool calls, reasoning
	// fields and server-side state degrade) while a price difference is merely
	// money. The strategy still decides the order *within* each tier, so
	// "cheapest" keeps meaning cheapest among comparable channels.
	//
	// This is applied after the strategy sort rather than inside it so that
	// every strategy gets the same guarantee; an earlier revision accepted the
	// flag and never read it, which silently disabled the feature.
	if preferSame {
		sort.SliceStable(cands, func(i, j int) bool {
			return !cands[i].Translated && cands[j].Translated
		})
	}
}

// lessUnitPrice orders by price, treating unknown prices as most expensive.
func (s *Selector) lessUnitPrice(a, b Candidate) bool {
	if a.HasPrice != b.HasPrice {
		return a.HasPrice
	}
	if !a.HasPrice {
		return a.Channel.Name < b.Channel.Name
	}
	if a.UnitPrice != b.UnitPrice {
		return a.UnitPrice < b.UnitPrice
	}
	return a.Channel.Name < b.Channel.Name
}

// capability returns the capability score with a neutral default.
func (s *Selector) capability(c Candidate) float64 {
	if c.Scores.Capability > 0 {
		return c.Scores.Capability
	}
	return 0.5
}

// explain builds the audit-facing justification for a choice.
func (s *Selector) explain(chosen Candidate, ranked []Candidate, strategy string) string {
	price := "unpriced"
	if chosen.HasPrice {
		price = fmt.Sprintf("%.4f %s/M", chosen.UnitPrice, chosen.Quote.Currency)
	}
	cap := "unmeasured"
	if chosen.Scores.Capability > 0 {
		cap = fmt.Sprintf("%.3f", chosen.Scores.Capability)
	}
	integrity := "unmeasured"
	if chosen.Scores.UsageIntegrity > 0 {
		integrity = fmt.Sprintf("%.3f", chosen.Scores.UsageIntegrity)
	}
	via := ""
	if chosen.Translated {
		s.mu.Lock()
		from := s.lastProtocol
		s.mu.Unlock()
		via = fmt.Sprintf(" (translated %s -> %s)", orNone(from), chosen.Protocol)
	}
	return fmt.Sprintf(
		"strategy=%s picked %q of %d candidate(s): protocol=%s%s unit_price=%s capability=%s usage_integrity=%s value=%.4g",
		strategy, chosen.Channel.Name, len(ranked), chosen.Protocol, via,
		price, cap, integrity, chosen.Value)
}

// clientProtocol is remembered on the selector for explanations. It is set by
// Candidates, which is the only entry point that knows the request.
func (s *Selector) noteClientProtocol(p string) {
	s.mu.Lock()
	s.lastProtocol = p
	s.mu.Unlock()
}

func orNone(v string) string {
	if v == "" {
		return "?"
	}
	return v
}

// ---------------------------------------------------------------------------
// Health tracking
// ---------------------------------------------------------------------------

// HealthTracker records channel failures so the router can avoid them.
//
// It implements a simple consecutive-failure circuit breaker: a channel is
// considered unhealthy after `Threshold` failures in a row and recovers either
// after `Cooldown` elapses or on an explicit success.
//
// It is safe for concurrent use, because every request goroutine reports its
// own outcome.
type HealthTracker struct {
	Threshold int
	Cooldown  time.Duration

	mu       sync.Mutex
	now      func() time.Time
	failures map[string]int
	openedAt map[string]time.Time
}

// NewHealthTracker builds a tracker with sensible defaults.
func NewHealthTracker(threshold int, cooldown time.Duration) *HealthTracker {
	if threshold <= 0 {
		threshold = 3
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &HealthTracker{
		Threshold: threshold,
		Cooldown:  cooldown,
		now:       time.Now,
		failures:  map[string]int{},
		openedAt:  map[string]time.Time{},
	}
}

// SetClock overrides the clock, for tests.
func (h *HealthTracker) SetClock(f func() time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = f
}

// Failure records a failure and reports whether the channel is now unhealthy.
func (h *HealthTracker) Failure(channel string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failures[channel]++
	if h.failures[channel] >= h.Threshold {
		if _, open := h.openedAt[channel]; !open {
			h.openedAt[channel] = h.now()
		}
		return true
	}
	return false
}

// Success clears a channel's failure state.
func (h *HealthTracker) Success(channel string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.failures, channel)
	delete(h.openedAt, channel)
}

// Unhealthy returns the set of currently unhealthy channels.
func (h *HealthTracker) Unhealthy() map[string]bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]bool{}
	now := h.now()
	for ch, at := range h.openedAt {
		if now.Sub(at) < h.Cooldown {
			out[ch] = true
		} else {
			// Cooldown elapsed: allow a half-open retry.
			delete(h.openedAt, ch)
			h.failures[ch] = 0
		}
	}
	return out
}

// FailureCount returns the consecutive failure count for a channel.
func (h *HealthTracker) FailureCount(channel string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.failures[channel]
}

// ---------------------------------------------------------------------------
// Usage-integrity degradation
// ---------------------------------------------------------------------------

// Deviation is the metering layer's measure of how far an upstream's reported
// usage diverged from the gateway's recount. It is redeclared here so that the
// routing package does not depend on the metering package, avoiding an import
// cycle (metering -> protocol, route -> config+meter).
type Deviation struct {
	// Worst is the largest absolute relative deviation observed.
	Worst float64
	// OverThreshold reports whether that deviation exceeded the tolerance.
	OverThreshold bool
	// Direction is "over" or "under".
	Direction string
}

// DegradeChannel lowers a channel's effective score in response to a metering
// violation.
//
// This is the feedback edge from section C (metering) back into routing: a
// channel that inflates its reported usage is penalised in proportion to how
// badly it lied, and the penalty decays over time rather than being permanent,
// so an upstream that fixes a billing bug is not punished forever.
func (s *Selector) DegradeChannel(channel string, d Deviation) {
	if s.scores == nil {
		return
	}
	book, ok := s.scores.(*MapScoreBook)
	if !ok {
		return
	}
	book.mu.Lock()
	defer book.mu.Unlock()
	set := func(key string, sc Scores) {
		if sc.UsageIntegrity == 0 {
			sc.UsageIntegrity = 1
		}
		// Clamp the measured deviation into an integrity factor in [0,1].
		worst := math.Abs(d.Worst)
		if math.IsInf(worst, 1) {
			worst = 1e6
		}
		measured := 1 - math.Min(worst, 1)
		// Blend with the existing estimate so a single anomaly does not
		// collapse a channel's score, but a pattern does.
		if sc.Samples > 0 {
			sc.UsageIntegrity = (sc.UsageIntegrity*float64(sc.Samples) + measured) / float64(sc.Samples+1)
		} else {
			sc.UsageIntegrity = measured
		}
		sc.Samples++
		sc.UpdatedAt = time.Now()
		book.byKey[key] = sc
	}
	// Apply to every model entry this channel has, since the billing
	// behaviour is a property of the channel rather than of one model.
	prefix := channel + "\x00"
	for k, sc := range book.byKey {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			set(k, sc)
		}
	}
}

// ---------------------------------------------------------------------------
// Protocol and group helpers
// ---------------------------------------------------------------------------

// channelProtocolName returns the channel's effective wire protocol.
func channelProtocolName(ch config.Channel) string {
	if ch.Protocol == "" {
		return "openai"
	}
	return ch.Protocol
}

// channelSupportsRequest reports whether a channel can serve a request that
// arrived in the given protocol.
//
// A channel always handles the protocol it prefers. Beyond that it is held to
// its declaration, and the declaration is exhaustive: a provider that writes
// protocol=openai with supports=[openai] has enumerated its surfaces and is
// saying "chat only", so a Responses request must not reach it. Absent metadata
// is silence rather than a list, and a directly-configured channel is trusted
// there because the operator wrote the channel by hand.
func channelSupportsRequest(ch config.Channel, protocol string) bool {
	if channelProtocolName(ch) == protocol {
		return true
	}
	declared := ch.DeclaredProtocols()
	if declared == nil {
		return ch.Metadata == nil
	}
	for _, p := range declared {
		if p == protocol {
			return true
		}
	}
	return false
}

// channelInGroups reports whether a channel belongs to any of the groups.
func channelInGroups(ch config.Channel, groups []string) bool {
	if ch.Metadata == nil {
		return false
	}
	listed, ok := ch.Metadata["groups"]
	if !ok {
		return false
	}
	member := map[string]bool{}
	for _, g := range strings.Split(listed, ",") {
		member[strings.TrimSpace(g)] = true
	}
	for _, g := range groups {
		if member[g] {
			return true
		}
	}
	return false
}

// channelInProviders reports whether a channel belongs to any of the providers.
func channelInProviders(ch config.Channel, providers []string) bool {
	name := ch.Name
	if ch.Metadata != nil {
		if p, ok := ch.Metadata["provider"]; ok {
			name = p
		}
	}
	for _, p := range providers {
		if name == p || strings.HasPrefix(ch.Name, p+"/") {
			return true
		}
	}
	return false
}

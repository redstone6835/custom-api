package route

import (
	"testing"
	"time"

	"github.com/redstone/customapi/internal/config"
	"github.com/redstone/customapi/internal/meter"
)

func chans() []config.Channel {
	enabled := true
	return []config.Channel{
		{Name: "cheap-degraded", BaseURL: "http://a", Protocol: "openai", Weight: 1, Enabled: &enabled,
			Models: map[string]string{"gpt-4o": "gpt-4o"}},
		{Name: "expensive-genuine", BaseURL: "http://b", Protocol: "openai", Weight: 1, Enabled: &enabled,
			Models: map[string]string{"gpt-4o": "gpt-4o"}},
		{Name: "disabled", BaseURL: "http://c", Protocol: "openai", Weight: 1,
			Enabled: boolPtr(false), Models: map[string]string{"gpt-4o": "gpt-4o"}},
	}
}

func boolPtr(b bool) *bool { return &b }

func prices() []config.PriceEntry {
	return []config.PriceEntry{
		{Channel: "cheap-degraded", Model: "gpt-4o", Price: config.PriceModel{InputPerM: 1, OutputPerM: 2, Currency: "CNY"}},
		{Channel: "expensive-genuine", Model: "gpt-4o", Price: config.PriceModel{InputPerM: 10, OutputPerM: 20, Currency: "CNY"}},
	}
}

func scoreBook() *MapScoreBook {
	return NewMapScoreBook(map[string]map[string]Scores{
		"cheap-degraded": {
			// Cheap, but measured as a substituted/degraded model.
			"gpt-4o": {Capability: 0.35, FingerprintMatch: 0.2, Reliability: 0.9, UsageIntegrity: 1},
		},
		"expensive-genuine": {
			"gpt-4o": {Capability: 0.95, FingerprintMatch: 1.0, Reliability: 0.99, UsageIntegrity: 1},
		},
	})
}

func newSelector(strategy string, sb ScoreBook) *Selector {
	return New(Options{
		Pricer:   meter.NewPricer(prices(), time.UTC),
		Scores:   sb,
		Strategy: strategy,
		Seed:     42,
	})
}

// ---------------------------------------------------------------------------
// Candidate construction
// ---------------------------------------------------------------------------

func TestCandidatesExcludeDisabled(t *testing.T) {
	s := newSelector("value", scoreBook())
	got, err := s.Candidates(chans(), Request{Model: "gpt-4o"})
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	for _, c := range got {
		if c.Channel.Name == "disabled" {
			t.Fatal("a disabled channel was offered as a candidate")
		}
	}
}

func TestCandidatesRespectExclusions(t *testing.T) {
	s := newSelector("value", scoreBook())
	got, err := s.Candidates(chans(), Request{
		Model:   "gpt-4o",
		Exclude: map[string]bool{"cheap-degraded": true},
	})
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(got) != 1 || got[0].Channel.Name != "expensive-genuine" {
		t.Fatalf("exclusion not honoured: %+v", got)
	}
}

func TestCandidatesRespectUnhealthy(t *testing.T) {
	s := newSelector("value", scoreBook())
	got, err := s.Candidates(chans(), Request{
		Model:     "gpt-4o",
		Unhealthy: map[string]bool{"cheap-degraded": true},
	})
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(got) != 1 || got[0].Channel.Name != "expensive-genuine" {
		t.Fatalf("unhealthy channel not skipped: %+v", got)
	}
}

func TestCandidatesNoMatch(t *testing.T) {
	s := newSelector("value", scoreBook())
	if _, err := s.Candidates(chans(), Request{Model: "no-such-model"}); err == nil {
		t.Fatal("expected an error when no channel can serve the model")
	}
}

// TestModelAliasing verifies that the canonical name is translated to the
// channel's own model name.
func TestModelAliasing(t *testing.T) {
	cs := []config.Channel{{
		Name: "aliased", BaseURL: "http://a", Protocol: "openai", Weight: 1,
		Models: map[string]string{"gpt-4o": "openai/gpt-4o-2024-11-20"},
	}}
	s := newSelector("value", nil)
	got, err := s.Candidates(cs, Request{Model: "gpt-4o"})
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if got[0].UpstreamModel != "openai/gpt-4o-2024-11-20" {
		t.Fatalf("upstream model = %q", got[0].UpstreamModel)
	}
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

// TestCheapestStrategy verifies the pure price strategy.
func TestCheapestStrategy(t *testing.T) {
	s := newSelector("cheapest", scoreBook())
	d, err := s.Select(chans(), Request{Model: "gpt-4o", Tokens: meter.Tokens{Input: 1000}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if d.Chosen.Channel.Name != "cheap-degraded" {
		t.Fatalf("cheapest strategy picked %q", d.Chosen.Channel.Name)
	}
}

// TestBestScoreStrategy verifies the pure capability strategy.
func TestBestScoreStrategy(t *testing.T) {
	s := newSelector("best_score", scoreBook())
	d, err := s.Select(chans(), Request{Model: "gpt-4o", Tokens: meter.Tokens{Input: 1000}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if d.Chosen.Channel.Name != "expensive-genuine" {
		t.Fatalf("best_score strategy picked %q", d.Chosen.Channel.Name)
	}
}

// TestValueStrategyPrefersGenuineOverCheap is the central routing test: the
// design's whole point is that a cheap channel with a bad fingerprint must not
// win. Here the genuine channel is 10x the price but ~13x better on
// capability*fingerprint, so value must choose it.
func TestValueStrategyPrefersGenuineOverCheap(t *testing.T) {
	s := newSelector("value", scoreBook())
	d, err := s.Select(chans(), Request{Model: "gpt-4o", Tokens: meter.Tokens{Input: 1_000_000, Output: 1_000_000}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if d.Chosen.Channel.Name != "expensive-genuine" {
		t.Fatalf("value strategy picked %q, expected the genuine channel", d.Chosen.Channel.Name)
	}
}

// TestValueStrategyStillPrefersCheapWhenQualityIsEqual verifies the metric is
// not simply "always pick the most expensive channel".
func TestValueStrategyStillPrefersCheapWhenQualityIsEqual(t *testing.T) {
	sb := NewMapScoreBook(map[string]map[string]Scores{
		"cheap-degraded":    {"gpt-4o": {Capability: 0.9, FingerprintMatch: 1, Reliability: 1, UsageIntegrity: 1}},
		"expensive-genuine": {"gpt-4o": {Capability: 0.9, FingerprintMatch: 1, Reliability: 1, UsageIntegrity: 1}},
	})
	s := newSelector("value", sb)
	d, err := s.Select(chans(), Request{Model: "gpt-4o", Tokens: meter.Tokens{Input: 1_000_000}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if d.Chosen.Channel.Name != "cheap-degraded" {
		t.Fatalf("equal quality should favour the cheaper channel, got %q", d.Chosen.Channel.Name)
	}
}

// TestValuePenalisesUsageInflation verifies that a channel caught inflating
// usage loses to an honest competitor even at a much lower price.
func TestValuePenalisesUsageInflation(t *testing.T) {
	sb := NewMapScoreBook(map[string]map[string]Scores{
		// Very cheap and apparently capable, but measured as dishonest.
		"cheap-degraded":    {"gpt-4o": {Capability: 1, FingerprintMatch: 1, Reliability: 1, UsageIntegrity: 0.2}},
		"expensive-genuine": {"gpt-4o": {Capability: 1, FingerprintMatch: 1, Reliability: 1, UsageIntegrity: 1}},
	})
	s := newSelector("value", sb)
	d, err := s.Select(chans(), Request{Model: "gpt-4o", Tokens: meter.Tokens{Input: 1_000_000, Output: 1_000_000}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if d.Chosen.Channel.Name != "expensive-genuine" {
		t.Fatalf("a dishonest channel won routing: %q", d.Chosen.Channel.Name)
	}
}

// TestUnknownPriceIsNotExcluded verifies that a channel without a price is
// still usable, just not preferred on cost.
func TestUnknownPriceIsNotExcluded(t *testing.T) {
	cs := []config.Channel{
		{Name: "unpriced", BaseURL: "http://a", Protocol: "openai", Weight: 1,
			Models: map[string]string{"gpt-4o": "gpt-4o"}},
	}
	s := newSelector("value", nil)
	d, err := s.Select(cs, Request{Model: "gpt-4o"})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if d.Chosen.HasPrice {
		t.Fatal("expected HasPrice=false for an unpriced channel")
	}
}

func TestPinOverridesStrategy(t *testing.T) {
	s := newSelector("cheapest", scoreBook())
	d, err := s.Select(chans(), Request{Model: "gpt-4o", Pin: "expensive-genuine"})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if d.Chosen.Channel.Name != "expensive-genuine" {
		t.Fatalf("pin ignored: %q", d.Chosen.Channel.Name)
	}
	if d.Strategy != "pinned" {
		t.Fatalf("strategy = %q", d.Strategy)
	}
}

func TestPinToUnavailableChannelFails(t *testing.T) {
	s := newSelector("value", scoreBook())
	if _, err := s.Select(chans(), Request{Model: "gpt-4o", Pin: "nope"}); err == nil {
		t.Fatal("expected an error for a pin to an unavailable channel")
	}
}

func TestFixedStrategyPreservesConfigOrder(t *testing.T) {
	s := newSelector("fixed", scoreBook())
	d, err := s.Select(chans(), Request{Model: "gpt-4o"})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if d.Chosen.Channel.Name != "cheap-degraded" {
		t.Fatalf("fixed strategy reordered channels: %q", d.Chosen.Channel.Name)
	}
}

// TestRankedListSupportsFailover verifies that the full ranking is returned so
// the caller can retry the next candidate.
func TestRankedListSupportsFailover(t *testing.T) {
	s := newSelector("value", scoreBook())
	d, err := s.Select(chans(), Request{Model: "gpt-4o", Tokens: meter.Tokens{Input: 1_000_000}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if len(d.Ranked) != 2 {
		t.Fatalf("expected 2 ranked candidates, got %d", len(d.Ranked))
	}
	if d.Ranked[0].Channel.Name != d.Chosen.Channel.Name {
		t.Fatal("the chosen channel must head the ranked list")
	}
}

// TestRequestPriceUsesThisRequestsMix verifies that a volume promotion that the
// current request unlocks is reflected in routing.
func TestRequestPriceUsesThisRequestsMix(t *testing.T) {
	pm := config.PriceModel{
		InputPerM: 100, OutputPerM: 100,
		Promotions: []config.Promotion{{Kind: config.PromoVolume, Multiplier: 0.1, MinTokens: 1_000_000}},
	}
	pricer := meter.NewPricer([]config.PriceEntry{
		{Channel: "vol", Model: "m", Price: pm},
	}, time.UTC)
	cs := []config.Channel{{Name: "vol", BaseURL: "http://a", Models: map[string]string{"m": "m"}}}
	s := New(Options{Pricer: pricer, Strategy: "cheapest"})

	small, err := s.Candidates(cs, Request{Model: "m", Tokens: meter.Tokens{Input: 1000}})
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	big, err := s.Candidates(cs, Request{Model: "m", Tokens: meter.Tokens{Input: 2_000_000}})
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	smallUnit := small[0].Quote.Cost / 0.001
	bigUnit := big[0].Quote.Cost / 2.0
	if !(bigUnit < smallUnit) {
		t.Fatalf("volume promotion not reflected in the unit price: big=%v small=%v", bigUnit, smallUnit)
	}
}

// ---------------------------------------------------------------------------
// Degradation feedback
// ---------------------------------------------------------------------------

// TestDegradeChannelLowersIntegrity verifies the feedback edge from metering
// back into routing.
func TestDegradeChannelLowersIntegrity(t *testing.T) {
	sb := scoreBook()
	s := New(Options{Pricer: meter.NewPricer(prices(), time.UTC), Scores: sb, Strategy: "value"})

	before, _ := sb.Score("expensive-genuine", "gpt-4o")
	if before.UsageIntegrity < 0.99 {
		t.Fatalf("expected a clean score to start, got %v", before.UsageIntegrity)
	}

	// The upstream claims 100% more than the gateway counted.
	s.DegradeChannel("expensive-genuine", Deviation{Worst: 1.0, OverThreshold: true, Direction: "over"})

	after, _ := sb.Score("expensive-genuine", "gpt-4o")
	if after.UsageIntegrity >= before.UsageIntegrity {
		t.Fatalf("integrity did not decrease: %v -> %v", before.UsageIntegrity, after.UsageIntegrity)
	}
	if after.Samples != before.Samples+1 {
		t.Fatalf("sample count not updated: %d -> %d", before.Samples, after.Samples)
	}
}

// TestDegradeChannelDoesNotAffectOtherChannels verifies the penalty is scoped.
func TestDegradeChannelDoesNotAffectOtherChannels(t *testing.T) {
	sb := scoreBook()
	s := New(Options{Scores: sb, Strategy: "value"})
	s.DegradeChannel("cheap-degraded", Deviation{Worst: 1, OverThreshold: true, Direction: "over"})
	if sc, _ := sb.Score("expensive-genuine", "gpt-4o"); sc.UsageIntegrity != 1 {
		t.Fatalf("degrading one channel changed another: %v", sc.UsageIntegrity)
	}
}

// ---------------------------------------------------------------------------
// Health tracking
// ---------------------------------------------------------------------------

func TestHealthTrackerOpensAndRecovers(t *testing.T) {
	h := NewHealthTracker(2, time.Minute)
	now := time.Now()
	h.SetClock(func() time.Time { return now })

	if h.Failure("a") {
		t.Fatal("a single failure should not trip the breaker")
	}
	if !h.Failure("a") {
		t.Fatal("the breaker should trip at the threshold")
	}
	if !h.Unhealthy()["a"] {
		t.Fatal("channel should be unhealthy")
	}

	// After the cooldown it becomes eligible again (half-open).
	now = now.Add(2 * time.Minute)
	if h.Unhealthy()["a"] {
		t.Fatal("channel should recover after the cooldown")
	}

	// A success clears the state entirely.
	h.Failure("a")
	h.Success("a")
	if h.FailureCount("a") != 0 {
		t.Fatalf("failure count = %d after success", h.FailureCount("a"))
	}
}

func TestHealthTrackerIsolatesChannels(t *testing.T) {
	h := NewHealthTracker(1, time.Minute)
	h.Failure("a")
	u := h.Unhealthy()
	if !u["a"] || u["b"] {
		t.Fatalf("health state leaked across channels: %+v", u)
	}
}

// ---------------------------------------------------------------------------
// Explanations
// ---------------------------------------------------------------------------

// TestDecisionIncludesReason verifies that every routing decision is
// explainable, which the audit ledger records.
func TestDecisionIncludesReason(t *testing.T) {
	s := newSelector("value", scoreBook())
	d, err := s.Select(chans(), Request{Model: "gpt-4o", Tokens: meter.Tokens{Input: 1000}})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if d.Reason == "" {
		t.Fatal("a routing decision must carry an explanation")
	}
}

// Same-protocol preference is a partition, not a tie-break: no price advantage
// justifies a lossy conversion. The flag used to be accepted and never read, so
// this asserts the ordering directly rather than through the gateway, where a
// candidate can also disappear for unrelated reasons.
//
// The converting candidate is an anthropic-native channel that has no chat
// surface, so serving a chat request on it means converting the payload. A
// channel that declared chat as well would serve it natively instead, which is a
// different (and separately tested) case.
func TestPreferSameProtocolPartitionsCandidates(t *testing.T) {
	channels := []config.Channel{
		{Name: "converted", Protocol: "anthropic", Weight: 1,
			BaseURL: "http://x", Models: map[string]string{"m": "m"},
			Metadata: map[string]string{"protocols": "anthropic"}},
		{Name: "native", Protocol: "openai", Weight: 1,
			BaseURL: "http://x", Models: map[string]string{"m": "m"}},
	}

	sel := New(Options{Strategy: "fixed"})
	dec, err := sel.Select(channels, Request{
		Model:              "m",
		ClientProtocol:     "openai",
		AllowTranslation:   true,
		PreferSameProtocol: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if len(dec.Ranked) != 2 {
		t.Fatalf("ranked = %d candidates, want both (the point is the order)", len(dec.Ranked))
	}
	if dec.Ranked[0].Channel.Name != "native" || dec.Ranked[0].Translated {
		t.Fatalf("first = %q translated=%v, want the native channel first",
			dec.Ranked[0].Channel.Name, dec.Ranked[0].Translated)
	}
	if dec.Ranked[1].Channel.Name != "converted" || !dec.Ranked[1].Translated {
		t.Fatalf("second = %q translated=%v, want the channel needing conversion",
			dec.Ranked[1].Channel.Name, dec.Ranked[1].Translated)
	}
}

// With the preference off, configuration order decides - which is what makes the
// flag meaningful rather than decorative.
func TestPreferSameProtocolOffLetsTheStrategyDecide(t *testing.T) {
	channels := []config.Channel{
		{Name: "converted", Protocol: "anthropic", Weight: 1,
			BaseURL: "http://x", Models: map[string]string{"m": "m"},
			Metadata: map[string]string{"protocols": "anthropic"}},
		{Name: "native", Protocol: "openai", Weight: 1,
			BaseURL: "http://x", Models: map[string]string{"m": "m"}},
	}
	sel := New(Options{Strategy: "fixed"})
	dec, err := sel.Select(channels, Request{
		Model:            "m",
		ClientProtocol:   "openai",
		AllowTranslation: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if dec.Ranked[0].Channel.Name != "converted" {
		t.Fatalf("first = %q, want the first configured channel", dec.Ranked[0].Channel.Name)
	}
	if !dec.Ranked[0].Translated {
		t.Fatal("the converting candidate is not marked as translated")
	}
}

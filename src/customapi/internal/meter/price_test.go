package meter

import (
	"math"
	"testing"
	"time"

	"github.com/redstone/customapi/internal/config"
)

var (
	noon  = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	night = time.Date(2026, 3, 1, 2, 0, 0, 0, time.UTC)
)

func almost(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// ---------------------------------------------------------------------------
// Basic pricing
// ---------------------------------------------------------------------------

func TestPriceWithFlatRates(t *testing.T) {
	pm := config.PriceModel{InputPerM: 10, OutputPerM: 30, Currency: "CNY"}
	q := PriceWith(pm, Tokens{Input: 1_000_000, Output: 1_000_000}, noon, time.UTC)
	if !almost(q.InputCost, 10) || !almost(q.OutputCost, 30) {
		t.Fatalf("component costs wrong: %+v", q)
	}
	if !almost(q.Cost, 40) {
		t.Fatalf("total = %v, want 40", q.Cost)
	}
	if !almost(q.DiscountPct, 0) {
		t.Fatalf("expected no discount, got %v", q.DiscountPct)
	}
}

func TestPriceWithPartialMillion(t *testing.T) {
	pm := config.PriceModel{InputPerM: 100, OutputPerM: 100}
	q := PriceWith(pm, Tokens{Input: 1000, Output: 0}, noon, time.UTC)
	if !almost(q.Cost, 0.1) {
		t.Fatalf("cost = %v, want 0.1", q.Cost)
	}
}

func TestPriceZeroTokens(t *testing.T) {
	pm := config.PriceModel{InputPerM: 10, OutputPerM: 30}
	q := PriceWith(pm, Tokens{}, noon, time.UTC)
	if q.Cost != 0 || q.ListCost != 0 {
		t.Fatalf("zero tokens should cost nothing: %+v", q)
	}
}

// ---------------------------------------------------------------------------
// Promotions
// ---------------------------------------------------------------------------

func TestOffPeakPromotion(t *testing.T) {
	pm := config.PriceModel{
		InputPerM: 100, OutputPerM: 100, Currency: "CNY",
		Promotions: []config.Promotion{{
			Kind: config.PromoOffPeak, Multiplier: 0.5,
			StartMinute: 0, EndMinute: 8 * 60, Note: "overnight half price",
		}},
	}
	tokens := Tokens{Input: 1_000_000}

	nightQ := PriceWith(pm, tokens, night, time.UTC)
	if !almost(nightQ.Cost, 50) {
		t.Fatalf("off-peak cost = %v, want 50", nightQ.Cost)
	}
	if !almost(nightQ.ListCost, 100) {
		t.Fatalf("list cost = %v, want 100", nightQ.ListCost)
	}
	if !almost(nightQ.DiscountPct, 50) {
		t.Fatalf("discount = %v, want 50", nightQ.DiscountPct)
	}
	if len(nightQ.Applied) != 1 || nightQ.Applied[0].Kind != config.PromoOffPeak {
		t.Fatalf("promotion not recorded: %+v", nightQ.Applied)
	}

	noonQ := PriceWith(pm, tokens, noon, time.UTC)
	if !almost(noonQ.Cost, 100) {
		t.Fatalf("peak cost = %v, want 100", noonQ.Cost)
	}
	if len(noonQ.Applied) != 0 {
		t.Fatalf("promotion should not apply at noon: %+v", noonQ.Applied)
	}
}

// TestOffPeakWindowWrappingMidnight covers the window shape that a naive
// comparison gets wrong.
func TestOffPeakWindowWrappingMidnight(t *testing.T) {
	pm := config.PriceModel{
		InputPerM: 100,
		Promotions: []config.Promotion{{
			Kind: config.PromoOffPeak, Multiplier: 0.5,
			StartMinute: 22 * 60, EndMinute: 6 * 60, // 22:00 -> 06:00
		}},
	}
	tokens := Tokens{Input: 1_000_000}

	inWindow := []time.Time{
		time.Date(2026, 3, 1, 23, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 1, 2, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 1, 5, 59, 0, 0, time.UTC),
	}
	outWindow := []time.Time{
		time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 1, 6, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 1, 21, 59, 0, 0, time.UTC),
	}
	for _, at := range inWindow {
		if q := PriceWith(pm, tokens, at, time.UTC); !almost(q.Cost, 50) {
			t.Fatalf("expected the wrapped window to apply at %s, got %v", at, q.Cost)
		}
	}
	for _, at := range outWindow {
		if q := PriceWith(pm, tokens, at, time.UTC); !almost(q.Cost, 100) {
			t.Fatalf("expected the wrapped window not to apply at %s, got %v", at, q.Cost)
		}
	}
}

func TestVolumePromotion(t *testing.T) {
	pm := config.PriceModel{
		InputPerM: 100,
		Promotions: []config.Promotion{{
			Kind: config.PromoVolume, Multiplier: 0.8, MinTokens: 1_000_000,
		}},
	}
	small := PriceWith(pm, Tokens{Input: 100_000}, noon, time.UTC)
	if !almost(small.Cost, 10) {
		t.Fatalf("below the threshold should not discount: %v", small.Cost)
	}
	big := PriceWith(pm, Tokens{Input: 2_000_000}, noon, time.UTC)
	if !almost(big.Cost, 160) {
		t.Fatalf("above the threshold should discount 20%%: %v", big.Cost)
	}
}

// TestSubscriptionPromotion verifies the break-even modelling: a monthly fee
// buying an allowance is converted into an effective multiplier.
func TestSubscriptionPromotion(t *testing.T) {
	// List price: 100 CNY per million. Plan: 50 CNY for 2M tokens, so the
	// plan's effective rate is 25 per million == a 0.25 multiplier against
	// the list price. A 1M-token request therefore costs 25. This is the
	// subscription break-even the comparison view needs: the same request
	// costs 100 on pay-as-you-go and 25 inside the plan.
	pm := config.PriceModel{
		InputPerM: 100, OutputPerM: 0,
		Promotions: []config.Promotion{{
			Kind: config.PromoSubscribe, MonthlyFee: 50, IncludedTokens: 2_000_000,
			Note: "monthly plan",
		}},
	}
	q := PriceWith(pm, Tokens{Input: 1_000_000}, noon, time.UTC)
	if !almost(q.ListCost, 100) {
		t.Fatalf("list cost = %v", q.ListCost)
	}
	if !almost(q.Cost, 25) {
		t.Fatalf("subscription cost = %v, want 25", q.Cost)
	}
	if len(q.Applied) != 1 || q.Applied[0].Kind != config.PromoSubscribe {
		t.Fatalf("subscription promotion not recorded: %+v", q.Applied)
	}
	if !almost(q.Applied[0].Multiplier, 0.25) {
		t.Fatalf("effective multiplier = %v, want 0.25", q.Applied[0].Multiplier)
	}
}

func TestStackedPromotions(t *testing.T) {
	pm := config.PriceModel{
		InputPerM: 100,
		Promotions: []config.Promotion{
			{Kind: config.PromoOffPeak, Multiplier: 0.5, StartMinute: 0, EndMinute: 8 * 60},
			{Kind: config.PromoVolume, Multiplier: 0.9, MinTokens: 1000},
		},
	}
	q := PriceWith(pm, Tokens{Input: 1_000_000}, night, time.UTC)
	if !almost(q.Cost, 45) {
		t.Fatalf("stacked promotions = %v, want 45", q.Cost)
	}
	if len(q.Applied) != 2 {
		t.Fatalf("expected both promotions recorded: %+v", q.Applied)
	}
}

// TestEffectiveUnitPriceIsSortable verifies that the comparison metric
// collapses a rate pair into one number that orders channels correctly.
func TestEffectiveUnitPriceIsSortable(t *testing.T) {
	cheap := config.PriceModel{InputPerM: 1, OutputPerM: 2}
	dear := config.PriceModel{InputPerM: 10, OutputPerM: 20}
	tokens := Tokens{Input: 1_000_000, Output: 1_000_000}
	uc := EffectiveUnitPrice(cheap, tokens, noon, time.UTC)
	ud := EffectiveUnitPrice(dear, tokens, noon, time.UTC)
	if !(uc < ud) {
		t.Fatalf("effective unit price did not order channels: %v vs %v", uc, ud)
	}
	if !almost(uc, 1.5) {
		t.Fatalf("blended unit price = %v, want 1.5", uc)
	}
}

func TestEffectiveUnitPriceDefaultMix(t *testing.T) {
	pm := config.PriceModel{InputPerM: 10, OutputPerM: 20}
	// With no token information the metric must still be meaningful (a 1:1 mix).
	got := EffectiveUnitPrice(pm, Tokens{}, noon, time.UTC)
	if !almost(got, 15) {
		t.Fatalf("default mix unit price = %v, want 15", got)
	}
}

// ---------------------------------------------------------------------------
// Catalogue
// ---------------------------------------------------------------------------

func TestPricerLookupAndSet(t *testing.T) {
	p := NewPricer([]config.PriceEntry{
		{Channel: "a", Model: "gpt-4o", Price: config.PriceModel{InputPerM: 10, OutputPerM: 30, Currency: "CNY"}},
		{Channel: "b", Model: "gpt-4o", Price: config.PriceModel{InputPerM: 5, OutputPerM: 15}},
	}, time.UTC)

	if pm, ok := p.Lookup("a", "gpt-4o"); !ok || pm.InputPerM != 10 {
		t.Fatalf("lookup a failed: %+v %v", pm, ok)
	}
	if _, ok := p.Lookup("a", "unknown"); ok {
		t.Fatal("expected a miss for an unknown model")
	}
	// An omitted currency defaults rather than being blank.
	if pm, _ := p.Lookup("b", "gpt-4o"); pm.Currency != "CNY" {
		t.Fatalf("expected the default currency, got %q", pm.Currency)
	}

	p.Set("c", "gpt-4o", config.PriceModel{InputPerM: 1})
	if pm, ok := p.Lookup("c", "gpt-4o"); !ok || pm.InputPerM != 1 {
		t.Fatal("Set did not take effect")
	}

	models := p.Models("a")
	if len(models) != 1 || models[0] != "gpt-4o" {
		t.Fatalf("Models(a) = %v", models)
	}
}

func TestPricerQuoteUnknownModel(t *testing.T) {
	p := NewPricer(nil, time.UTC)
	q := p.Quote("a", "nope", Tokens{Input: 100}, noon)
	if q.Basis != "unknown" {
		t.Fatalf("basis = %q", q.Basis)
	}
	if q.Cost != 0 {
		t.Fatalf("an unpriced model should cost 0, got %v", q.Cost)
	}
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

// TestNormalizeMultiplierScheme reproduces the api-price-monitor conversion:
// price = base * modelRatio * groupRatio, output = input * completionRatio.
func TestNormalizeMultiplierScheme(t *testing.T) {
	pm, err := Normalize(RawPrice{
		Scheme:          "multiplier",
		BasePricePerM:   2.0,
		ModelRatio:      1.5,
		GroupRatio:      0.8,
		CompletionRatio: 3.0,
		Currency:        "USD",
		ExchangeRate:    7.0,
	})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	wantIn := 2.0 * 1.5 * 0.8 * 7.0 // 16.8
	if !almost(pm.InputPerM, wantIn) {
		t.Fatalf("input = %v, want %v", pm.InputPerM, wantIn)
	}
	if !almost(pm.OutputPerM, wantIn*3.0) {
		t.Fatalf("output = %v, want %v", pm.OutputPerM, wantIn*3.0)
	}
	if !almost(pm.CompletionRatio, 3.0) {
		t.Fatalf("completion ratio not preserved: %v", pm.CompletionRatio)
	}
}

func TestNormalizeDefaultsToOne(t *testing.T) {
	pm, err := Normalize(RawPrice{Scheme: "multiplier", BasePricePerM: 2, Currency: "USD"})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if !almost(pm.InputPerM, 2) || !almost(pm.OutputPerM, 2) {
		t.Fatalf("expected ratio 1 defaults, got %+v", pm)
	}
}

func TestNormalizeFlatScheme(t *testing.T) {
	pm, err := Normalize(RawPrice{Scheme: "flat", InputPerM: 10, CompletionRatio: 2})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if !almost(pm.InputPerM, 10) || !almost(pm.OutputPerM, 20) {
		t.Fatalf("flat scheme wrong: %+v", pm)
	}
}

// TestNormalizePerRequest verifies that a per-request charge becomes an
// equivalent per-million rate for the stated typical mix.
func TestNormalizePerRequest(t *testing.T) {
	pm, err := Normalize(RawPrice{
		Scheme: "per_request", PerRequestPrice: 1.0,
		TypicalInput: 10_000, TypicalOutput: 10_000,
	})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	// 1.0 per request over 20k tokens == 50 per million.
	if !almost(pm.InputPerM, 50) {
		t.Fatalf("per-request conversion = %v, want 50", pm.InputPerM)
	}
}

func TestNormalizePerRequestNeedsMix(t *testing.T) {
	if _, err := Normalize(RawPrice{Scheme: "per_request", PerRequestPrice: 1}); err == nil {
		t.Fatal("expected an error when no typical mix is supplied")
	}
}

// TestNormalizeTiered verifies the volume-weighted collapse of a tier table.
func TestNormalizeTiered(t *testing.T) {
	pm, err := Normalize(RawPrice{
		Scheme: "tiered",
		Tiers: []Tier{
			{UpToTokens: 1_000_000, InputPerM: 10},
			{UpToTokens: 0, InputPerM: 5}, // and above
		},
		TypicalInput: 2_000_000,
	})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	// Half at 10, half at 5 -> 7.5.
	if !almost(pm.InputPerM, 7.5) {
		t.Fatalf("tiered average = %v, want 7.5", pm.InputPerM)
	}
}

func TestNormalizeTieredNeedsTiers(t *testing.T) {
	if _, err := Normalize(RawPrice{Scheme: "tiered"}); err == nil {
		t.Fatal("expected an error for a tiered scheme with no tiers")
	}
}

func TestNormalizeUnknownScheme(t *testing.T) {
	if _, err := Normalize(RawPrice{Scheme: "magic"}); err == nil {
		t.Fatal("expected an error for an unknown scheme")
	}
}

func TestNormalizeAppliesExchangeRate(t *testing.T) {
	usd, _ := Normalize(RawPrice{Scheme: "flat", InputPerM: 1, Currency: "USD", ExchangeRate: 7.2})
	cny, _ := Normalize(RawPrice{Scheme: "flat", InputPerM: 1, Currency: "CNY"})
	if !almost(usd.InputPerM, 7.2) {
		t.Fatalf("exchange rate not applied: %v", usd.InputPerM)
	}
	if !almost(cny.InputPerM, 1) {
		t.Fatalf("rate 0 should mean no conversion, got %v", cny.InputPerM)
	}
}

func TestCurrencyRate(t *testing.T) {
	if got := CurrencyRate("USD", "CNY", 7.1); !almost(got, 7.1) {
		t.Fatalf("USD->CNY = %v", got)
	}
	if got := CurrencyRate("CNY", "USD", 7.1); !almost(got, 1/7.1) {
		t.Fatalf("CNY->USD = %v", got)
	}
	if got := CurrencyRate("CNY", "CNY", 7.1); !almost(got, 1) {
		t.Fatalf("same currency = %v", got)
	}
	// A missing rate falls back to a sensible default instead of dividing by 0.
	if got := CurrencyRate("USD", "CNY", 0); !almost(got, 7.1) {
		t.Fatalf("default USD->CNY = %v", got)
	}
}

// TestNormalizeThenPrice is an end-to-end sanity check that a normalized price
// produces the expected cash amount.
func TestNormalizeThenPrice(t *testing.T) {
	pm, err := Normalize(RawPrice{
		Scheme: "multiplier", BasePricePerM: 2, ModelRatio: 1, GroupRatio: 1,
		CompletionRatio: 2, Currency: "USD", ExchangeRate: 7.0,
	})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	// 14 CNY/M in, 28 CNY/M out.
	q := PriceWith(pm, Tokens{Input: 1_000_000, Output: 1_000_000}, noon, time.UTC)
	if !almost(q.Cost, 42) {
		t.Fatalf("cost = %v, want 42", q.Cost)
	}
}

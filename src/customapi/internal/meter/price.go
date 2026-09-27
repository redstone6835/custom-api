// Package meter turns token counts into money.
//
// It also owns the project's price *normalisation* concern: upstream pricing
// arrives in several incompatible shapes (multiplier tables, flat per-million
// rates, per-request charges, tiered expressions, subscription plans), and the
// customs gateway must reduce all of them to a single comparable number - the
// effective price for a given input/output token mix at a given time.
package meter

import (
	"fmt"
	"math"
	"time"

	"github.com/redstone/customapi/internal/config"
)

// Tokens is a token mix to price.
type Tokens struct {
	Input  int64
	Output int64
}

// Total returns the combined token count.
func (t Tokens) Total() int64 { return t.Input + t.Output }

// Quote is the priced result for a token mix.
type Quote struct {
	// ListCost is the undiscounted cost.
	ListCost float64 `json:"list_cost"`
	// Cost is the cost after promotions.
	Cost float64 `json:"cost"`
	// Currency of both amounts.
	Currency string `json:"currency"`
	// DiscountPct is the effective discount, 0..100.
	DiscountPct float64 `json:"discount_pct"`
	// InputCost and OutputCost are the discounted components.
	InputCost  float64 `json:"input_cost"`
	OutputCost float64 `json:"output_cost"`
	// Applied lists the promotions that fired, for auditability.
	Applied []AppliedPromotion `json:"applied,omitempty"`
	// Basis describes how the price was obtained.
	Basis string `json:"basis"`
}

// AppliedPromotion records one promotion that reduced the price.
type AppliedPromotion struct {
	Kind       config.PromotionKind `json:"kind"`
	Multiplier float64              `json:"multiplier"`
	Note       string               `json:"note,omitempty"`
}

// Pricer prices token mixes using a catalogue of normalized prices.
type Pricer struct {
	// catalogue maps "channel\x00model" to a normalized price.
	catalogue map[string]config.PriceModel
	// location is the timezone used for off-peak windows.
	location *time.Location
	// defaultCurrency is used when a price omits its currency.
	defaultCurrency string
}

// NewPricer builds a pricer from price entries.
func NewPricer(entries []config.PriceEntry, tz *time.Location) *Pricer {
	if tz == nil {
		tz = time.UTC
	}
	p := &Pricer{
		catalogue:       make(map[string]config.PriceModel, len(entries)),
		location:        tz,
		defaultCurrency: "CNY",
	}
	for _, e := range entries {
		pm := e.Price
		if pm.Currency == "" {
			pm.Currency = p.defaultCurrency
		}
		p.catalogue[key(e.Channel, e.Model)] = pm
	}
	return p
}

func key(channel, model string) string { return channel + "\x00" + model }

// Lookup returns the normalized price for a channel/model pair.
func (p *Pricer) Lookup(channel, model string) (config.PriceModel, bool) {
	pm, ok := p.catalogue[key(channel, model)]
	return pm, ok
}

// Set inserts or replaces a price at runtime (used by the intelligence layer
// when it refreshes the catalogue without a restart).
func (p *Pricer) Set(channel, model string, pm config.PriceModel) {
	if pm.Currency == "" {
		pm.Currency = p.defaultCurrency
	}
	p.catalogue[key(channel, model)] = pm
}

// Models returns every priced model for a channel.
func (p *Pricer) Models(channel string) []string {
	var out []string
	for k := range p.catalogue {
		if len(k) > len(channel) && k[:len(channel)] == channel && k[len(channel)] == 0 {
			out = append(out, k[len(channel)+1:])
		}
	}
	return out
}

// Quote prices a token mix at a point in time.
//
// Time-dependent promotions use at; volume promotions use tokens.Total().
func (p *Pricer) Quote(channel, model string, tokens Tokens, at time.Time) Quote {
	pm, ok := p.Lookup(channel, model)
	if !ok {
		return Quote{Basis: "unknown", Currency: p.defaultCurrency}
	}
	return PriceWith(pm, tokens, at, p.location)
}

// PriceWith applies a normalized price plus its promotions to a token mix.
func PriceWith(pm config.PriceModel, tokens Tokens, at time.Time, loc *time.Location) Quote {
	if loc == nil {
		loc = time.UTC
	}
	currency := pm.Currency
	if currency == "" {
		currency = "CNY"
	}
	inCost := float64(tokens.Input) / 1e6 * pm.InputPerM
	outCost := float64(tokens.Output) / 1e6 * pm.OutputPerM
	list := inCost + outCost

	mult := 1.0
	var applied []AppliedPromotion
	for _, promo := range pm.Promotions {
		m, ok := promotionMultiplier(promo, pm, tokens, at, loc)
		if !ok {
			continue
		}
		mult *= m
		applied = append(applied, AppliedPromotion{Kind: promo.Kind, Multiplier: m, Note: promo.Note})
	}
	cost := list * mult
	discount := 0.0
	if list > 0 {
		discount = (1 - cost/list) * 100
	}
	return Quote{
		ListCost:    round6(list),
		Cost:        round6(cost),
		Currency:    currency,
		DiscountPct: round4(discount),
		InputCost:   round6(inCost * mult),
		OutputCost:  round6(outCost * mult),
		Applied:     applied,
		Basis:       "catalogue",
	}
}

// EffectiveUnitPrice returns the blended price per million tokens for a mix.
//
// This is the number the comparison UI shows: it collapses an input/output
// rate pair plus every active promotion into one scalar that can be sorted.
func EffectiveUnitPrice(pm config.PriceModel, tokens Tokens, at time.Time, loc *time.Location) float64 {
	if tokens.Total() == 0 {
		// Fall back to a 1:1 mix so the number is still meaningful.
		tokens = Tokens{Input: 500_000, Output: 500_000}
	}
	q := PriceWith(pm, tokens, at, loc)
	return q.Cost / (float64(tokens.Total()) / 1e6)
}

// promotionMultiplier evaluates a promotion, reporting whether it applies.
func promotionMultiplier(p config.Promotion, pm config.PriceModel, tokens Tokens, at time.Time, loc *time.Location) (float64, bool) {
	m := p.Multiplier
	if m <= 0 {
		m = 1
	}
	switch p.Kind {
	case config.PromoOffPeak:
		if inWindow(at.In(loc), p.StartMinute, p.EndMinute) {
			return m, true
		}
		return 1, false
	case config.PromoVolume:
		if tokens.Total() >= p.MinTokens && p.MinTokens > 0 {
			return m, true
		}
		return 1, false
	case config.PromoSubscribe:
		if p.IncludedTokens <= 0 {
			return 1, false
		}
		// Amortised subscription: the monthly fee buys IncludedTokens, so
		// the effective multiplier is (fee / included tokens) relative to the
		// pay-as-you-go rate for this mix.
		listCost := float64(tokens.Input)/1e6*pm.InputPerM + float64(tokens.Output)/1e6*pm.OutputPerM
		if listCost <= 0 {
			return 1, false
		}
		perToken := p.MonthlyFee / float64(p.IncludedTokens)
		subCost := perToken * float64(tokens.Total())
		return subCost / listCost, true
	default:
		return 1, false
	}
}

// inWindow reports whether t falls in [start,end) minutes past midnight,
// supporting windows that wrap past midnight.
func inWindow(t time.Time, start, end int) bool {
	if start == end {
		return true // a full-day window
	}
	minutes := t.Hour()*60 + t.Minute()
	if start < end {
		return minutes >= start && minutes < end
	}
	return minutes >= start || minutes < end
}

func round6(v float64) float64 { return math.Round(v*1e6) / 1e6 }
func round4(v float64) float64 { return math.Round(v*1e4) / 1e4 }

// ---------------------------------------------------------------------------
// Price normalisation
// ---------------------------------------------------------------------------

// RawPrice is an upstream price in whatever shape the upstream published it.
type RawPrice struct {
	// Scheme selects the conversion: "multiplier", "flat", "per_request",
	// "tiered" or "manual".
	Scheme string
	// InputPerM is the paid price per million input tokens (schemes where the
	// upstream states a cash rate directly).
	InputPerM float64
	// CompletionRatio is the output/input ratio for multiplier schemes, where
	// the upstream expresses input as a multiple of a reference price.
	CompletionRatio float64
	// ModelRatio is the upstream's per-model multiplier against a base price.
	ModelRatio float64
	// BasePricePerM is the reference price per million tokens that ModelRatio
	// multiplies. new-api calls this "模型固定价格/倍率" base.
	BasePricePerM float64
	// GroupRatio is a per-user-group multiplier applied on top.
	GroupRatio float64
	// PerRequestPrice is the charge per request for per_request schemes.
	PerRequestPrice float64
	// Currency of the raw numbers.
	Currency string
	// TypicalInput / TypicalOutput describe the token mix used to convert a
	// per-request price into per-million rates.
	TypicalInput  int64
	TypicalOutput int64
	// Tiers holds tiered pricing rows.
	Tiers []Tier
	// ExchangeRate converts from the raw currency to the catalogue currency.
	ExchangeRate float64
	// Source documents where the number came from.
	Source string
}

// Tier is one row of a tiered price expression.
type Tier struct {
	// UpToTokens is the inclusive upper bound of this tier; 0 means "and
	// above" when it is the last tier.
	UpToTokens int64
	// InputPerM / OutputPerM apply within the tier.
	InputPerM  float64
	OutputPerM float64
	// Multiplier alternative to explicit rates.
	Multiplier float64
}

// Normalize reduces a RawPrice to the catalogue shape.
//
// This is the "归一化口径" the project reuses from api-price-monitor, extended
// with tiered and per-request handling.
func Normalize(r RawPrice) (config.PriceModel, error) {
	rate := r.ExchangeRate
	if rate == 0 {
		rate = 1
	}
	pm := config.PriceModel{
		Currency: r.Currency,
		Source:   r.Source,
		Scheme:   r.Scheme,
	}
	switch r.Scheme {
	case "multiplier":
		// price = base * modelRatio * groupRatio, with output derived from
		// the completion ratio.
		base := r.BasePricePerM
		mr := r.ModelRatio
		if mr == 0 {
			mr = 1
		}
		gr := r.GroupRatio
		if gr == 0 {
			gr = 1
		}
		in := base * mr * gr
		cr := r.CompletionRatio
		if cr == 0 {
			cr = 1
		}
		pm.InputPerM = in * rate
		pm.OutputPerM = in * cr * rate
		pm.CompletionRatio = cr
	case "flat":
		pm.InputPerM = r.InputPerM * rate
		cr := r.CompletionRatio
		if cr == 0 {
			cr = 1
		}
		pm.OutputPerM = pm.InputPerM * cr
		pm.CompletionRatio = cr
	case "per_request":
		in := r.TypicalInput
		out := r.TypicalOutput
		if in == 0 && out == 0 {
			return pm, fmt.Errorf("meter: per_request scheme needs a typical token mix")
		}
		total := float64(in + out)
		if total <= 0 {
			return pm, fmt.Errorf("meter: per_request scheme needs a non-zero token mix")
		}
		// Spread the per-request charge across the typical mix, attributing
		// it proportionally to the two sides.
		perToken := r.PerRequestPrice / total * rate
		pm.InputPerM = perToken * 1e6
		pm.OutputPerM = perToken * 1e6
		pm.CompletionRatio = 1
	case "tiered":
		if len(r.Tiers) == 0 {
			return pm, fmt.Errorf("meter: tiered scheme needs at least one tier")
		}
		// Collapse tiers to a volume-weighted average over the typical mix so
		// that a single comparable pair of rates exists. The full tier table
		// is preserved by the caller if it wants exact billing.
		var (
			inSum, outSum float64
			weight        float64
			remaining     = r.TypicalInput + r.TypicalOutput
		)
		if remaining <= 0 {
			remaining = 1_000_000
		}
		for _, t := range r.Tiers {
			span := t.UpToTokens
			if span <= 0 || span > remaining {
				span = remaining
			}
			if span <= 0 {
				continue
			}
			w := float64(span)
			inSum += t.InputPerM * rate * w
			outSum += t.OutputPerM * rate * w
			weight += w
			remaining -= span
			if remaining <= 0 {
				break
			}
		}
		if weight == 0 {
			return pm, fmt.Errorf("meter: tiered scheme produced no weight")
		}
		pm.InputPerM = inSum / weight
		pm.OutputPerM = outSum / weight
	case "manual":
		pm.InputPerM = r.InputPerM * rate
		cr := r.CompletionRatio
		if cr == 0 {
			cr = 1
		}
		pm.OutputPerM = pm.InputPerM * cr
		pm.CompletionRatio = cr
	default:
		return pm, fmt.Errorf("meter: unknown price scheme %q", r.Scheme)
	}
	return pm, nil
}

// CurrencyRate returns a conversion factor between two currencies using a
// configurable USD/CNY rate.
func CurrencyRate(from, to string, usdCNY float64) float64 {
	if from == to {
		return 1
	}
	if usdCNY <= 0 {
		usdCNY = 7.1
	}
	switch {
	case from == "USD" && to == "CNY":
		return usdCNY
	case from == "CNY" && to == "USD":
		return 1 / usdCNY
	default:
		return 1
	}
}

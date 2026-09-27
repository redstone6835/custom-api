// Package config loads and validates the customs gateway configuration.
//
// The configuration is intentionally one flat JSON file plus environment
// overrides, so the whole gateway state is auditable and easy to diff.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Trust model
// ---------------------------------------------------------------------------

// Trust controls how much auditing a subject is exempted from.
//
// The project's core premise is "few subjects are trusted, everything else is
// untrusted by default". Trust NEVER disables metering or audit persistence;
// it only relaxes content inspection.
type Trust string

const (
	// TrustUntrusted is the default for every channel and every user.
	TrustUntrusted Trust = "untrusted"
	// TrustTrusted relaxes content inspection (fewer false positives, lower
	// latency) but keeps usage verification and audit recording enabled.
	TrustTrusted Trust = "trusted"
)

// Valid reports whether t is a recognised trust level.
func (t Trust) Valid() bool { return t == TrustUntrusted || t == TrustTrusted }

// ---------------------------------------------------------------------------
// Channel (upstream access point)
// ---------------------------------------------------------------------------

// Channel describes one upstream access point.
type Channel struct {
	// Name is the stable identifier used in routing and audit records.
	Name string `json:"name"`
	// BaseURL is the upstream API root, e.g. https://api.example.com
	BaseURL string `json:"base_url"`
	// APIKey is the upstream credential. It is never exposed to users.
	APIKey string `json:"api_key"`
	// Protocol is the wire protocol spoken by this channel: "openai" or
	// "anthropic". Empty means "openai".
	Protocol string `json:"protocol,omitempty"`
	// Models maps the canonical (user-facing) model name to the upstream's
	// own model identifier. An empty map means "pass through unchanged".
	Models map[string]string `json:"models,omitempty"`
	// Trust relaxes content inspection for this channel.
	Trust Trust `json:"trust,omitempty"`
	// Weight biases the router. Zero means default (1.0).
	Weight float64 `json:"weight,omitempty"`
	// Enabled allows disabling a channel without deleting it.
	Enabled *bool `json:"enabled,omitempty"`
	// Timeout overrides the per-request upstream timeout.
	Timeout Duration `json:"timeout,omitempty"`
	// Headers are extra headers to attach to upstream requests.
	Headers map[string]string `json:"headers,omitempty"`
	// Metadata carries free-form operator annotations (provider, notes...).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// IsEnabled reports whether the channel may receive traffic.
func (c Channel) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// TrustLevel returns the effective trust level.
func (c Channel) TrustLevel() Trust {
	if c.Trust == "" {
		return TrustUntrusted
	}
	return c.Trust
}

// UpstreamModel translates a canonical model name to the channel's own name.
//
// It returns "" when the channel is known not to serve the model, which is what
// lets the router exclude a channel rather than sending it a model it does not
// have and returning an upstream error to the user.
//
// A channel with an empty Models map is treated as an explicit pass-through:
// it accepts whatever model name it is given. A channel with a non-empty map
// has declared its catalogue and is held to it.
func (c Channel) UpstreamModel(canonical string) string {
	if len(c.Models) == 0 {
		return canonical
	}
	if m, ok := c.Models[canonical]; ok {
		return m
	}
	return ""
}

// CanonicalModel is the inverse of UpstreamModel, used when fingerprinting a
// response whose model field was rewritten by the upstream.
func (c Channel) CanonicalModel(upstream string) string {
	for k, v := range c.Models {
		if v == upstream {
			return k
		}
	}
	return upstream
}

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

// User is a gateway client.
type User struct {
	// Name is the stable identifier recorded in audit records.
	Name string `json:"name"`
	// Token is the bearer credential the client presents.
	Token string `json:"token"`
	// Quota is the total allowance in quota units; 0 means unlimited.
	Quota int64 `json:"quota,omitempty"`
	// Period resets the consumed counter on a schedule: "none", "daily",
	// "weekly" or "monthly".
	Period string `json:"period,omitempty"`
	// Models restricts this user to a set of canonical models. Empty means
	// all models are allowed.
	Models []string `json:"models,omitempty"`
	// RateLimit is the sustained request rate (requests per second). Zero
	// disables rate limiting.
	RateLimit float64 `json:"rate_limit,omitempty"`
	// Burst is the rate limiter bucket size. Zero means 2x RateLimit.
	Burst int `json:"burst,omitempty"`
	// MaxConcurrent caps in-flight requests. Zero means unlimited.
	MaxConcurrent int `json:"max_concurrent,omitempty"`
	// Trust relaxes inbound/outbound content inspection for this user.
	Trust Trust `json:"trust,omitempty"`
	// Enabled allows suspending a user without deleting it.
	Enabled *bool `json:"enabled,omitempty"`
}

// IsEnabled reports whether the user may issue requests.
func (u User) IsEnabled() bool { return u.Enabled == nil || *u.Enabled }

// TrustLevel returns the effective trust level.
func (u User) TrustLevel() Trust {
	if u.Trust == "" {
		return TrustUntrusted
	}
	return u.Trust
}

// AllowsModel reports whether the user may call the given canonical model.
func (u User) AllowsModel(model string) bool {
	if len(u.Models) == 0 {
		return true
	}
	for _, m := range u.Models {
		if m == model {
			return true
		}
	}
	// Wildcard support: "gpt-*" style prefixes.
	for _, m := range u.Models {
		if strings.HasSuffix(m, "*") && strings.HasPrefix(model, strings.TrimSuffix(m, "*")) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Pricing
// ---------------------------------------------------------------------------

// PriceModel is the normalized price for one canonical model on one channel.
//
// The normalization "口径" mirrors api-price-monitor: every upstream pricing
// scheme (multiplier, flat, per-request, tiered expression) is reduced to a
// pair of per-million-token rates so that channels can be compared directly.
type PriceModel struct {
	// InputPerM is the price per million input tokens, in Currency.
	InputPerM float64 `json:"input_per_m"`
	// OutputPerM is the price per million output tokens, in Currency.
	OutputPerM float64 `json:"output_per_m"`
	// Currency is the unit of the two rates above, e.g. "CNY" or "USD".
	Currency string `json:"currency,omitempty"`
	// Scheme records how the raw upstream price was expressed:
	// "multiplier", "flat", "per_request", "tiered" or "manual".
	Scheme string `json:"scheme,omitempty"`
	// CompletionRatio is the raw ratio used by multiplier schemes, kept for
	// auditability of the normalization.
	CompletionRatio float64 `json:"completion_ratio,omitempty"`
	// Promotions are discounts that depend on time or volume.
	Promotions []Promotion `json:"promotions,omitempty"`
	// Source documents where the number came from (URL or "manual").
	Source string `json:"source,omitempty"`
	// UpdatedAt is when the price was last observed.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// PromotionKind enumerates the modelled discount mechanisms.
type PromotionKind string

const (
	// PromoOffPeak applies a multiplier inside a daily time window.
	PromoOffPeak PromotionKind = "off_peak"
	// PromoVolume applies a multiplier once usage exceeds a threshold.
	PromoVolume PromotionKind = "volume"
	// PromoSubscribe is a subscription plan amortised over an allowance.
	PromoSubscribe PromotionKind = "subscription"
)

// Promotion is one discount rule.
type Promotion struct {
	Kind PromotionKind `json:"kind"`
	// Multiplier scales the base price (0.8 == 20% off). Zero means 1.0.
	Multiplier float64 `json:"multiplier,omitempty"`
	// StartMinute/EndMinute bound an off-peak window as minutes past local
	// midnight. A window may wrap past midnight (start > end).
	StartMinute int `json:"start_minute,omitempty"`
	EndMinute   int `json:"end_minute,omitempty"`
	// MinTokens is the volume threshold for PromoVolume.
	MinTokens int64 `json:"min_tokens,omitempty"`
	// MonthlyFee and IncludedTokens describe a PromoSubscribe plan.
	MonthlyFee     float64 `json:"monthly_fee,omitempty"`
	IncludedTokens int64   `json:"included_tokens,omitempty"`
	// Note is a human-readable justification shown in the comparison UI.
	Note string `json:"note,omitempty"`
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

// Policy configures the audit engine.
type Policy struct {
	// Outbound rules guard the upstream against user abuse.
	Outbound OutboundPolicy `json:"outbound"`
	// Inbound rules guard the user against a hostile upstream.
	Inbound InboundPolicy `json:"inbound"`
	// Metering configures usage verification.
	Metering MeteringPolicy `json:"metering"`
}

// OutboundPolicy configures request-side inspection.
type OutboundPolicy struct {
	// BlockKeywords rejects a request containing any of these substrings.
	BlockKeywords []string `json:"block_keywords,omitempty"`
	// BlockPatterns rejects a request matching any regexp.
	BlockPatterns []string `json:"block_patterns,omitempty"`
	// DenyTools rejects these tool/function names outright.
	DenyTools []string `json:"deny_tools,omitempty"`
	// AllowTools, when non-empty, switches to allowlist mode: only these
	// tools may be called and everything else is denied.
	AllowTools []string `json:"allow_tools,omitempty"`
	// DenyPathPatterns flags dangerous paths inside tool arguments.
	DenyPathPatterns []string `json:"deny_path_patterns,omitempty"`
	// RedactPatterns are replaced before the request is persisted to audit.
	RedactPatterns []string `json:"redact_patterns,omitempty"`
	// Mode is "enforce" or "report"; report records but never blocks.
	Mode string `json:"mode,omitempty"`
}

// InboundPolicy configures response-side inspection.
type InboundPolicy struct {
	// InjectionPatterns detect prompt-injection attempts in model output.
	InjectionPatterns []string `json:"injection_patterns,omitempty"`
	// SecretPatterns detect leaked credentials in model output.
	SecretPatterns []string `json:"secret_patterns,omitempty"`
	// ToolCallPolicy is "off", "report" or "block" for upstream-suggested
	// tool calls.
	ToolCallPolicy string `json:"tool_call_policy,omitempty"`
	// Mode is "enforce" or "report".
	Mode string `json:"mode,omitempty"`
}

// MeteringPolicy configures usage verification.
type MeteringPolicy struct {
	// MinAbsoluteDelta is the absolute token difference below which a
	// deviation is treated as estimator noise, however large it looks in
	// relative terms. Together with Tolerance it prevents short responses from
	// generating false billing accusations.
	MinAbsoluteDelta int `json:"min_absolute_delta,omitempty"`
	// Tolerance is the allowed relative deviation between the upstream's
	// reported usage and the gateway's own recount before it is flagged.
	//
	// This must be set well above the local estimator's error, or honest
	// upstreams will be flagged constantly and the signal becomes noise. The
	// built-in estimator's worst observed error is about 45% on adversarial
	// content (dense digits, code, CJK) and under 20% on ordinary prose; the
	// default of 0.25 therefore sits inside the noise floor of an estimator
	// that is deliberately vocabulary-free, while still catching the kind of
	// inflated billing an access point would have to report to profit.
	Tolerance float64 `json:"tolerance,omitempty"`
	// FingerprintSampleRate is the fraction of requests that get an online
	// behavioural probe (0 disables, 1 probes everything).
	FingerprintSampleRate float64 `json:"fingerprint_sample_rate,omitempty"`
	// FingerprintThreshold is the JS-divergence above which a channel is
	// considered to be serving a different model.
	FingerprintThreshold float64 `json:"fingerprint_threshold,omitempty"`
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// Server configures listeners and storage.
type Server struct {
	// Listen is the user-facing address, e.g. 127.0.0.1:8080.
	Listen string `json:"listen"`
	// AdminListen is the management API/UI address.
	AdminListen string `json:"admin_listen,omitempty"`
	// AuditPath is the append-only audit log file.
	AuditPath string `json:"audit_path,omitempty"`
	// MeterPath is the JSONL metering ledger file.
	MeterPath string `json:"meter_path,omitempty"`
	// StatePath persists quota counters between restarts.
	StatePath string `json:"state_path,omitempty"`
	// PricePath is the price catalogue maintained by the intelligence layer.
	PricePath string `json:"price_path,omitempty"`
	// ScorePath is the channel scorecard produced by the intelligence layer.
	ScorePath string `json:"score_path,omitempty"`
	// UpstreamTimeout bounds a whole upstream exchange.
	UpstreamTimeout Duration `json:"upstream_timeout,omitempty"`
	// FailMode is "open" or "closed" when the audit engine itself errors.
	FailMode string `json:"fail_mode,omitempty"`
	// LogLevel is "debug", "info", "warn" or "error".
	LogLevel string `json:"log_level,omitempty"`
	// RouteStrategy is "cheapest", "best_score", "value", "weighted" or
	// "fixed".
	RouteStrategy string `json:"route_strategy,omitempty"`
	// AdminRemote allows the management API to answer callers that are not on
	// the loopback interface. It is off by default: the management API can
	// suspend users and read the audit ledger, so reaching it should be a
	// deliberate decision rather than a side effect of binding its listener to
	// a routable address.
	AdminRemote bool `json:"admin_remote,omitempty"`
	// AdminToken is the bearer credential for the management API. It is only
	// consulted when AdminRemote is on; loopback callers are trusted, because
	// anyone who can reach the loopback interface already controls the host.
	AdminToken string `json:"admin_token,omitempty"`
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

// Config is the whole gateway configuration.
type Config struct {
	// Comment is an operator note carried in the file.
	//
	// It exists because the parser rejects unknown fields (so that a typo in a
	// field name is a hard error rather than a silently ignored default), yet
	// operators need somewhere to document a deployment. One explicit
	// "_comment" field satisfies both. It accepts either a string or an array
	// of strings.
	Comment Comment `json:"_comment,omitempty"`

	Server Server `json:"server"`
	Policy Policy `json:"policy"`

	// Providers are upstream vendors with one or more API keys. Each key is
	// expanded into its own channel at load time; see provider.go.
	Providers []Provider `json:"providers,omitempty"`
	// Channels are single-endpoint upstreams configured directly. They remain
	// supported for one-off endpoints and for existing configurations.
	Channels []Channel `json:"channels,omitempty"`

	Users  []User       `json:"users"`
	Prices []PriceEntry `json:"prices,omitempty"`

	// Routing configures provider selection across protocols.
	Routing RoutingPolicy `json:"routing,omitempty"`
	// Discovery configures automatic upstream model discovery.
	Discovery DiscoveryPolicy `json:"discovery,omitempty"`
}

// PriceEntry binds a price to a channel/model pair.
type PriceEntry struct {
	Channel string     `json:"channel"`
	Model   string     `json:"model"`
	Price   PriceModel `json:"price"`
}

// Comment is a documentation-only field that accepts a string or an array of
// strings, so a configuration file can read naturally in either style.
type Comment []string

// UnmarshalJSON accepts a string, an array of strings, or null.
func (c *Comment) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*c = nil
		return nil
	}
	if strings.HasPrefix(trimmed, `"`) {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*c = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return fmt.Errorf("_comment must be a string or an array of strings: %w", err)
	}
	*c = arr
	return nil
}

// String renders the comment for display.
func (c Comment) String() string { return strings.Join(c, " ") }

// Duration is a JSON-friendly time.Duration ("30s", "2m").
type Duration time.Duration

// UnmarshalJSON accepts both a Go duration string and a number of seconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*d = 0
		return nil
	}
	if v, err := time.ParseDuration(s); err == nil {
		*d = Duration(v)
		return nil
	}
	var secs float64
	if _, err := fmt.Sscanf(s, "%g", &secs); err == nil {
		*d = Duration(time.Duration(secs * float64(time.Second)))
		return nil
	}
	return fmt.Errorf("invalid duration %q", s)
}

// MarshalJSON renders the duration as a Go duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

// ErrNoConfig reports a missing configuration file.
var ErrNoConfig = errors.New("config: file not found")

// Load reads a configuration file, applies defaults and validates it.
//
// Environment variables of the form CUSTOMS_<SECTION>_<FIELD> are applied
// afterwards, which keeps secrets (upstream API keys) out of the file.
func Load(path string) (*Config, error) { return LoadWithEnvFile(path, "") }

// LoadWithEnvFile is Load plus an optional KEY=VALUE secrets file.
//
// Precedence, lowest to highest: configuration file, environment, env file.
// The env file wins over the ambient environment because it is the more
// specific, explicitly requested source.
func LoadWithEnvFile(path, envFile string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNoConfig, path)
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	environ := os.Environ()
	if envFile != "" {
		pairs, err := LoadEnvFile(envFile)
		if err != nil {
			return nil, err
		}
		// The env file wins over the ambient environment, so it is applied last.
		for k, v := range pairs {
			environ = append(environ, k+"="+v)
		}
	}
	c.applyEnv(environ)
	c.applyProviderEnv(environ)
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// truthy interprets an environment value as a boolean, accepting the spellings
// an operator is likely to reach for in an env file.
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "y", "t":
		return true
	default:
		return false
	}
}

// applyEnv overlays environment variables onto the configuration.
//
// Supported forms:
//
//	CUSTOMS_SERVER_LISTEN
//	CUSTOMS_SERVER_ADMIN_REMOTE
//	CUSTOMS_SERVER_ADMIN_TOKEN
//	CUSTOMS_CHANNEL_<NAME>_APIKEY
//	CUSTOMS_CHANNEL_<NAME>_BASEURL
//	CUSTOMS_USER_<NAME>_TOKEN
func (c *Config) applyEnv(environ []string) {
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(k, "CUSTOMS_") {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(k, "CUSTOMS_"), "_")
		if len(parts) < 2 {
			continue
		}
		switch parts[0] {
		case "SERVER":
			switch strings.Join(parts[1:], "_") {
			case "LISTEN":
				c.Server.Listen = v
			case "ADMIN_LISTEN":
				c.Server.AdminListen = v
			case "AUDIT_PATH":
				c.Server.AuditPath = v
			case "METER_PATH":
				c.Server.MeterPath = v
			case "STATE_PATH":
				c.Server.StatePath = v
			case "LOG_LEVEL":
				c.Server.LogLevel = v
			case "FAIL_MODE":
				c.Server.FailMode = v
			case "ROUTE_STRATEGY":
				c.Server.RouteStrategy = v
			case "ADMIN_REMOTE":
				c.Server.AdminRemote = truthy(v)
			case "ADMIN_TOKEN":
				c.Server.AdminToken = v
			}
		case "CHANNEL":
			if len(parts) < 3 {
				continue
			}
			field := parts[len(parts)-1]
			name := strings.Join(parts[1:len(parts)-1], "_")
			for i := range c.Channels {
				if strings.EqualFold(c.Channels[i].Name, name) {
					switch field {
					case "APIKEY":
						c.Channels[i].APIKey = v
					case "BASEURL":
						c.Channels[i].BaseURL = v
					}
				}
			}
		case "USER":
			if len(parts) < 3 || parts[len(parts)-1] != "TOKEN" {
				continue
			}
			name := strings.Join(parts[1:len(parts)-1], "_")
			for i := range c.Users {
				if strings.EqualFold(c.Users[i].Name, name) {
					c.Users[i].Token = v
				}
			}
		}
	}
}

// ApplyDefaults fills unset fields with safe defaults.
func (c *Config) ApplyDefaults() {
	s := &c.Server
	if s.Listen == "" {
		s.Listen = "127.0.0.1:8080"
	}
	if s.AdminListen == "" {
		s.AdminListen = "127.0.0.1:8081"
	}
	if s.AuditPath == "" {
		s.AuditPath = "var/audit.jsonl"
	}
	if s.MeterPath == "" {
		s.MeterPath = "var/meter.jsonl"
	}
	if s.StatePath == "" {
		s.StatePath = "var/state.json"
	}
	if s.PricePath == "" {
		s.PricePath = "etc/prices.json"
	}
	if s.ScorePath == "" {
		s.ScorePath = "var/scores.json"
	}
	if s.UpstreamTimeout == 0 {
		s.UpstreamTimeout = Duration(120 * time.Second)
	}
	if s.FailMode == "" {
		s.FailMode = "open"
	}
	if s.LogLevel == "" {
		s.LogLevel = "info"
	}
	if s.RouteStrategy == "" {
		s.RouteStrategy = "value"
	}

	p := &c.Policy
	if p.Outbound.Mode == "" {
		p.Outbound.Mode = "enforce"
	}
	if p.Inbound.Mode == "" {
		p.Inbound.Mode = "enforce"
	}
	if p.Inbound.ToolCallPolicy == "" {
		p.Inbound.ToolCallPolicy = "block"
	}
	if p.Metering.Tolerance == 0 {
		p.Metering.Tolerance = 0.25
	}
	if p.Metering.MinAbsoluteDelta == 0 {
		p.Metering.MinAbsoluteDelta = 8
	}
	if p.Metering.FingerprintThreshold == 0 {
		p.Metering.FingerprintThreshold = 0.35
	}

	// Providers need the same normalisation as channels: the expansion
	// multiplies the provider weight by each key weight, so a provider left at
	// weight 0 would silently produce zero-weight channels that a weighted
	// strategy never selects.
	for i := range c.Providers {
		p := &c.Providers[i]
		if p.Protocol == "" {
			p.Protocol = "openai"
		}
		if p.Trust == "" {
			p.Trust = TrustUntrusted
		}
		if p.Weight == 0 {
			p.Weight = 1
		}
		if p.Timeout == 0 {
			p.Timeout = s.UpstreamTimeout
		}
		if p.Discover != nil && p.Discover.Interval == 0 {
			p.Discover.Interval = c.Discovery.Interval
		}
	}
	for i := range c.Channels {
		ch := &c.Channels[i]
		if ch.Protocol == "" {
			ch.Protocol = "openai"
		}
		if ch.Trust == "" {
			ch.Trust = TrustUntrusted
		}
		if ch.Weight == 0 {
			ch.Weight = 1
		}
		if ch.Timeout == 0 {
			ch.Timeout = s.UpstreamTimeout
		}
	}
	for i := range c.Users {
		u := &c.Users[i]
		if u.Trust == "" {
			u.Trust = TrustUntrusted
		}
		if u.Period == "" {
			u.Period = "none"
		}
	}
}

// Validate rejects configurations that cannot work.
func (c *Config) Validate() error {
	var errs []string
	if c.Server.Listen == "" {
		errs = append(errs, "server.listen must not be empty")
	}
	switch c.Server.FailMode {
	case "open", "closed":
	default:
		errs = append(errs, fmt.Sprintf("server.fail_mode %q must be open or closed", c.Server.FailMode))
	}
	switch c.Server.RouteStrategy {
	case "cheapest", "best_score", "value", "weighted", "fixed":
	default:
		errs = append(errs, fmt.Sprintf("server.route_strategy %q is not recognised", c.Server.RouteStrategy))
	}
	if len(c.Channels) == 0 && len(c.Providers) == 0 {
		errs = append(errs, "at least one channel or provider is required")
	}
	seenChan := map[string]bool{}
	for i, ch := range c.Channels {
		if ch.Name == "" {
			errs = append(errs, fmt.Sprintf("channels[%d].name must not be empty", i))
		} else if seenChan[ch.Name] {
			errs = append(errs, fmt.Sprintf("duplicate channel %q", ch.Name))
		}
		seenChan[ch.Name] = true
		if ch.BaseURL == "" {
			errs = append(errs, fmt.Sprintf("channel %q: base_url must not be empty", ch.Name))
		}
		if !isKnownProtocol(ch.Protocol) {
			errs = append(errs, fmt.Sprintf("channel %q: protocol %q must be openai, responses or anthropic", ch.Name, ch.Protocol))
		}
		if !ch.Trust.Valid() {
			errs = append(errs, fmt.Sprintf("channel %q: invalid trust %q", ch.Name, ch.Trust))
		}
	}
	seenUser := map[string]bool{}
	seenToken := map[string]bool{}
	for i, u := range c.Users {
		if u.Name == "" {
			errs = append(errs, fmt.Sprintf("users[%d].name must not be empty", i))
		} else if seenUser[u.Name] {
			errs = append(errs, fmt.Sprintf("duplicate user %q", u.Name))
		}
		seenUser[u.Name] = true
		if u.Token == "" {
			errs = append(errs, fmt.Sprintf("user %q: token must not be empty", u.Name))
		} else if seenToken[u.Token] {
			errs = append(errs, fmt.Sprintf("duplicate user token for %q", u.Name))
		}
		seenToken[u.Token] = true
		switch u.Period {
		case "none", "daily", "weekly", "monthly":
		default:
			errs = append(errs, fmt.Sprintf("user %q: period %q must be none/daily/weekly/monthly", u.Name, u.Period))
		}
		if !u.Trust.Valid() {
			errs = append(errs, fmt.Sprintf("user %q: invalid trust %q", u.Name, u.Trust))
		}
	}
	errs = append(errs, c.validateProviders()...)
	errs = append(errs, c.validateRouting()...)
	if len(errs) > 0 {
		return fmt.Errorf("config: %s", strings.Join(errs, "; "))
	}
	return nil
}

// validateRouting checks the routing policy.
func (c *Config) validateRouting() []string {
	var errs []string
	// "quota" is a provider-side refusal to serve (its account cannot pay), not
	// a client error, so it is a first-class retry class: the next provider can
	// serve the same request.
	known := map[string]bool{"5xx": true, "429": true, "timeout": true, "network": true, "quota": true}
	for _, class := range c.Routing.RetryOn {
		if !known[class] {
			errs = append(errs, fmt.Sprintf("routing.retry_on %q must be one of 5xx, 429, timeout, network, quota", class))
		}
	}
	// A routing group that no provider belongs to would silently match nothing,
	// which is a configuration mistake worth surfacing.
	if len(c.Routing.Groups) > 0 {
		available := map[string]bool{}
		for _, g := range c.GroupNames() {
			available[g] = true
		}
		for _, g := range c.Routing.Groups {
			if !available[g] {
				errs = append(errs, fmt.Sprintf("routing.groups references unknown group %q", g))
			}
		}
	}
	return errs
}

// ChannelByName returns the channel with the given name.
func (c *Config) ChannelByName(name string) (Channel, bool) {
	for _, ch := range c.Channels {
		if ch.Name == name {
			return ch, true
		}
	}
	return Channel{}, false
}

// UserByToken returns the user owning the given bearer token.
func (c *Config) UserByToken(token string) (User, bool) {
	if token == "" {
		return User{}, false
	}
	for _, u := range c.Users {
		if subtleEqual(u.Token, token) {
			return u, true
		}
	}
	return User{}, false
}

// PriceFor returns the advertised price for a channel/model pair.
func (c *Config) PriceFor(channel, model string) (PriceModel, bool) {
	for _, p := range c.Prices {
		if p.Channel == channel && p.Model == model {
			return p.Price, true
		}
	}
	return PriceModel{}, false
}

// Resolve makes a path absolute relative to a base directory.
func Resolve(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// subtleEqual compares two secrets without leaking length-independent timing.
func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

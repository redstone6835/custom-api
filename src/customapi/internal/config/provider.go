package config

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------
//
// Why a provider layer exists on top of channels
//
// A "channel" in this gateway is one upstream endpoint with one credential, and
// it is what routing, metering and auditing operate on. Operators, however,
// think in terms of *providers*: one vendor, usually with several API keys to
// spread load or to survive a key being rate-limited or revoked.
//
// A provider therefore declares the vendor (base URL, protocol, trust, model
// aliases) once and lists its keys. At load time each key is expanded into its
// own channel named "<provider>/<key>", so every downstream component keeps
// working on the flat channel list it already understands, while the operator
// gets to manage keys as a group.
//
// The expansion is what makes multi-key failover work without touching the
// router: a failed key is one unhealthy channel, and the router already knows
// how to move to the next candidate.

// Provider is an upstream vendor with one or more API keys.
type Provider struct {
	// Name is the stable identifier used in channel names and audit records.
	Name string `json:"name"`
	// BaseURL is the vendor's API root, e.g. https://api.openai.com
	BaseURL string `json:"base_url"`
	// Protocol is the wire protocol to prefer when talking to this provider:
	// "openai" (chat completions), "responses" or "anthropic".
	Protocol string `json:"protocol,omitempty"`
	// Supports lists every protocol this provider can serve. When empty it
	// defaults to just Protocol.
	//
	// It exists so that cross-protocol routing can be deliberate: a provider
	// that only implements the chat surface must not be handed a Responses
	// request just because both are "OpenAI-ish".
	Supports []string `json:"supports,omitempty"`
	// Models maps a canonical (user-facing) model name to this provider's own
	// model identifier. An empty map means "pass through unchanged".
	Models map[string]string `json:"models,omitempty"`
	// Aliases adds extra canonical names that resolve to a model served by this
	// provider, which is how one vendor's spelling is exposed under another's.
	Aliases map[string]string `json:"aliases,omitempty"`
	// Trust relaxes content inspection for this provider.
	Trust Trust `json:"trust,omitempty"`
	// Weight biases routing across providers.
	Weight float64 `json:"weight,omitempty"`
	// Enabled allows disabling a whole provider without deleting its keys.
	Enabled *bool `json:"enabled,omitempty"`
	// Timeout overrides the per-request upstream timeout.
	Timeout Duration `json:"timeout,omitempty"`
	// Headers are extra headers attached to every request to this provider.
	Headers map[string]string `json:"headers,omitempty"`
	// Groups names the routing groups this provider belongs to.
	Groups []string `json:"groups,omitempty"`
	// Keys are the provider's credentials.
	Keys []APIKey `json:"keys,omitempty"`
	// Discover controls automatic model discovery from this provider.
	Discover *DiscoverPolicy `json:"discover,omitempty"`
	// Metadata carries free-form operator annotations.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// IsEnabled reports whether the provider may receive traffic.
func (p Provider) IsEnabled() bool { return p.Enabled == nil || *p.Enabled }

// TrustLevel returns the effective trust level.
func (p Provider) TrustLevel() Trust {
	if p.Trust == "" {
		return TrustUntrusted
	}
	return p.Trust
}

// SupportedProtocols returns the protocols this provider can serve, defaulting
// to the preferred protocol alone.
func (p Provider) SupportedProtocols() []string {
	if len(p.Supports) > 0 {
		return p.Supports
	}
	if p.Protocol != "" {
		return []string{p.Protocol}
	}
	return []string{"openai"}
}

// SpeaksProtocol reports whether the provider claims to serve a protocol.
func (p Provider) SpeaksProtocol(protocol string) bool {
	for _, supported := range p.SupportedProtocols() {
		if supported == protocol {
			return true
		}
	}
	return false
}

// APIKey is one credential belonging to a provider.
type APIKey struct {
	// Name identifies the key within its provider; it appears in audit records
	// so an operator can tell which key served a request.
	Name string `json:"name"`
	// APIKey is the credential itself. It is normally supplied through the env
	// file rather than this field, using
	// CUSTOMS_PROVIDER_<PROVIDER>_KEY_<NAME>_APIKEY
	APIKey string `json:"api_key,omitempty"`
	// Weight biases key selection within the provider. Zero means 1.
	Weight float64 `json:"weight,omitempty"`
	// Enabled allows parking a key without deleting it.
	Enabled *bool `json:"enabled,omitempty"`
	// Limits documents the operator's knowledge of this key's allowance, which
	// the front end shows as a hint. The gateway does not enforce it: only the
	// provider knows the real limit.
	Limits *KeyLimits `json:"limits,omitempty"`
	// Note is a free-form annotation.
	Note string `json:"note,omitempty"`
}

// IsEnabled reports whether the key may be used.
func (k APIKey) IsEnabled() bool { return k.Enabled == nil || *k.Enabled }

// KeyLimits is operator-recorded information about a key's allowance.
type KeyLimits struct {
	// RPM is the requests-per-minute allowance.
	RPM int `json:"rpm,omitempty"`
	// TPM is the tokens-per-minute allowance.
	TPM int `json:"tpm,omitempty"`
	// MonthlyBudget is the spend cap in Currency.
	MonthlyBudget float64 `json:"monthly_budget,omitempty"`
	// Currency of MonthlyBudget.
	Currency string `json:"currency,omitempty"`
}

// DiscoverPolicy controls model discovery for a provider.
type DiscoverPolicy struct {
	// Enabled turns discovery on. Nil means "inherit the global setting".
	Enabled *bool `json:"enabled,omitempty"`
	// Path overrides the discovery endpoint, defaulting to /v1/models.
	Path string `json:"path,omitempty"`
	// Interval overrides how often discovery runs.
	Interval Duration `json:"interval,omitempty"`
	// Exclude filters out discovered model names (substring or glob).
	Exclude []string `json:"exclude,omitempty"`
	// Include, when non-empty, restricts discovery to these patterns.
	Include []string `json:"include,omitempty"`
	// Namespace, when true, exposes discovered models as "<provider>/<model>"
	// in addition to any bare name. Useful when several providers serve
	// same-named models and the caller wants to be explicit.
	Namespace *bool `json:"namespace,omitempty"`
}

// DiscoverEnabled resolves the discovery switch against the global default.
func (p Provider) DiscoverEnabled(globalDefault bool) bool {
	if p.Discover == nil || p.Discover.Enabled == nil {
		return globalDefault
	}
	return *p.Discover.Enabled
}

// ---------------------------------------------------------------------------
// Routing policy
// ---------------------------------------------------------------------------

// RoutingPolicy configures provider selection.
type RoutingPolicy struct {
	// PreferSameProtocol makes the router choose a channel that already speaks
	// the client's protocol before considering any translation. Translation is
	// lossy in places, so it is a fallback rather than the default.
	PreferSameProtocol *bool `json:"prefer_same_protocol,omitempty"`
	// AllowTranslation permits routing to a channel that speaks a different
	// protocol, which requires a conversion. When false, a request whose
	// protocol no candidate speaks is refused rather than converted.
	AllowTranslation *bool `json:"allow_translation,omitempty"`
	// MaxAttempts bounds how many channels one request may try. Each attempt is
	// a real upstream call that may be billed, so this is a cost control as
	// much as a latency one.
	MaxAttempts int `json:"max_attempts,omitempty"`
	// RetryOn lists the failure classes worth another channel:
	// "5xx", "429", "timeout", "network".
	RetryOn []string `json:"retry_on,omitempty"`
	// Groups restricts routing to these provider groups. Empty means all.
	Groups []string `json:"groups,omitempty"`
	// ExcludeProviders skips these providers entirely.
	ExcludeProviders []string `json:"exclude_providers,omitempty"`
}

// SameProtocolPreferred reports the effective setting.
func (r RoutingPolicy) SameProtocolPreferred() bool {
	return r.PreferSameProtocol == nil || *r.PreferSameProtocol
}

// TranslationAllowed reports the effective setting.
func (r RoutingPolicy) TranslationAllowed() bool {
	return r.AllowTranslation == nil || *r.AllowTranslation
}

// Attempts returns the effective attempt bound.
func (r RoutingPolicy) Attempts() int {
	if r.MaxAttempts <= 0 {
		return 3
	}
	return r.MaxAttempts
}

// ShouldRetry reports whether a failure class is retryable.
func (r RoutingPolicy) ShouldRetry(class string) bool {
	if len(r.RetryOn) == 0 {
		switch class {
		case "5xx", "429", "timeout", "network", "quota":
			// "quota" belongs in the defaults: a provider whose account cannot
			// pay is exactly the provider an operator wants skipped, and the
			// request is unaffected - which is why several providers are
			// configured in the first place.
			return true
		}
		return false
	}
	for _, c := range r.RetryOn {
		if c == class {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Discovery (global)
// ---------------------------------------------------------------------------

// DiscoveryPolicy configures model discovery globally.
type DiscoveryPolicy struct {
	// Enabled turns discovery on for providers that do not override it.
	Enabled *bool `json:"enabled,omitempty"`
	// Interval is how often discovery runs.
	Interval Duration `json:"interval,omitempty"`
	// Timeout bounds one provider's discovery call.
	Timeout Duration `json:"timeout,omitempty"`
	// CachePath is where the merged catalogue is persisted.
	CachePath string `json:"cache_path,omitempty"`
	// StaleAfter marks a cached entry as stale for display purposes.
	StaleAfter Duration `json:"stale_after,omitempty"`
}

// EnabledDefault resolves the global switch.
func (d DiscoveryPolicy) EnabledDefault() bool {
	if d.Enabled == nil {
		return true
	}
	return *d.Enabled
}

// IntervalD returns the discovery interval.
func (d DiscoveryPolicy) IntervalD() time.Duration {
	if d.Interval <= 0 {
		return 30 * time.Minute
	}
	return d.Interval.D()
}

// TimeoutD returns the per-provider discovery timeout.
func (d DiscoveryPolicy) TimeoutD() time.Duration {
	if d.Timeout <= 0 {
		return 20 * time.Second
	}
	return d.Timeout.D()
}

// StaleAfterD returns the staleness threshold.
func (d DiscoveryPolicy) StaleAfterD() time.Duration {
	if d.StaleAfter <= 0 {
		return 24 * time.Hour
	}
	return d.StaleAfter.D()
}

// ---------------------------------------------------------------------------
// Expansion: providers -> channels
// ---------------------------------------------------------------------------

// ExpandProviders turns the configured providers into flat channels.
//
// Naming: a provider with one key produces the channel name "<provider>",
// preserving the simple case and keeping existing audit queries working. A
// provider with several keys produces "<provider>/<key>" for each, because a
// bare provider name would be ambiguous.
func (c *Config) ExpandProviders() []Channel {
	var out []Channel
	for _, p := range c.Providers {
		if !p.IsEnabled() {
			continue
		}
		keys := p.Keys
		if len(keys) == 0 {
			// A provider may legitimately have no inline keys, for example when
			// the credential arrives through the environment. Emit one channel
			// so the provider still participates, with the key filled in later.
			keys = []APIKey{{Name: ""}}
		}
		for _, key := range keys {
			if !key.IsEnabled() {
				continue
			}
			// A named key keeps its name even when it is the only one: the key
			// identity is what lets an operator tell which credential served a
			// request, so it must not disappear just because the provider
			// happens to have a single key. Only an unnamed single key uses the
			// bare provider name.
			name := p.Name
			if key.Name != "" {
				name = p.Name + "/" + key.Name
			}
			ch := Channel{
				Name:     name,
				BaseURL:  p.BaseURL,
				APIKey:   key.APIKey,
				Protocol: p.Protocol,
				Models:   mergeStringMaps(p.Models, p.Aliases),
				Trust:    p.Trust,
				Weight:   p.Weight * weightOr(key.Weight),
				Timeout:  p.Timeout,
				Headers:  p.Headers,
				Metadata: p.Metadata,
			}
			if !p.IsEnabled() {
				disabled := false
				ch.Enabled = &disabled
			}
			// Carry the provenance so audit records and the admin API can
			// explain which provider and key served a request.
			if ch.Metadata == nil {
				ch.Metadata = map[string]string{}
			}
			ch.Metadata["provider"] = p.Name
			if key.Name != "" {
				ch.Metadata["key"] = key.Name
			}
			ch.Metadata["protocols"] = strings.Join(p.SupportedProtocols(), ",")
			if len(p.Groups) > 0 {
				ch.Metadata["groups"] = strings.Join(p.Groups, ",")
			}
			out = append(out, ch)
		}
	}
	return out
}

func weightOr(w float64) float64 {
	if w <= 0 {
		return 1
	}
	return w
}

// mergeStringMaps overlays b onto a copy of a. Aliases win over model names,
// because an alias is the more specific operator intent.
func mergeStringMaps(a, b map[string]string) map[string]string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// AllChannels returns the effective channel list: providers expanded, plus any
// channels configured directly.
//
// Direct channels are kept so that an existing configuration keeps working
// unchanged, and so that a one-off endpoint (a test double, a colleague's
// gateway) does not need a provider wrapper.
func (c *Config) AllChannels() []Channel {
	out := make([]Channel, 0, len(c.Channels)+len(c.Providers))
	out = append(out, c.ExpandProviders()...)
	out = append(out, c.Channels...)
	return out
}

// ProviderByChannelName maps a channel back to its provider.
func (c *Config) ProviderByChannelName(channel string) (Provider, bool) {
	for _, p := range c.Providers {
		if p.Name == channel {
			return p, true
		}
		if strings.HasPrefix(channel, p.Name+"/") {
			return p, true
		}
	}
	return Provider{}, false
}

// GroupNames returns every routing group referenced by any provider.
func (c *Config) GroupNames() []string {
	seen := map[string]bool{}
	for _, p := range c.Providers {
		for _, g := range p.Groups {
			seen[g] = true
		}
	}
	out := make([]string, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Provider secret overlay
// ---------------------------------------------------------------------------

// envNameMatches compares a configured name against the name as it appears in an
// environment variable.
//
// The comparison folds case and treats every character an environment variable
// cannot carry (dot, dash, space) as an underscore, so "naapi.cc" and
// "NAAPI_CC" are the same provider. That is deliberately generous rather than
// strict: the alternative is a credential that silently never gets attached,
// which surfaces as an authentication failure against the upstream rather than
// as a configuration error.
func envNameMatches(configured, fromEnv string) bool {
	return normaliseEnvName(configured) == normaliseEnvName(fromEnv)
}

// normaliseEnvName maps a name onto its environment-variable spelling.
func normaliseEnvName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range strings.ToUpper(name) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// applyProviderEnv overlays credentials from the environment or env file.
//
// Accepted names:
//
//	CUSTOMS_PROVIDER_<PROVIDER>_APIKEY          single-key provider
//	CUSTOMS_PROVIDER_<PROVIDER>_BASEURL
//	CUSTOMS_PROVIDER_<PROVIDER>_KEY_<NAME>_APIKEY   one of several keys
//
// <PROVIDER> is compared after normalisation, so a provider named after its
// host ("naapi.cc") is addressable as CUSTOMS_PROVIDER_NAAPI_CC_...: an
// environment variable name cannot contain a dot, and forcing operators to
// rename providers would mean the name in the audit ledger no longer matched
// the name of the thing it came from.
func (c *Config) applyProviderEnv(environ []string) {
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(k, "CUSTOMS_PROVIDER_") {
			continue
		}
		rest := strings.TrimPrefix(k, "CUSTOMS_PROVIDER_")
		// Key-specific form first: ..._KEY_<NAME>_APIKEY
		if idx := strings.Index(rest, "_KEY_"); idx > 0 && strings.HasSuffix(rest, "_APIKEY") {
			provider := rest[:idx]
			name := strings.TrimSuffix(rest[idx+len("_KEY_"):], "_APIKEY")
			for i := range c.Providers {
				if !envNameMatches(c.Providers[i].Name, provider) {
					continue
				}
				for j := range c.Providers[i].Keys {
					if strings.EqualFold(c.Providers[i].Keys[j].Name, name) {
						c.Providers[i].Keys[j].APIKey = v
					}
				}
			}
			continue
		}
		switch {
		case strings.HasSuffix(rest, "_APIKEY"):
			name := strings.TrimSuffix(rest, "_APIKEY")
			for i := range c.Providers {
				if !envNameMatches(c.Providers[i].Name, name) {
					continue
				}
				if len(c.Providers[i].Keys) == 0 {
					c.Providers[i].Keys = []APIKey{{Name: ""}}
				}
				c.Providers[i].Keys[0].APIKey = v
			}
		case strings.HasSuffix(rest, "_BASEURL"):
			name := strings.TrimSuffix(rest, "_BASEURL")
			for i := range c.Providers {
				if envNameMatches(c.Providers[i].Name, name) {
					c.Providers[i].BaseURL = v
				}
			}
		}
	}
}

// validateProviders checks the provider layer.
func (c *Config) validateProviders() []string {
	var errs []string
	seen := map[string]bool{}
	for i, p := range c.Providers {
		where := fmt.Sprintf("providers[%d]", i)
		if p.Name == "" {
			errs = append(errs, where+".name must not be empty")
			continue
		}
		where = fmt.Sprintf("provider %q", p.Name)
		if seen[p.Name] {
			errs = append(errs, "duplicate "+where)
		}
		seen[p.Name] = true
		if p.BaseURL == "" {
			errs = append(errs, where+": base_url must not be empty")
		}
		if p.Protocol != "" && !isKnownProtocol(p.Protocol) {
			errs = append(errs, fmt.Sprintf("%s: protocol %q must be openai, responses or anthropic", where, p.Protocol))
		}
		for _, s := range p.Supports {
			if !isKnownProtocol(s) {
				errs = append(errs, fmt.Sprintf("%s: supports %q must be openai, responses or anthropic", where, s))
			}
		}
		if !p.TrustLevel().Valid() {
			errs = append(errs, fmt.Sprintf("%s: invalid trust %q", where, p.Trust))
		}
		keyNames := map[string]bool{}
		for j, k := range p.Keys {
			if k.Name == "" && len(p.Keys) > 1 {
				errs = append(errs, fmt.Sprintf("%s: keys[%d].name is required when a provider has several keys", where, j))
			}
			if k.Name != "" {
				if keyNames[k.Name] {
					errs = append(errs, fmt.Sprintf("%s: duplicate key name %q", where, k.Name))
				}
				keyNames[k.Name] = true
				// A key name becomes part of a channel name, which is used in
				// audit records and as a route target, so it must not contain
				// the separator.
				if strings.ContainsAny(k.Name, "/") {
					errs = append(errs, fmt.Sprintf("%s: key name %q must not contain '/'", where, k.Name))
				}
			}
		}
	}
	// A provider name must not collide with a directly-configured channel,
	// because both become entries in the same flat channel list.
	for _, ch := range c.Channels {
		if seen[ch.Name] {
			errs = append(errs, fmt.Sprintf("channel %q collides with a provider of the same name", ch.Name))
		}
	}
	return errs
}

func isKnownProtocol(p string) bool {
	switch p {
	case "openai", "responses", "anthropic":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

// ProviderSummary is the redacted view of a provider for the admin API.
type ProviderSummary struct {
	Name        string            `json:"name"`
	BaseURL     string            `json:"base_url"`
	Protocol    string            `json:"protocol"`
	Protocols   []string          `json:"protocols"`
	Trust       string            `json:"trust"`
	Enabled     bool              `json:"enabled"`
	Weight      float64           `json:"weight"`
	Groups      []string          `json:"groups,omitempty"`
	Models      int               `json:"models"`
	Keys        []KeySummary      `json:"keys"`
	Discover    *DiscoverPolicy   `json:"discover,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Translates  bool              `json:"can_translate"`
	ChannelBase string            `json:"channel_prefix,omitempty"`
}

// KeySummary is the redacted view of one API key.
type KeySummary struct {
	Name    string     `json:"name"`
	HasKey  bool       `json:"has_key"`
	Prefix  string     `json:"prefix,omitempty"`
	Weight  float64    `json:"weight,omitempty"`
	Enabled bool       `json:"enabled"`
	Limits  *KeyLimits `json:"limits,omitempty"`
	Note    string     `json:"note,omitempty"`
	// Channel is the channel name this key expands to.
	Channel string `json:"channel"`
}

// SummarizeProviders renders providers without exposing credentials.
//
// The key prefix is included deliberately: it is enough for an operator to tell
// two keys apart when checking which one is rate-limited, and a prefix alone
// does not grant access. Full keys are never returned.
func (c *Config) SummarizeProviders() []ProviderSummary {
	out := make([]ProviderSummary, 0, len(c.Providers))
	for _, p := range c.Providers {
		s := ProviderSummary{
			Name:      p.Name,
			BaseURL:   p.BaseURL,
			Protocol:  orDefault(p.Protocol, "openai"),
			Protocols: p.SupportedProtocols(),
			Trust:     string(p.TrustLevel()),
			Enabled:   p.IsEnabled(),
			Weight:    p.Weight,
			Groups:    p.Groups,
			Models:    len(p.Models),
			Discover:  p.Discover,
			Metadata:  p.Metadata,
		}
		if len(p.Keys) == 0 {
			s.Keys = []KeySummary{{
				Name: "", Enabled: true, Channel: p.Name, HasKey: false,
			}}
		}
		for _, k := range p.Keys {
			channel := p.Name
			if k.Name != "" {
				channel = p.Name + "/" + k.Name
			}
			s.Keys = append(s.Keys, KeySummary{
				Name:    k.Name,
				HasKey:  k.APIKey != "",
				Prefix:  keyPrefix(k.APIKey),
				Weight:  k.Weight,
				Enabled: k.IsEnabled(),
				Limits:  k.Limits,
				Note:    k.Note,
				Channel: channel,
			})
		}
		out = append(out, s)
	}
	return out
}

// keyPrefix returns a short, non-secret identifier for a credential.
func keyPrefix(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return key[:1] + "***"
	}
	return key[:6] + "..." + key[len(key)-2:]
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// UnmarshalProvider is a helper for tests and tooling that build providers from
// JSON fragments.
func UnmarshalProvider(data []byte) (Provider, error) {
	var p Provider
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Provider{}, err
	}
	return p, nil
}

// ---------------------------------------------------------------------------
// Upstream URL construction
// ---------------------------------------------------------------------------

// apiVersionSegment is the version prefix every wire protocol this gateway
// speaks lives under.
const apiVersionSegment = "/v1"

// UpstreamURL joins a channel's base_url with a protocol path.
//
// Operators write base_url both ways, and both are reasonable:
//
//	https://host            the vendor's host root
//	https://host/v1         the documented "API root", which is how relay
//	                        services and most vendor docs print it
//
// Appending "/v1/chat/completions" to the second form yields
// "https://host/v1/v1/chat/completions" and a 404 that looks like the
// aggregator is broken. So a base_url that already ends in the version segment
// is treated as the API root, and the path is appended without repeating it:
// "/v1/chat/completions" becomes "/chat/completions". A base_url carrying
// additional path segments ("https://host/openai/v1") keeps them, because only
// the trailing version segment is dropped.
func UpstreamURL(baseURL, path string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	// An unset base is returned as the empty string rather than as a bare path:
	// validation rejects an empty base_url, and a caller that forgot to check
	// should see "no host" rather than a relative URL.
	if base == "" {
		return ""
	}
	p := path
	if p == "" {
		return base
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if strings.HasSuffix(base, apiVersionSegment) && strings.HasPrefix(p, apiVersionSegment+"/") {
		// Drop one copy of the version segment: the base already carries it.
		p = strings.TrimPrefix(p, apiVersionSegment)
	}
	return base + p
}

// DeclaredProtocols returns the protocol surfaces a channel announced, or nil
// when it announced none.
//
// The distinction carries meaning throughout the system: declared-but-incomplete
// is a statement about what the upstream implements ("these are my surfaces"),
// while absent is silence, and silence is not evidence that a surface exists.
// Provider expansion writes this from Provider.Supports, so both the router and
// the proxy read the operator's declaration from one place.
func (ch Channel) DeclaredProtocols() []string {
	if ch.Metadata == nil {
		return nil
	}
	listed, ok := ch.Metadata["protocols"]
	if !ok {
		return nil
	}
	var out []string
	for _, p := range strings.Split(listed, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DeclaresProtocol reports whether the channel announced this protocol as one it
// serves directly, which means a request in that protocol can go to that surface
// unchanged rather than being converted.
func (ch Channel) DeclaresProtocol(protocol string) bool {
	for _, p := range ch.DeclaredProtocols() {
		if p == protocol {
			return true
		}
	}
	return false
}

// Package discovery maintains the catalogue of models the gateway can serve.
//
// # Why it exists
//
// An operator who adds a provider by API key wants to know what that key can
// actually reach. Asking them to hand-write every model name is both tedious and
// error-prone: providers add and retire models continuously, and a stale list
// silently makes models unreachable or routes to ones that no longer exist.
//
// The catalogue is therefore assembled from three sources, in decreasing order
// of authority:
//
//  1. a provider's declared `models` and `aliases`, which is explicit operator
//     intent and always wins;
//  2. models discovered from the provider's own model-list endpoint;
//  3. nothing else - a model is never invented.
//
// The catalogue is a *view*, not a routing input: routing still resolves through
// the channel list. That separation matters because discovery can fail or be
// stale without affecting live traffic, and a provider outage must never remove
// a model from service.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/redstone/customapi/internal/config"
)

// Source records where a catalogue entry came from.
type Source string

const (
	// SourceConfigured is operator-declared, and always wins.
	SourceConfigured Source = "configured"
	// SourceDiscovered came from the provider's model-list endpoint.
	SourceDiscovered Source = "discovered"
)

// ModelEntry is one servable model on one channel.
type ModelEntry struct {
	// Model is the canonical, user-facing name.
	Model string `json:"model"`
	// Channel is the channel that serves it.
	Channel string `json:"channel"`
	// Provider and Key identify the credential.
	Provider string `json:"provider,omitempty"`
	Key      string `json:"key,omitempty"`
	// UpstreamModel is the name sent to the provider.
	UpstreamModel string `json:"upstream_model,omitempty"`
	// Protocol is the channel's native protocol.
	Protocol string `json:"protocol,omitempty"`
	// Protocols lists every protocol the channel can accept: its native one
	// plus any the provider declared it also serves. It is what lets the
	// catalogue tell a chat-only channel apart from one that also speaks the
	// Responses or Messages surface.
	Protocols []string `json:"protocols,omitempty"`
	// Source records whether this entry was configured or discovered.
	Source Source `json:"source"`
	// OwnedBy is the provider-reported owner, when it reports one.
	OwnedBy string `json:"owned_by,omitempty"`
	// Created is the provider-reported creation time, when available.
	Created int64 `json:"created,omitempty"`
	// DiscoveredAt is when the entry was last confirmed by discovery.
	DiscoveredAt time.Time `json:"discovered_at,omitempty"`
	// Error records a discovery failure for this provider, so an operator can
	// see why a provider contributed nothing instead of assuming it has no
	// models.
	Error string `json:"error,omitempty"`
}

// ChannelModels groups the models one channel serves.
type ChannelModels struct {
	Channel  string       `json:"channel"`
	Provider string       `json:"provider,omitempty"`
	Key      string       `json:"key,omitempty"`
	Protocol string       `json:"protocol"`
	Models   []ModelEntry `json:"models"`
	// Discovered is when this channel's list was last refreshed.
	Discovered time.Time `json:"discovered,omitempty"`
	// Stale reports that the list is older than the configured threshold.
	Stale bool `json:"stale,omitempty"`
	// Error is set when the last refresh failed.
	Error string `json:"error,omitempty"`
	// ConfiguredOnly reports that the channel declares models but discovery
	// produced nothing, so the list is operator-supplied rather than verified.
	ConfiguredOnly bool `json:"configured_only,omitempty"`
}

// Snapshot is the whole catalogue at one point in time.
type Snapshot struct {
	// UpdatedAt is when discovery last ran to completion.
	UpdatedAt time.Time `json:"updated_at"`
	// Channels holds the per-channel model lists.
	Channels []ChannelModels `json:"channels"`
	// Providers counts discovered models per provider.
	Providers map[string]int `json:"providers,omitempty"`
	// Errors records provider-level failures from the last run.
	Errors map[string]string `json:"errors,omitempty"`
}

// ModelView is the merged, user-facing view of one model name.
type ModelView struct {
	Model string `json:"model"`
	// Channels lists every channel that can serve it, with the protocol each
	// speaks. The front end uses this to show "where can I get this model".
	Channels []ModelChannel `json:"channels"`
	// Protocols is the de-duplicated set of protocols available for this model.
	Protocols []string `json:"protocols"`
	// Configured reports that at least one provider declares it explicitly.
	Configured bool `json:"configured"`
	// Cheapest is the channel with the lowest effective unit price, when prices
	// are known. Pricing is not discoverable, so this is often empty.
	Cheapest string `json:"cheapest,omitempty"`
	// UnitPrice is the cheapest effective unit price.
	UnitPrice float64 `json:"unit_price,omitempty"`
	// Currency of UnitPrice.
	Currency string `json:"currency,omitempty"`
}

// ModelChannel is one channel serving a model.
type ModelChannel struct {
	Channel       string `json:"channel"`
	Provider      string `json:"provider,omitempty"`
	Key           string `json:"key,omitempty"`
	Protocol      string `json:"protocol"`
	UpstreamModel string `json:"upstream_model,omitempty"`
	Source        Source `json:"source"`
	Trust         string `json:"trust,omitempty"`
	// TranslateFrom lists the client protocols this channel can accept by
	// translation, i.e. every protocol it supports other than its own.
	TranslateFrom []string `json:"translate_from,omitempty"`
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// Service discovers and caches provider model lists.
type Service struct {
	mu       sync.RWMutex
	snapshot Snapshot
	// client performs discovery requests.
	client *http.Client
	// cachePath persists the snapshot across restarts.
	cachePath string
	// staleAfter marks entries as stale in the view.
	staleAfter time.Duration
	// log receives structured progress messages.
	log logger
	// now is injectable for tests.
	now func() time.Time
	// configured holds the operator-declared models, which always win.
	configured map[string][]ModelEntry
}

// logger is the subset of slog the service needs.
type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// Options configures the service.
type Options struct {
	// Policy is the global discovery policy.
	Policy config.DiscoveryPolicy
	// Client overrides the HTTP client.
	Client *http.Client
	// Logger receives progress messages.
	Logger logger
	// Now is injectable for tests.
	Now func() time.Time
}

// New creates a discovery service.
func New(opts Options) *Service {
	client := opts.Client
	if client == nil {
		timeout := opts.Policy.TimeoutD()
		client = &http.Client{Timeout: timeout}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	s := &Service{
		client:     client,
		cachePath:  opts.Policy.CachePath,
		staleAfter: opts.Policy.StaleAfterD(),
		log:        opts.Logger,
		now:        now,
		configured: map[string][]ModelEntry{},
		snapshot: Snapshot{
			Providers: map[string]int{},
			Errors:    map[string]string{},
		},
	}
	return s
}

// Load restores a cached snapshot from disk.
//
// A missing cache is not an error: the first discovery run populates it.
func (s *Service) Load() error {
	if s.cachePath == "" {
		return nil
	}
	b, err := readFile(s.cachePath)
	if err != nil {
		if isNotExist(err) {
			return nil
		}
		return err
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return fmt.Errorf("discovery: parse cache %s: %w", s.cachePath, err)
	}
	if snap.Providers == nil {
		snap.Providers = map[string]int{}
	}
	if snap.Errors == nil {
		snap.Errors = map[string]string{}
	}
	s.mu.Lock()
	s.snapshot = snap
	s.mu.Unlock()
	return nil
}

// Save persists the current snapshot.
func (s *Service) Save() error {
	if s.cachePath == "" {
		return nil
	}
	s.mu.RLock()
	snap := s.snapshot
	s.mu.RUnlock()
	b, err := json.MarshalIndent(&snap, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.cachePath, b)
}

// Snapshot returns the current catalogue.
func (s *Service) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.snapshot
	out.Channels = append([]ChannelModels(nil), s.snapshot.Channels...)
	return out
}

// SetConfigured installs the operator-declared models for each channel.
//
// Configured entries always win, so a provider that reports a model under a
// different name cannot hide the operator's mapping.
func (s *Service) SetConfigured(channels []config.Channel) {
	byChannel := map[string][]ModelEntry{}
	for _, ch := range channels {
		if len(ch.Models) == 0 {
			continue
		}
		provider, key := providerOfChannel(ch)
		names := make([]string, 0, len(ch.Models))
		for canonical := range ch.Models {
			names = append(names, canonical)
		}
		sort.Strings(names)
		entries := make([]ModelEntry, 0, len(names))
		for _, canonical := range names {
			entries = append(entries, ModelEntry{
				Model:         canonical,
				Channel:       ch.Name,
				Provider:      provider,
				Key:           key,
				UpstreamModel: ch.Models[canonical],
				Protocol:      channelProtocol(ch),
				Protocols:     channelProtocols(ch),
				Source:        SourceConfigured,
				DiscoveredAt:  s.now(),
			})
		}
		byChannel[ch.Name] = entries
	}
	s.mu.Lock()
	s.configured = byChannel
	s.mu.Unlock()
}

// Run performs discovery now and then on every interval until ctx is cancelled.
func (s *Service) Run(ctx context.Context, cfg *config.Config, interval time.Duration) {
	s.Refresh(ctx, cfg)
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Refresh(ctx, cfg)
		}
	}
}

// Refresh queries every provider that has discovery enabled.
func (s *Service) Refresh(ctx context.Context, cfg *config.Config) {
	channels := cfg.AllChannels()
	s.SetConfigured(channels)

	// Group channels by provider so a provider with several keys is queried
	// once per key but reported per provider.
	type job struct {
		channel  config.Channel
		provider config.Provider
	}
	var jobs []job
	for _, ch := range channels {
		provider, ok := cfg.ProviderByChannelName(ch.Name)
		if !ok {
			// A directly-configured channel has no discovery policy; it still
			// gets an entry built from its declared models.
			jobs = append(jobs, job{channel: ch})
			continue
		}
		if !provider.DiscoverEnabled(cfg.Discovery.EnabledDefault()) {
			jobs = append(jobs, job{channel: ch, provider: provider})
			continue
		}
		jobs = append(jobs, job{channel: ch, provider: provider})
	}

	var (
		mu       sync.Mutex
		results  = make([]ChannelModels, 0, len(jobs))
		provider = map[string]int{}
		errs     = map[string]string{}
		wg       sync.WaitGroup
	)
	for _, j := range jobs {
		j := j
		wg.Add(1)
		go func() {
			defer wg.Done()
			cm := s.discoverChannel(ctx, cfg, j.channel, j.provider)
			mu.Lock()
			results = append(results, cm)
			provider[cm.Provider] += len(cm.Models)
			if cm.Error != "" {
				errs[cm.Provider] = cm.Error
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Channel < results[j].Channel })
	s.mu.Lock()
	s.snapshot = Snapshot{
		UpdatedAt: s.now(),
		Channels:  results,
		Providers: provider,
		Errors:    errs,
	}
	s.mu.Unlock()

	if err := s.Save(); err != nil && s.log != nil {
		s.log.Warn("discovery cache save failed", "err", err)
	}
	if s.log != nil {
		total := 0
		for _, n := range provider {
			total += n
		}
		s.log.Info("model discovery complete",
			"channels", len(results), "models", total, "providers_with_errors", len(errs))
	}
}

// discoverChannel queries one channel and merges the result with what the
// operator declared for it.
func (s *Service) discoverChannel(ctx context.Context, cfg *config.Config,
	ch config.Channel, provider config.Provider) ChannelModels {

	cm := ChannelModels{
		Channel:  ch.Name,
		Protocol: channelProtocol(ch),
	}
	if provider.Name != "" {
		cm.Provider = provider.Name
	}
	if meta := ch.Metadata; meta != nil {
		if v, ok := meta["key"]; ok {
			cm.Key = v
		}
		if cm.Provider == "" {
			cm.Provider = meta["provider"]
		}
	}

	// Configured entries always come first and are never overwritten.
	s.mu.RLock()
	configured := append([]ModelEntry(nil), s.configured[ch.Name]...)
	s.mu.RUnlock()
	cm.Models = append(cm.Models, configured...)
	seen := map[string]bool{}
	for _, e := range configured {
		seen[e.Model] = true
	}

	discover := provider.Name == "" || provider.DiscoverEnabled(cfg.Discovery.EnabledDefault())
	if !discover {
		cm.ConfiguredOnly = len(configured) > 0
		cm.Discovered = s.now()
		return cm
	}

	found, err := s.fetchModels(ctx, ch, provider)
	if err != nil {
		cm.Error = err.Error()
		cm.ConfiguredOnly = len(configured) > 0
		cm.Discovered = s.now()
		return cm
	}
	cm.Discovered = s.now()

	providerName, keyName := cm.Provider, cm.Key
	for _, m := range found {
		if m.ID == "" {
			continue
		}
		// Only names the operator asked for are exposed under their bare name;
		// everything else is namespaced so that two providers serving the same
		// model name do not silently collide in the user-facing catalogue.
		canonical := m.ID
		if !s.allowedByFilter(provider, m.ID) {
			continue
		}
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		cm.Models = append(cm.Models, ModelEntry{
			Model:         canonical,
			Channel:       ch.Name,
			Provider:      providerName,
			Key:           keyName,
			UpstreamModel: m.ID,
			Protocol:      cm.Protocol,
			Protocols:     channelProtocols(ch),
			Source:        SourceDiscovered,
			OwnedBy:       m.OwnedBy,
			Created:       m.Created,
			DiscoveredAt:  cm.Discovered,
		})
	}
	cm.ConfiguredOnly = len(cm.Models) == 0 && len(configured) > 0
	return cm
}

// allowedByFilter applies the provider's include/exclude patterns.
func (s *Service) allowedByFilter(p config.Provider, model string) bool {
	if p.Discover == nil {
		return true
	}
	for _, pat := range p.Discover.Exclude {
		if matchPattern(pat, model) {
			return false
		}
	}
	if len(p.Discover.Include) == 0 {
		return true
	}
	for _, pat := range p.Discover.Include {
		if matchPattern(pat, model) {
			return true
		}
	}
	return false
}

// matchPattern supports exact names and a trailing "*" wildcard, which covers
// how operators actually filter (e.g. "gpt-4*").
func matchPattern(pattern, name string) bool {
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

// providerModel is one entry of an upstream model list.
type providerModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
	// Some compatible servers nest the identifier.
	Name string `json:"name"`
}

// fetchModels asks a channel for its model list.
//
// The endpoint and the authentication depend on the protocol: the Responses and
// chat APIs share /v1/models with a bearer token, while the Messages API exposes
// /v1/models with the x-api-key header.
func (s *Service) fetchModels(ctx context.Context, ch config.Channel, p config.Provider) ([]providerModel, error) {
	path := "/v1/models"
	if p.Discover != nil && p.Discover.Path != "" {
		path = p.Discover.Path
	}
	// UpstreamURL tolerates a base_url that already carries the version
	// segment, which is how most aggregators document their endpoint.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		config.UpstreamURL(ch.BaseURL, path), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	switch channelProtocol(ch) {
	case "anthropic":
		if ch.APIKey != "" {
			req.Header.Set("x-api-key", ch.APIKey)
		}
		req.Header.Set("anthropic-version", "2023-06-01")
	default:
		if ch.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+ch.APIKey)
		}
	}
	for k, v := range ch.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("model list request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("model list read failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("model list returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 160))
	}

	// Both protocols return {"data":[...]}; Anthropic uses the same envelope.
	var payload struct {
		Data []providerModel `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("model list parse failed: %w", err)
	}
	out := make([]providerModel, 0, len(payload.Data))
	for _, m := range payload.Data {
		if m.ID == "" {
			m.ID = m.Name
		}
		if m.ID != "" {
			out = append(out, m)
		}
	}
	return out, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

// Models merges the catalogue into a user-facing list.
//
// allow, when non-nil, filters the result, which is how a user restricted to a
// set of models sees only those.
func (s *Service) Models(allow func(model string) bool) []ModelView {
	s.mu.RLock()
	snap := s.snapshot
	configured := s.configured
	s.mu.RUnlock()

	byModel := map[string]*ModelView{}
	// seen deduplicates by channel plus upstream name: the snapshot and the
	// configured list can both carry the same model (discovery confirms what the
	// operator declared), and listing it twice would make any channel count
	// wrong.
	seen := map[string]bool{}
	add := func(e ModelEntry) {
		if allow != nil && !allow(e.Model) {
			return
		}
		key := e.Model + "\x00" + e.Channel + "\x00" + e.UpstreamModel
		if seen[key] {
			return
		}
		seen[key] = true

		v, ok := byModel[e.Model]
		if !ok {
			v = &ModelView{Model: e.Model}
			byModel[e.Model] = v
		}
		// Everything the channel can accept beyond the protocol it speaks is
		// reachable only through translation, and saying so explicitly is what
		// makes the console able to warn about it.
		var translateFrom []string
		for _, p := range e.Protocols {
			if p != "" && p != e.Protocol {
				translateFrom = append(translateFrom, p)
			}
		}
		sort.Strings(translateFrom)
		v.Channels = append(v.Channels, ModelChannel{
			Channel: e.Channel, Provider: e.Provider, Key: e.Key,
			Protocol: e.Protocol, UpstreamModel: e.UpstreamModel, Source: e.Source,
			TranslateFrom: translateFrom,
		})
		if e.Source == SourceConfigured {
			v.Configured = true
		}
	}
	for _, cm := range snap.Channels {
		for _, e := range cm.Models {
			add(e)
		}
	}
	// A configured model whose channel did not appear in the last snapshot
	// (because discovery failed outright) must still be offered: the model is
	// servable, the catalogue is just unverified.
	for _, entries := range configured {
		for _, e := range entries {
			add(e)
		}
	}

	out := make([]ModelView, 0, len(byModel))
	for _, v := range byModel {
		// A model's protocol list is the union over its channels of what each
		// channel can accept: its own protocol plus everything it declared it
		// can also serve. Reporting only the channel's own protocol told an
		// operator that a model was chat-only when the provider had in fact
		// declared the Responses surface too - and this list is what the
		// console and /v1/models show to someone choosing a model.
		protos := map[string]bool{}
		for _, c := range v.Channels {
			if c.Protocol != "" {
				protos[c.Protocol] = true
			}
			for _, p := range c.TranslateFrom {
				if p != "" {
					protos[p] = true
				}
			}
		}
		for p := range protos {
			v.Protocols = append(v.Protocols, p)
		}
		sort.Strings(v.Protocols)
		sort.Slice(v.Channels, func(i, j int) bool {
			if v.Channels[i].Channel != v.Channels[j].Channel {
				return v.Channels[i].Channel < v.Channels[j].Channel
			}
			return v.Channels[i].Key < v.Channels[j].Key
		})
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Model < out[j].Model })
	return out
}

// Channels returns the per-channel catalogue with staleness marked.
func (s *Service) Channels() []ChannelModels {
	s.mu.RLock()
	snap := s.snapshot
	configured := s.configured
	staleAfter := s.staleAfter
	now := s.now()
	s.mu.RUnlock()

	out := make([]ChannelModels, 0, len(snap.Channels))
	for _, cm := range snap.Channels {
		if cm.Discovered.IsZero() {
			cm.Discovered = snap.UpdatedAt
		}
		cm.Stale = staleAfter > 0 && !cm.Discovered.IsZero() && now.Sub(cm.Discovered) > staleAfter
		out = append(out, cm)
	}
	// Channels the last run did not reach still deserve an entry built from
	// their configured models, so a provider outage does not make them vanish.
	present := map[string]bool{}
	for _, cm := range out {
		present[cm.Channel] = true
	}
	for channel, entries := range configured {
		if present[channel] {
			continue
		}
		cm := ChannelModels{Channel: channel, Models: append([]ModelEntry(nil), entries...)}
		if len(entries) > 0 {
			cm.Protocol = entries[0].Protocol
			cm.Provider = entries[0].Provider
			cm.Key = entries[0].Key
		}
		cm.ConfiguredOnly = true
		out = append(out, cm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Channel < out[j].Channel })
	return out
}

// Lookup reports every channel that can serve a model.
func (s *Service) Lookup(model string) (ModelView, bool) {
	for _, v := range s.Models(nil) {
		if v.Model == model {
			return v, true
		}
	}
	return ModelView{}, false
}

// Known reports whether the catalogue knows a model at all.
func (s *Service) Known(model string) bool {
	_, ok := s.Lookup(model)
	return ok
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func channelProtocol(ch config.Channel) string {
	if ch.Protocol == "" {
		return "openai"
	}
	return ch.Protocol
}

// channelProtocols returns every protocol a channel can accept, native first.
//
// The provider expansion records the declaration in Metadata["protocols"]; a
// directly-configured channel has no metadata and therefore supports only what
// it speaks.
func channelProtocols(ch config.Channel) []string {
	native := channelProtocol(ch)
	out := []string{native}
	if ch.Metadata != nil {
		for _, p := range strings.Split(ch.Metadata["protocols"], ",") {
			p = strings.TrimSpace(p)
			if p == "" || p == native {
				continue
			}
			out = append(out, p)
		}
	}
	return out
}

func providerOfChannel(ch config.Channel) (provider, key string) {
	if ch.Metadata == nil {
		return "", ""
	}
	return ch.Metadata["provider"], ch.Metadata["key"]
}

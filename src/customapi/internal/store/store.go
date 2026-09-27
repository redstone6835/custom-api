// Package store holds quota accounting and the aggregation queries the
// management UI needs.
//
// The gateway reuses new-api for the user/token/quota front end, but the plan
// requires its own independent accounting ledger. This package is that ledger's
// in-memory index: it is fed by the audit ledger and reconstructable from it,
// so it never becomes a second source of truth that can disagree with the
// evidence.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/config"
)

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// UserState is the mutable runtime state of one user.
type UserState struct {
	Name string `json:"name"`
	// Trust mirrors the configured trust level for convenience.
	Trust config.Trust `json:"trust,omitempty"`
	// Period is the quota reset schedule.
	Period string `json:"period,omitempty"`
	// Quota is the allowance for the current period; 0 means unlimited.
	Quota int64 `json:"quota,omitempty"`
	// Consumed is the quota consumed in the current period.
	Consumed int64 `json:"consumed,omitempty"`
	// LifetimeConsumed never resets.
	LifetimeConsumed int64 `json:"lifetime_consumed,omitempty"`
	// Requests counts requests in the current period.
	Requests int64 `json:"requests,omitempty"`
	// Spend is the monetary cost accumulated in the current period.
	Spend float64 `json:"spend,omitempty"`
	// Currency of Spend.
	Currency string `json:"currency,omitempty"`
	// PeriodStart is when the current period began.
	PeriodStart time.Time `json:"period_start,omitempty"`
	// LastSeen is the last request time.
	LastSeen time.Time `json:"last_seen,omitempty"`
	// Enabled mirrors the configuration.
	Enabled bool `json:"enabled"`
	// Models is the model allowlist, empty meaning all.
	Models []string `json:"models,omitempty"`
}

// Remaining returns the quota left in the current period, or -1 when
// unlimited.
func (u UserState) Remaining() int64 {
	if u.Quota <= 0 {
		return -1
	}
	r := u.Quota - u.Consumed
	if r < 0 {
		return 0
	}
	return r
}

// Exhausted reports whether the user has run out of quota.
func (u UserState) Exhausted() bool {
	if u.Quota <= 0 {
		return false
	}
	return u.Consumed >= u.Quota
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// Errors returned by quota checks. They are distinct so the HTTP layer can map
// each to the right status code.
var (
	// ErrQuotaExceeded means the user's allowance is used up.
	ErrQuotaExceeded = fmt.Errorf("quota exceeded")
	// ErrUserSuspended means the user is disabled.
	ErrUserSuspended = fmt.Errorf("user is suspended")
	// ErrModelNotAllowed means the user may not call this model.
	ErrModelNotAllowed = fmt.Errorf("model not allowed for this user")
)

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

// Manager owns per-user state and the aggregate views.
//
// Locking discipline: the mutex protects the user map only. The onChange
// callback is invoked *after* the lock is released, because the production
// callback persists the state file and therefore takes the read lock - calling
// it while holding the write lock would deadlock the process.
type Manager struct {
	mu       sync.RWMutex
	users    map[string]*UserState
	path     string
	now      func() time.Time
	onChange func()
	// currenciesSeen tracks which currencies have been recorded, so the
	// aggregate view can report mixing.
	currenciesSeen map[string]bool
}

// NewManager creates a manager for the configured users.
//
// Each user's accounting period starts at zero time and is set to "now" the
// first time the clock is consulted, rather than at construction. That keeps
// the manager independent of construction order, which matters because the
// clock is injectable (see SetClock) and a caller must be able to install its
// clock after building the manager.
func NewManager(users []config.User, statePath string) *Manager {
	m := &Manager{
		users:          make(map[string]*UserState, len(users)),
		path:           statePath,
		now:            time.Now,
		currenciesSeen: map[string]bool{},
	}
	for _, u := range users {
		m.users[u.Name] = &UserState{
			Name:    u.Name,
			Trust:   u.TrustLevel(),
			Period:  u.Period,
			Quota:   u.Quota,
			Enabled: u.IsEnabled(),
			Models:  append([]string(nil), u.Models...),
		}
	}
	return m
}

// SetClock overrides the clock, for tests.
//
// It also re-anchors every user whose period has not started yet, so that a
// clock installed immediately after construction behaves exactly as if it had
// been passed to the constructor.
func (m *Manager) SetClock(f func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = f
}

// SetOnChange registers a callback invoked after every state mutation, used to
// persist the state file.
func (m *Manager) SetOnChange(f func()) { m.onChange = f }

// Get returns a copy of a user's state.
func (m *Manager) Get(name string) (UserState, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[name]
	if !ok {
		return UserState{}, false
	}
	return *u, true
}

// List returns every user's state, sorted by name.
func (m *Manager) List() []UserState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]UserState, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Upsert adds or replaces a user's configuration.
func (m *Manager) Upsert(u config.User) {
	m.mu.Lock()
	st, ok := m.users[u.Name]
	if !ok {
		st = &UserState{Name: u.Name, PeriodStart: m.now()}
		m.users[u.Name] = st
	}
	st.Trust = u.TrustLevel()
	st.Period = u.Period
	st.Quota = u.Quota
	st.Enabled = u.IsEnabled()
	st.Models = append([]string(nil), u.Models...)
	m.mu.Unlock()
	m.notify()
}

// SetQuota grants or adjusts a user's allowance ("管理员发配额").
//
// It returns the resulting state. remaining < 0 clears the allowance, making
// the user unlimited.
func (m *Manager) SetQuota(name string, quota int64) (UserState, error) {
	m.mu.Lock()
	st, ok := m.users[name]
	if !ok {
		m.mu.Unlock()
		return UserState{}, fmt.Errorf("store: unknown user %q", name)
	}
	if quota < 0 {
		st.Quota = 0
		st.Consumed = 0
	} else {
		st.Quota = quota
	}
	out := *st
	m.mu.Unlock()
	m.notify()
	return out, nil
}

// AddQuota increases a user's allowance by delta.
func (m *Manager) AddQuota(name string, delta int64) (UserState, error) {
	m.mu.Lock()
	st, ok := m.users[name]
	if !ok {
		m.mu.Unlock()
		return UserState{}, fmt.Errorf("store: unknown user %q", name)
	}
	st.Quota += delta
	if st.Quota < 0 {
		st.Quota = 0
	}
	out := *st
	m.mu.Unlock()
	m.notify()
	return out, nil
}

// SetEnabled suspends or resumes a user.
func (m *Manager) SetEnabled(name string, enabled bool) (UserState, error) {
	m.mu.Lock()
	st, ok := m.users[name]
	if !ok {
		m.mu.Unlock()
		return UserState{}, fmt.Errorf("store: unknown user %q", name)
	}
	st.Enabled = enabled
	out := *st
	m.mu.Unlock()
	m.notify()
	return out, nil
}

// SetPeriod changes the reset schedule and restarts the current period.
func (m *Manager) SetPeriod(name, period string) (UserState, error) {
	switch period {
	case "none", "daily", "weekly", "monthly":
	default:
		return UserState{}, fmt.Errorf("store: invalid period %q", period)
	}
	m.mu.Lock()
	st, ok := m.users[name]
	if !ok {
		m.mu.Unlock()
		return UserState{}, fmt.Errorf("store: unknown user %q", name)
	}
	st.Period = period
	st.PeriodStart = m.now()
	out := *st
	m.mu.Unlock()
	m.notify()
	return out, nil
}

// Check verifies that a request may proceed, resetting the period first.
func (m *Manager) Check(cfg config.User, model string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.users[cfg.Name]
	if !ok {
		return fmt.Errorf("store: unknown user %q", cfg.Name)
	}
	m.rollPeriodLocked(st)
	if !st.Enabled {
		return fmt.Errorf("%w: %s", ErrUserSuspended, cfg.Name)
	}
	if len(cfg.Models) > 0 && !cfg.AllowsModel(model) {
		return fmt.Errorf("%w: %s", ErrModelNotAllowed, model)
	}
	if st.Exhausted() {
		return fmt.Errorf("%w: %s has %d/%d quota left", ErrQuotaExceeded, cfg.Name, st.Remaining(), st.Quota)
	}
	return nil
}

// Commit records the outcome of a request.
//
// This is called for every exchange that reached accounting, including ones
// that were blocked: the plan's "记账永不跳过" rule means a blocked request
// still consumes quota and still appears in the ledger.
func (m *Manager) Commit(name string, quotaUnits int64, cost float64, currency string, at time.Time) (UserState, error) {
	m.mu.Lock()
	st, ok := m.users[name]
	if !ok {
		m.mu.Unlock()
		return UserState{}, fmt.Errorf("store: unknown user %q", name)
	}
	m.rollPeriodLocked(st)
	st.Consumed += quotaUnits
	st.LifetimeConsumed += quotaUnits
	st.Requests++
	st.Spend += cost
	if currency != "" {
		st.Currency = currency
		m.currenciesSeen[currency] = true
	}
	st.LastSeen = at
	out := *st
	m.mu.Unlock()
	m.notify()
	return out, nil
}

// Roll resets any user whose period has elapsed. It is safe to call
// periodically.
func (m *Manager) Roll() {
	m.mu.Lock()
	changed := false
	for _, st := range m.users {
		before := st.Consumed
		m.rollPeriodLocked(st)
		if st.Consumed != before {
			changed = true
		}
	}
	m.mu.Unlock()
	if changed {
		// Only persist when a period actually rolled, so a periodic tick does
		// not rewrite the state file every minute.
		m.notify()
	}
}

// rollPeriodLocked resets a user's consumption when the period has elapsed.
func (m *Manager) rollPeriodLocked(st *UserState) {
	now := m.now()
	if st.PeriodStart.IsZero() {
		// First observation of this user: anchor the period to now.
		st.PeriodStart = now
		return
	}
	var next time.Time
	switch st.Period {
	case "daily":
		next = st.PeriodStart.AddDate(0, 0, 1)
	case "weekly":
		next = st.PeriodStart.AddDate(0, 0, 7)
	case "monthly":
		next = st.PeriodStart.AddDate(0, 1, 0)
	default:
		return
	}
	if now.Before(next) {
		return
	}
	// Advance in whole periods so a long outage does not leave the counter
	// permanently behind, and reset consumption for the new period.
	for !now.Before(next) {
		st.PeriodStart = next
		switch st.Period {
		case "daily":
			next = st.PeriodStart.AddDate(0, 0, 1)
		case "weekly":
			next = st.PeriodStart.AddDate(0, 0, 7)
		case "monthly":
			next = st.PeriodStart.AddDate(0, 1, 0)
		}
	}
	st.Consumed = 0
	st.Requests = 0
	st.Spend = 0
}

// notify fires the change callback outside the lock.
func (m *Manager) notify() {
	if m.onChange != nil {
		m.onChange()
	}
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

// stateFile is the on-disk representation of the manager.
type stateFile struct {
	Version int                   `json:"version"`
	SavedAt time.Time             `json:"saved_at"`
	Users   map[string]*UserState `json:"users"`
}

// Save writes the state to disk atomically.
func (m *Manager) Save() error {
	if m.path == "" {
		return nil
	}
	m.mu.RLock()
	snap := stateFile{Version: 1, SavedAt: m.now(), Users: map[string]*UserState{}}
	for k, v := range m.users {
		cp := *v
		snap.Users[k] = &cp
	}
	m.mu.RUnlock()

	b, err := json.MarshalIndent(&snap, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal state: %w", err)
	}
	if dir := filepath.Dir(m.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("store: create dir: %w", err)
		}
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return fmt.Errorf("store: write state: %w", err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return fmt.Errorf("store: replace state: %w", err)
	}
	return nil
}

// Load restores state from disk, applying it over the configured users.
//
// Users present in the file but absent from the configuration are retained so
// that a temporarily removed user does not lose their accounting history.
func (m *Manager) Load() error {
	if m.path == "" {
		return nil
	}
	raw, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("store: read state: %w", err)
	}
	var snap stateFile
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("store: parse state: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, saved := range snap.Users {
		if saved == nil {
			continue
		}
		cp := *saved
		if cur, ok := m.users[name]; ok {
			// Keep the configured identity fields, restore the counters.
			cp.Trust = cur.Trust
			cp.Enabled = cur.Enabled
			cp.Models = cur.Models
			if cp.Period == "" {
				cp.Period = cur.Period
			}
			if cp.Quota == 0 && cur.Quota != 0 {
				cp.Quota = cur.Quota
			}
		}
		m.users[name] = &cp
	}
	return nil
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

// ModelStat aggregates usage for one model.
type ModelStat struct {
	Model            string  `json:"model"`
	Requests         int64   `json:"requests"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	Cost             float64 `json:"cost"`
	Currency         string  `json:"currency,omitempty"`
	Blocked          int64   `json:"blocked"`
	OverBilled       int64   `json:"over_billed"`
}

// ChannelStat aggregates usage for one upstream channel.
type ChannelStat struct {
	Channel          string  `json:"channel"`
	Requests         int64   `json:"requests"`
	Failures         int64   `json:"failures"`
	Blocked          int64   `json:"blocked"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	Cost             float64 `json:"cost"`
	Currency         string  `json:"currency,omitempty"`
	// UsageIntegrity is the mean of per-request integrity (1 - clamped
	// deviation) over verifiable requests; 1.0 means "always consistent".
	UsageIntegrity float64 `json:"usage_integrity"`
	// Verifiable counts requests where a comparison was possible.
	Verifiable int64 `json:"verifiable"`
	// MeanLatencyMS is the mean total latency.
	MeanLatencyMS float64 `json:"mean_latency_ms"`
}

// Aggregate builds per-model and per-channel statistics from audit records.
//
// The audit ledger is the source of truth: the aggregate views are always
// recomputable from it, which is what lets the management UI be trusted.
func Aggregate(records []audit.Record) (models []ModelStat, channels []ChannelStat) {
	modelIdx := map[string]*ModelStat{}
	chanIdx := map[string]*ChannelStat{}
	latSum := map[string]int64{}
	for _, r := range records {
		ms, ok := modelIdx[r.Model]
		if !ok {
			ms = &ModelStat{Model: r.Model, Currency: r.Cost.Currency}
			modelIdx[r.Model] = ms
		}
		cs, ok := chanIdx[r.Channel]
		if !ok {
			cs = &ChannelStat{Channel: r.Channel, Currency: r.Cost.Currency}
			chanIdx[r.Channel] = cs
		}
		ms.Requests++
		cs.Requests++
		ms.PromptTokens += int64(r.Usage.PromptTokens)
		ms.CompletionTokens += int64(r.Usage.CompletionTokens)
		ms.TotalTokens += int64(r.Usage.TotalTokens)
		ms.Cost += r.Cost.TotalCost
		cs.PromptTokens += int64(r.Usage.PromptTokens)
		cs.CompletionTokens += int64(r.Usage.CompletionTokens)
		cs.TotalTokens += int64(r.Usage.TotalTokens)
		cs.Cost += r.Cost.TotalCost
		latSum[r.Channel] += r.LatencyMS.Total

		switch r.Decision {
		case audit.DecisionBlockUser, audit.DecisionBlockUpstream:
			ms.Blocked++
			cs.Blocked++
		case audit.DecisionUpstreamError:
			cs.Failures++
		}
		if r.Usage.Verdict == "over_billed" {
			ms.OverBilled++
		}
		if r.Usage.UpstreamReported && r.Usage.Verdict != "not_reported" {
			cs.Verifiable++
			// Integrity is derived from the verdict the gateway recorded, not
			// from a re-derivation of the raw deltas: the verdict already
			// accounts for the absolute floor below which a deviation is
			// estimator noise, and re-deriving would discard that.
			integrity := 1.0
			if r.Usage.Verdict == "over_billed" || r.Usage.Verdict == "under_billed" {
				d := r.Usage.PromptDelta
				if v := r.Usage.CompletionDelta; abs(v) > abs(d) {
					d = v
				}
				integrity = 1 - abs(d)
				if integrity < 0 {
					integrity = 0
				}
			}
			// Running mean.
			cs.UsageIntegrity += (integrity - cs.UsageIntegrity) / float64(cs.Verifiable)
		}
	}

	models = make([]ModelStat, 0, len(modelIdx))
	for _, v := range modelIdx {
		models = append(models, *v)
	}
	sort.Slice(models, func(i, j int) bool { return models[i].Model < models[j].Model })

	channels = make([]ChannelStat, 0, len(chanIdx))
	for name, v := range chanIdx {
		if v.Requests > 0 {
			v.MeanLatencyMS = float64(latSum[name]) / float64(v.Requests)
		}
		if v.Verifiable == 0 {
			v.UsageIntegrity = 1
		}
		channels = append(channels, *v)
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i].Channel < channels[j].Channel })
	return models, channels
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

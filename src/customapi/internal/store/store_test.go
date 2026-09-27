package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/config"
)

func users() []config.User {
	return []config.User{
		{Name: "alice", Token: "t1", Quota: 1000, Period: "daily"},
		{Name: "bob", Token: "t2", Quota: 0}, // unlimited
		{Name: "carol", Token: "t3", Quota: 500, Period: "monthly", Models: []string{"gpt-4o"}},
	}
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(users(), filepath.Join(t.TempDir(), "state.json"))
	return m
}

// ---------------------------------------------------------------------------
// Quota
// ---------------------------------------------------------------------------

func TestCheckAndCommit(t *testing.T) {
	m := newTestManager(t)
	alice := users()[0]

	if err := m.Check(alice, "gpt-4o"); err != nil {
		t.Fatalf("initial check failed: %v", err)
	}
	st, err := m.Commit("alice", 400, 0.4, "CNY", time.Now())
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if st.Consumed != 400 || st.Remaining() != 600 {
		t.Fatalf("unexpected state: %+v", st)
	}
	if st.Requests != 1 {
		t.Fatalf("request count = %d", st.Requests)
	}
	if st.LifetimeConsumed != 400 {
		t.Fatalf("lifetime = %d", st.LifetimeConsumed)
	}
}

func TestQuotaExhaustion(t *testing.T) {
	m := newTestManager(t)
	alice := users()[0]
	_, _ = m.Commit("alice", 1000, 1, "CNY", time.Now())

	err := m.Check(alice, "gpt-4o")
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected ErrQuotaExceeded, got %v", err)
	}
}

func TestUnlimitedQuota(t *testing.T) {
	m := newTestManager(t)
	bob := users()[1]
	if _, err := m.Commit("bob", 10_000_000, 10, "CNY", time.Now()); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := m.Check(bob, "gpt-4o"); err != nil {
		t.Fatalf("an unlimited user should never be exhausted: %v", err)
	}
	st, _ := m.Get("bob")
	if st.Remaining() != -1 {
		t.Fatalf("unlimited remaining should be -1, got %d", st.Remaining())
	}
}

func TestModelRestriction(t *testing.T) {
	m := newTestManager(t)
	carol := users()[2]
	if err := m.Check(carol, "gpt-4o"); err != nil {
		t.Fatalf("allowed model rejected: %v", err)
	}
	if err := m.Check(carol, "claude-3"); !errors.Is(err, ErrModelNotAllowed) {
		t.Fatalf("expected ErrModelNotAllowed, got %v", err)
	}
}

func TestSuspendedUser(t *testing.T) {
	m := newTestManager(t)
	alice := users()[0]
	if _, err := m.SetEnabled("alice", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if err := m.Check(alice, "gpt-4o"); !errors.Is(err, ErrUserSuspended) {
		t.Fatalf("expected ErrUserSuspended, got %v", err)
	}
	if _, err := m.SetEnabled("alice", true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if err := m.Check(alice, "gpt-4o"); err != nil {
		t.Fatalf("resumed user rejected: %v", err)
	}
}

// TestQuotaGrantIsAuditable verifies the "管理员发配额" workflow.
func TestQuotaGrant(t *testing.T) {
	m := newTestManager(t)

	st, err := m.SetQuota("alice", 5000)
	if err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	if st.Quota != 5000 {
		t.Fatalf("quota = %d", st.Quota)
	}
	// Granting preserves consumption so an audit can reconstruct history.
	_, _ = m.Commit("alice", 100, 0.1, "CNY", time.Now())
	st, _ = m.AddQuota("alice", 1000)
	if st.Quota != 6000 || st.Consumed != 100 {
		t.Fatalf("AddQuota produced %+v", st)
	}
	// A negative grant clears the allowance.
	st, _ = m.SetQuota("alice", -1)
	if st.Quota != 0 || st.Consumed != 0 {
		t.Fatalf("clearing quota produced %+v", st)
	}
	if _, err := m.SetQuota("nobody", 1); err == nil {
		t.Fatal("expected an error for an unknown user")
	}
}

// ---------------------------------------------------------------------------
// Periods
// ---------------------------------------------------------------------------

// TestDailyReset verifies that a daily quota resets when the day rolls over.
func TestDailyReset(t *testing.T) {
	m := newTestManager(t)
	now := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	m.SetClock(func() time.Time { return now })

	// Roll sets each user's period start to the current clock.
	m.Roll()
	_, _ = m.Commit("alice", 900, 0.9, "CNY", now)
	st, _ := m.Get("alice")
	if st.Consumed != 900 {
		t.Fatalf("consumed = %d", st.Consumed)
	}

	// Same day: no reset.
	now = now.Add(2 * time.Hour)
	m.Roll()
	if st, _ := m.Get("alice"); st.Consumed != 900 {
		t.Fatalf("consumption reset prematurely: %d", st.Consumed)
	}

	// Next day: reset, but lifetime persists.
	now = now.Add(24 * time.Hour)
	m.Roll()
	st, _ = m.Get("alice")
	if st.Consumed != 0 {
		t.Fatalf("daily quota did not reset: %d", st.Consumed)
	}
	if st.LifetimeConsumed != 900 {
		t.Fatalf("lifetime consumption must survive a period reset: %d", st.LifetimeConsumed)
	}
	if st.Requests != 0 {
		t.Fatalf("period request count did not reset: %d", st.Requests)
	}
}

// TestPeriodCatchUpAfterOutage verifies that a long gap does not leave the
// counter permanently behind.
func TestPeriodCatchUpAfterOutage(t *testing.T) {
	m := newTestManager(t)
	start := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	now := start
	m.SetClock(func() time.Time { return now })
	m.Roll()
	_, _ = m.Commit("alice", 500, 0.5, "CNY", now)

	// The gateway is down for a week.
	now = start.AddDate(0, 0, 7)
	m.Roll()
	st, _ := m.Get("alice")
	if st.Consumed != 0 {
		t.Fatalf("expected a reset after a week: %d", st.Consumed)
	}
	// The period start must have advanced to the current period, not lagged.
	if st.PeriodStart.Before(now.Add(-25 * time.Hour)) {
		t.Fatalf("period start lagged behind: %v vs now %v", st.PeriodStart, now)
	}
}

func TestMonthlyReset(t *testing.T) {
	m := newTestManager(t)
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	m.SetClock(func() time.Time { return now })
	m.Roll()
	_, _ = m.Commit("carol", 100, 0.1, "CNY", now)

	now = time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC)
	m.Roll()
	if st, _ := m.Get("carol"); st.Consumed != 0 {
		t.Fatalf("monthly quota did not reset: %d", st.Consumed)
	}
}

func TestSetPeriod(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.SetPeriod("bob", "weekly"); err != nil {
		t.Fatalf("SetPeriod: %v", err)
	}
	if st, _ := m.Get("bob"); st.Period != "weekly" {
		t.Fatalf("period = %q", st.Period)
	}
	if _, err := m.SetPeriod("bob", "hourly"); err == nil {
		t.Fatal("expected an error for an invalid period")
	}
}

// TestNoPeriodNeverResets verifies that period "none" is truly permanent.
func TestNoPeriodNeverResets(t *testing.T) {
	m := newTestManager(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.SetClock(func() time.Time { return now })
	_, _ = m.Commit("bob", 42, 0.1, "CNY", now)

	now = now.AddDate(2, 0, 0)
	m.Roll()
	if st, _ := m.Get("bob"); st.Consumed != 42 {
		t.Fatalf("a permanent allowance was reset: %d", st.Consumed)
	}
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

func TestStatePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	m1 := NewManager(users(), path)
	if err := m1.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, _ = m1.Commit("alice", 750, 0.75, "CNY", time.Now())
	if err := m1.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	m2 := NewManager(users(), path)
	if err := m2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	st, ok := m2.Get("alice")
	if !ok {
		t.Fatal("user missing after reload")
	}
	if st.Consumed != 750 || st.LifetimeConsumed != 750 {
		t.Fatalf("state not restored: %+v", st)
	}
}

// TestLoadMissingStateIsNotAnError verifies a first run works.
func TestLoadMissingStateIsNotAnError(t *testing.T) {
	m := NewManager(users(), filepath.Join(t.TempDir(), "absent.json"))
	if err := m.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestLoadCorruptStateFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := writeFile(path, "{not json"); err != nil {
		t.Fatal(err)
	}
	m := NewManager(users(), path)
	if err := m.Load(); err == nil {
		t.Fatal("expected an error for a corrupt state file")
	}
}

// TestSaveDisabledWhenNoPath verifies the in-memory mode used by tests.
func TestSaveDisabledWhenNoPath(t *testing.T) {
	m := NewManager(users(), "")
	if err := m.Save(); err != nil {
		t.Fatalf("Save with no path should be a no-op: %v", err)
	}
}

func TestOnChangeCallback(t *testing.T) {
	m := newTestManager(t)
	var calls int
	m.SetOnChange(func() { calls++ })
	_, _ = m.Commit("alice", 1, 0, "CNY", time.Now())
	_, _ = m.SetQuota("alice", 10)
	if calls != 2 {
		t.Fatalf("expected 2 change notifications, got %d", calls)
	}
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

func TestAggregate(t *testing.T) {
	records := []audit.Record{
		{
			Channel: "a", Model: "gpt-4o", Decision: audit.DecisionAllow,
			Usage: audit.UsageSummary{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150,
				UpstreamReported: true, Verdict: "consistent", PromptDelta: 0, CompletionDelta: 0},
			Cost:      audit.Cost{TotalCost: 0.5, Currency: "CNY"},
			LatencyMS: audit.Latency{Total: 100},
		},
		{
			Channel: "a", Model: "gpt-4o", Decision: audit.DecisionAllow,
			// Upstream billed 50% more than the recount.
			Usage: audit.UsageSummary{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150,
				UpstreamReported: true, Verdict: "over_billed", CompletionDelta: 0.5},
			Cost:      audit.Cost{TotalCost: 0.5, Currency: "CNY"},
			LatencyMS: audit.Latency{Total: 200},
		},
		{
			Channel: "b", Model: "claude-3", Decision: audit.DecisionBlockUser,
			Usage: audit.UsageSummary{Verdict: "not_reported"},
			Cost:  audit.Cost{TotalCost: 0, Currency: "CNY"},
		},
		{
			Channel: "b", Model: "claude-3", Decision: audit.DecisionUpstreamError,
			Usage: audit.UsageSummary{Verdict: "not_reported"},
			Cost:  audit.Cost{TotalCost: 0, Currency: "CNY"},
		},
	}
	models, channels := Aggregate(records)

	if len(models) != 2 {
		t.Fatalf("expected 2 model stats, got %d", len(models))
	}
	var gpt ModelStat
	for _, m := range models {
		if m.Model == "gpt-4o" {
			gpt = m
		}
	}
	if gpt.Requests != 2 || gpt.TotalTokens != 300 {
		t.Fatalf("model aggregation wrong: %+v", gpt)
	}
	if gpt.OverBilled != 1 {
		t.Fatalf("over-billed count = %d", gpt.OverBilled)
	}
	if gpt.Cost < 0.99 || gpt.Cost > 1.01 {
		t.Fatalf("cost aggregation wrong: %v", gpt.Cost)
	}

	if len(channels) != 2 {
		t.Fatalf("expected 2 channel stats, got %d", len(channels))
	}
	var chA, chB ChannelStat
	for _, c := range channels {
		switch c.Channel {
		case "a":
			chA = c
		case "b":
			chB = c
		}
	}
	if chA.Requests != 2 {
		t.Fatalf("channel a requests = %d", chA.Requests)
	}
	// Mean latency over two requests: (100+200)/2 = 150.
	if chA.MeanLatencyMS != 150 {
		t.Fatalf("mean latency = %v", chA.MeanLatencyMS)
	}
	// Usage integrity is the mean of (1-0) and (1-0.5) = 0.75.
	if chA.UsageIntegrity < 0.74 || chA.UsageIntegrity > 0.76 {
		t.Fatalf("usage integrity = %v, want ~0.75", chA.UsageIntegrity)
	}
	if chA.Verifiable != 2 {
		t.Fatalf("verifiable = %d", chA.Verifiable)
	}
	if chB.Blocked != 1 || chB.Failures != 1 {
		t.Fatalf("channel b outcomes wrong: %+v", chB)
	}
	// A channel with nothing verifiable reports full integrity rather than 0,
	// so it is not punished for an absence of evidence.
	if chB.UsageIntegrity != 1 {
		t.Fatalf("channel b integrity = %v, want 1", chB.UsageIntegrity)
	}
}

func TestAggregateEmpty(t *testing.T) {
	models, channels := Aggregate(nil)
	if len(models) != 0 || len(channels) != 0 {
		t.Fatal("aggregating nothing should produce nothing")
	}
}

func TestListSorted(t *testing.T) {
	m := newTestManager(t)
	list := m.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 users, got %d", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].Name > list[i].Name {
			t.Fatalf("users not sorted: %v", list)
		}
	}
}

func TestUpsert(t *testing.T) {
	m := newTestManager(t)
	m.Upsert(config.User{Name: "dave", Token: "t4", Quota: 77, Period: "weekly"})
	st, ok := m.Get("dave")
	if !ok {
		t.Fatal("upsert did not create the user")
	}
	if st.Quota != 77 || st.Period != "weekly" {
		t.Fatalf("upsert produced %+v", st)
	}
	// Upserting again updates rather than resetting consumption.
	_, _ = m.Commit("dave", 10, 0.1, "CNY", time.Now())
	m.Upsert(config.User{Name: "dave", Token: "t4", Quota: 100, Period: "weekly"})
	st, _ = m.Get("dave")
	if st.Quota != 100 || st.Consumed != 10 {
		t.Fatalf("re-upsert produced %+v", st)
	}
}

func TestUnknownUserOperations(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Commit("ghost", 1, 0, "CNY", time.Now()); err == nil {
		t.Fatal("expected an error committing for an unknown user")
	}
	if _, err := m.AddQuota("ghost", 1); err == nil {
		t.Fatal("expected an error adding quota for an unknown user")
	}
	if _, err := m.SetEnabled("ghost", true); err == nil {
		t.Fatal("expected an error enabling an unknown user")
	}
	if err := m.Check(config.User{Name: "ghost"}, "m"); err == nil {
		t.Fatal("expected an error checking an unknown user")
	}
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

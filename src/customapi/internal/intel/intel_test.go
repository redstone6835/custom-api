package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/redstone/customapi/internal/config"
)

// ---------------------------------------------------------------------------
// Distribution comparison
// ---------------------------------------------------------------------------

// TestJensenShannonIdentical verifies that identical distributions score zero.
func TestJensenShannonIdentical(t *testing.T) {
	a := []int{10, 20, 30, 40, 50}
	if got := JensenShannon(a, a); got != 0 {
		t.Fatalf("identical distributions diverged by %v", got)
	}
}

// TestJensenShannonDiscriminates verifies that a substituted model - one whose
// reply lengths differ materially - is separated from the baseline.
func TestJensenShannonDiscriminates(t *testing.T) {
	baseline := []int{100, 110, 120, 105, 115, 108}
	sameModel := []int{102, 108, 118, 111, 113, 106}
	substitute := []int{5, 6, 7, 5, 6, 8} // terse, cheap substitute

	near := JensenShannon(baseline, sameModel)
	far := JensenShannon(baseline, substitute)
	if !(near < far) {
		t.Fatalf("divergence did not separate the cases: same=%v different=%v", near, far)
	}
	if near > 0.35 {
		t.Fatalf("a matching model scored above the default threshold: %v", near)
	}
	if far <= 0.35 {
		t.Fatalf("a substituted model scored below the default threshold: %v", far)
	}
}

func TestJensenShannonBounded(t *testing.T) {
	a := []int{1, 1, 1}
	b := []int{1000, 1000, 1000}
	got := JensenShannon(a, b)
	if got < 0 || got > 1.001 {
		t.Fatalf("divergence out of range: %v", got)
	}
}

func TestJensenShannonEmpty(t *testing.T) {
	if got := JensenShannon(nil, []int{1}); got != 1 {
		t.Fatalf("empty input should be maximally divergent, got %v", got)
	}
}

func TestJensenShannonConstantDistributions(t *testing.T) {
	if got := JensenShannon([]int{5, 5, 5}, []int{5, 5, 5}); got != 0 {
		t.Fatalf("identical constants diverged: %v", got)
	}
	if got := JensenShannon([]int{5, 5}, []int{9, 9}); got != 1 {
		t.Fatalf("different constants should be maximally divergent, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Baseline comparison
// ---------------------------------------------------------------------------

func TestBaselineCompareNoBaseline(t *testing.T) {
	fb := NewFingerprintBaselines()
	res := fb.Compare("gpt-4o", []int{1, 2, 3}, 0.35)
	if res.Verdict != VerdictNoBaseline {
		t.Fatalf("verdict = %q", res.Verdict)
	}
}

func TestBaselineCompareMatch(t *testing.T) {
	fb := NewFingerprintBaselines()
	fb.Models["gpt-4o"] = Baseline{
		Model: "gpt-4o", Source: "official", Samples: []int{100, 105, 110, 108, 102, 106},
	}
	res := fb.Compare("gpt-4o", []int{101, 107, 109, 104, 103, 108}, 0.35)
	if res.Verdict != VerdictMatch {
		t.Fatalf("verdict = %q (score %v)", res.Verdict, res.Score)
	}
	if res.BaselineSource != "official" {
		t.Fatalf("baseline source = %q", res.BaselineSource)
	}
	if res.SampleHash == "" {
		t.Fatal("comparison should record a sample hash for reproducibility")
	}
}

func TestBaselineCompareMismatch(t *testing.T) {
	fb := NewFingerprintBaselines()
	fb.Models["gpt-4o"] = Baseline{
		Model: "gpt-4o", Source: "official", Samples: []int{200, 210, 220, 205, 215},
	}
	res := fb.Compare("gpt-4o", []int{3, 4, 3, 5, 4}, 0.35)
	if res.Verdict != VerdictMismatch {
		t.Fatalf("verdict = %q (score %v)", res.Verdict, res.Score)
	}
}

// ---------------------------------------------------------------------------
// Baseline persistence
// ---------------------------------------------------------------------------

func TestBaselineSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/baselines.json"

	fb := NewFingerprintBaselines()
	fb.Models["gpt-4o"] = Baseline{Model: "gpt-4o", Source: "official", Samples: []int{1, 2, 3}}
	if err := fb.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := LoadBaselines(path)
	if err != nil {
		t.Fatalf("LoadBaselines: %v", err)
	}
	got, ok := loaded.Models["gpt-4o"]
	if !ok {
		t.Fatal("baseline lost")
	}
	if len(got.Samples) != 3 || got.Source != "official" {
		t.Fatalf("baseline corrupted: %+v", got)
	}
}

func TestLoadBaselinesMissingIsEmpty(t *testing.T) {
	fb, err := LoadBaselines(t.TempDir() + "/absent.json")
	if err != nil {
		t.Fatalf("LoadBaselines: %v", err)
	}
	if len(fb.Models) != 0 {
		t.Fatal("expected an empty baseline set")
	}
}

func TestLoadBaselinesCorruptFails(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.json"
	if err := writeTestFile(path, "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaselines(path); err == nil {
		t.Fatal("expected an error for a corrupt baseline file")
	}
}

// ---------------------------------------------------------------------------
// Grading
// ---------------------------------------------------------------------------

// TestGradeCase exercises the objective graders. Grading must be exact enough
// that a channel cannot pass by accident, and forgiving enough that showing
// working is not punished.
func TestGradeCase(t *testing.T) {
	cases := []struct {
		name  string
		tc    BenchCase
		reply string
		want  bool
	}{
		{"exact", BenchCase{Expect: "42"}, "42", true},
		{"exact with whitespace", BenchCase{Expect: "42"}, "  42  ", true},
		{"exact with trailing punctuation", BenchCase{Expect: "42"}, "42.", true},
		{"answer prefix", BenchCase{Expect: "42"}, "The answer is 42", true},
		{"chinese answer prefix", BenchCase{Expect: "北京"}, "答案是北京", true},
		{"wrong number", BenchCase{Expect: "42"}, "43", false},
		{"number with working", BenchCase{Expect: "42"}, "17 + 25 = 42", true},
		{"wrong but contains number", BenchCase{Expect: "42"}, "17 + 25 = 43", false},
		{"contains", BenchCase{ExpectContains: []string{"yes"}}, "Yes, Tom is a mammal.", true},
		{"contains case insensitive", BenchCase{ExpectContains: []string{"Mars"}}, "the red planet is mars", true},
		{"contains missing", BenchCase{ExpectContains: []string{"Mars"}}, "Venus", false},
		{"contains numeric precision", BenchCase{ExpectContains: []string{"5"}}, "15", false},
		{"contains numeric exact", BenchCase{ExpectContains: []string{"5"}}, "5 cents", true},
		{"empty reply", BenchCase{Expect: "42"}, "", false},
		{"whitespace reply", BenchCase{Expect: "42"}, "   \n  ", false},
		{"smoke test no expectation", BenchCase{}, "anything at all", true},
		{"smoke test empty", BenchCase{}, "", false},
		{"uppercase instruction", BenchCase{Expect: "ALPHA-beta"}, "ALPHA-beta", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := GradeCase(tc.tc, tc.reply); got != tc.want {
				t.Fatalf("GradeCase(%+v, %q) = %v, want %v", tc.tc, tc.reply, got, tc.want)
			}
		})
	}
}

func TestDefaultBenchSuiteIsWellFormed(t *testing.T) {
	suite := DefaultBenchSuite()
	if len(suite) < 30 {
		t.Fatalf("suite has only %d cases; the plan calls for a layered profile", len(suite))
	}
	ids := map[string]bool{}
	cats := map[string]int{}
	levels := map[string]int{}
	for _, c := range suite {
		if c.ID == "" {
			t.Fatal("a case has no id")
		}
		if ids[c.ID] {
			t.Fatalf("duplicate case id %q", c.ID)
		}
		ids[c.ID] = true
		if c.Prompt == "" {
			t.Fatalf("case %s has no prompt", c.ID)
		}
		if c.MaxTokens <= 0 {
			t.Fatalf("case %s has no token bound, which would let a channel run away", c.ID)
		}
		if c.Expect == "" && len(c.ExpectContains) == 0 && c.ExpectRegex == "" {
			t.Fatalf("case %s has no expectation, so it cannot discriminate", c.ID)
		}
		cats[c.Category]++
		levels[c.Difficulty]++
	}
	for _, want := range []string{"math", "logic", "code", "instruction", "fact", "chinese", "reasoning"} {
		if cats[want] == 0 {
			t.Fatalf("no cases in category %q", want)
		}
	}
	for _, want := range []string{"E", "M", "H"} {
		if levels[want] == 0 {
			t.Fatalf("no cases at difficulty %q", want)
		}
	}
}

// TestGradingIsDeterministic verifies that scoring needs no judge model.
func TestGradingIsDeterministic(t *testing.T) {
	suite := DefaultBenchSuite()
	for _, c := range suite {
		a := GradeCase(c, "some reply")
		b := GradeCase(c, "some reply")
		if a != b {
			t.Fatalf("grading of %s is not deterministic", c.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Scoring assembly
// ---------------------------------------------------------------------------

func TestAssembleScores(t *testing.T) {
	reports := []BenchReport{{
		Model: "gpt-4o", Score: 0.8,
		ByCategory: map[string]float64{"math": 1.0, "code": 0.6},
		ByLevel:    map[string]float64{"E": 1.0, "H": 0.5},
	}}
	fps := []CompareResult{{Model: "gpt-4o", Verdict: VerdictMatch, Score: 0.05, Threshold: 0.35}}

	got := AssembleScores(reports, fps, 0.9, 0.95)
	sc, ok := got["gpt-4o"]
	if !ok {
		t.Fatal("no score produced")
	}
	if sc.Capability != 0.8 {
		t.Fatalf("capability = %v", sc.Capability)
	}
	if sc.FingerprintMatch != 1 {
		t.Fatalf("a match verdict should score 1, got %v", sc.FingerprintMatch)
	}
	if sc.UsageIntegrity != 0.9 || sc.Reliability != 0.95 {
		t.Fatalf("channel properties not applied: %+v", sc)
	}
	if sc.Benchmarks["math"] != 1.0 || sc.Benchmarks["level_E"] != 1.0 {
		t.Fatalf("per-category detail missing: %+v", sc.Benchmarks)
	}
}

// TestAssembleScoresMismatchScalesDown verifies that a fingerprint mismatch
// reduces the score proportionally to how far the divergence exceeded the
// threshold.
func TestAssembleScoresMismatchScalesDown(t *testing.T) {
	fps := []CompareResult{
		{Model: "gpt-4o", Verdict: VerdictMismatch, Score: 0.5, Threshold: 0.35},
	}
	got := AssembleScores(nil, fps, 1, 1)
	sc := got["gpt-4o"]
	if sc.FingerprintMatch <= 0 || sc.FingerprintMatch >= 1 {
		t.Fatalf("mismatch should scale the score below 1, got %v", sc.FingerprintMatch)
	}
}

// TestAssembleScoresNoBaselineIsNeutral verifies that an unmeasured channel is
// neither rewarded nor punished.
func TestAssembleScoresNoBaselineIsNeutral(t *testing.T) {
	fps := []CompareResult{{Model: "gpt-4o", Verdict: VerdictNoBaseline}}
	got := AssembleScores(nil, fps, 1, 1)
	if got["gpt-4o"].FingerprintMatch != 0 {
		t.Fatalf("no-baseline should leave the score unmeasured, got %v", got["gpt-4o"].FingerprintMatch)
	}
}

// ---------------------------------------------------------------------------
// Price collection
// ---------------------------------------------------------------------------

// TestCollectPricesFromNewAPI verifies the normalization of a new-api pricing
// payload, including the multiplier and flat schemes.
func TestCollectPricesFromNewAPI(t *testing.T) {
	payload := map[string]any{
		"success": true,
		"data": []map[string]any{
			{
				"model_name": "gpt-4o", "quota_type": 0,
				"model_ratio": 1.25, "completion_ratio": 4.0,
			},
			{
				"model_name": "flat-model", "quota_type": 1,
				"model_price": 3.0, "completion_ratio": 2.0,
			},
		},
		"group_ratio":       map[string]float64{"default": 1.0, "vip": 0.8},
		"usd_exchange_rate": 7.0,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	entries, err := CollectPrices(context.Background(), nil, PriceSource{
		Channel: "upstream-a", Kind: "newapi", URL: srv.URL, Currency: "USD",
	}, "default")
	if err != nil {
		t.Fatalf("CollectPrices: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	byModel := map[string]float64{}
	for _, e := range entries {
		if e.Channel != "upstream-a" {
			t.Fatalf("entry attributed to %q", e.Channel)
		}
		byModel[e.Model] = e.Price.InputPerM
	}
	// multiplier: 2.0 base * 1.25 ratio * 1.0 group * 7.0 fx = 17.5
	if byModel["gpt-4o"] != 17.5 {
		t.Fatalf("multiplier normalization = %v, want 17.5", byModel["gpt-4o"])
	}
	// flat: 3.0 * 7.0 = 21
	if byModel["flat-model"] != 21 {
		t.Fatalf("flat normalization = %v, want 21", byModel["flat-model"])
	}
}

// TestCollectPricesGroupRatio verifies that a non-default group changes the
// normalized price.
func TestCollectPricesGroupRatio(t *testing.T) {
	payload := map[string]any{
		"success": true,
		"data": []map[string]any{{
			"model_name": "m", "quota_type": 0, "model_ratio": 1.0, "completion_ratio": 1.0,
		}},
		"group_ratio": map[string]float64{"default": 1.0, "vip": 0.5},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	base, err := CollectPrices(context.Background(), nil,
		PriceSource{Channel: "c", Kind: "newapi", URL: srv.URL}, "default")
	if err != nil {
		t.Fatalf("CollectPrices: %v", err)
	}
	vip, err := CollectPrices(context.Background(), nil,
		PriceSource{Channel: "c", Kind: "newapi", URL: srv.URL}, "vip")
	if err != nil {
		t.Fatalf("CollectPrices: %v", err)
	}
	if !(vip[0].Price.InputPerM < base[0].Price.InputPerM) {
		t.Fatalf("vip group should be cheaper: %v vs %v", vip[0].Price.InputPerM, base[0].Price.InputPerM)
	}
}

func TestCollectPricesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, err := CollectPrices(context.Background(), nil,
		PriceSource{Channel: "c", Kind: "newapi", URL: srv.URL}, ""); err == nil {
		t.Fatal("expected an error for an HTTP failure")
	}
}

func TestCollectPricesUnknownKind(t *testing.T) {
	if _, err := CollectPrices(context.Background(), nil,
		PriceSource{Channel: "c", Kind: "wat", URL: "http://x"}, ""); err == nil {
		t.Fatal("expected an error for an unknown source kind")
	}
}

func TestCollectPricesSkipsUnknownQuotaType(t *testing.T) {
	payload := map[string]any{
		"success": true,
		"data": []map[string]any{
			{"model_name": "known", "quota_type": 0, "model_ratio": 1.0, "completion_ratio": 1.0},
			{"model_name": "weird", "quota_type": 99, "model_ratio": 1.0},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	entries, err := CollectPrices(context.Background(), nil,
		PriceSource{Channel: "c", Kind: "newapi", URL: srv.URL}, "")
	if err != nil {
		t.Fatalf("CollectPrices: %v", err)
	}
	// An unrecognised scheme is skipped rather than guessed at: a wrong price
	// would corrupt routing.
	if len(entries) != 1 || entries[0].Model != "known" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

// ---------------------------------------------------------------------------
// Catalogue
// ---------------------------------------------------------------------------

func TestCatalogueMergeAndSave(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/catalogue.json"

	c := NewCatalogue()
	if err := c.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	c.Merge([]config.PriceEntry{{Channel: "a", Model: "m", Price: config.PriceModel{InputPerM: 5, Currency: "CNY"}}})
	if got := len(c.Entries()); got != 1 {
		t.Fatalf("expected 1 entry, got %d", got)
	}
	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	c2 := NewCatalogue()
	if err := c2.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	entries := c2.Entries()
	if len(entries) != 1 || entries[0].Price.InputPerM != 5 {
		t.Fatalf("round-trip lost data: %+v", entries)
	}
}

func writeTestFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

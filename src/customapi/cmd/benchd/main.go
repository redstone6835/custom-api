// Command benchd is the customs intelligence daemon.
//
// It performs the work of layer L3 on a schedule:
//
//	prices       - collect and normalise upstream prices
//	fingerprint  - L1 behavioural probes against every channel
//	bench        - L2 layered capability suite
//	score        - fold the evidence into the routing scorecard
//
// It can run as a long-lived service ("run") or execute a single task and exit,
// which is what the FreeBSD rc.d script and cron entries use.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/config"
	"github.com/redstone/customapi/internal/intel"
	"github.com/redstone/customapi/internal/route"
	"github.com/redstone/customapi/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "benchd:", err)
		os.Exit(1)
	}
}

type options struct {
	configPath string
	baseURL    string
	token      string
	model      string
	channel    string
	outDir     string
	logLevel   string
	pricesURL  string
	group      string
	includeOut bool
}

func run() error {
	var (
		configPath = flag.String("config", "", "gateway configuration file (required)")
		envFile    = flag.String("env-file", "", "optional KEY=VALUE file supplying secrets")
		baseURL    = flag.String("gateway", "http://127.0.0.1:8080", "gateway base URL to probe through")
		token      = flag.String("token", "", "gateway API key used for probes (defaults to the first probe user)")
		model      = flag.String("model", "", "canonical model to probe/bench (default: all priced models)")
		channel    = flag.String("channel", "", "restrict to one channel")
		outDir     = flag.String("out", "", "output directory (defaults to the config directory)")
		logLevel   = flag.String("log-level", "info", "debug|info|warn|error")
		pricesURL  = flag.String("prices-url", "", "new-api compatible /api/pricing URL to collect from")
		group      = flag.String("group", "default", "group name for multiplier pricing")
		includeOut = flag.Bool("outcomes", false, "include per-case benchmark outcomes")
		printVer   = flag.Bool("version", false, "print build identity and exit")
	)
	flag.Parse()

	if *printVer {
		fmt.Println(version.String())
		return nil
	}
	if *configPath == "" {
		flag.Usage()
		return errors.New("--config is required")
	}
	cfg, err := config.LoadWithEnvFile(*configPath, *envFile)
	if err != nil {
		return err
	}
	opts := options{
		configPath: *configPath, baseURL: *baseURL, token: *token, model: *model,
		channel: *channel, outDir: *outDir, logLevel: *logLevel,
		pricesURL: *pricesURL, group: *group, includeOut: *includeOut,
	}
	if opts.outDir == "" {
		opts.outDir = filepath.Dir(*configPath)
	}
	if opts.token == "" {
		opts.token = probeToken(cfg)
	}
	if opts.token == "" {
		return errors.New("no probe credential: set --token, or configure a user named \"probe\" (or \"*-probe\") with unlimited quota")
	}
	logger := newLogger(*logLevel)

	cmd := "run"
	if flag.NArg() > 0 {
		cmd = flag.Arg(0)
	}
	switch cmd {
	case "prices":
		return taskPrices(context.Background(), cfg, opts, logger)
	case "fingerprint":
		return taskFingerprint(context.Background(), cfg, opts, logger)
	case "bench":
		return taskBench(context.Background(), cfg, opts, logger)
	case "score":
		return taskScore(cfg, opts, logger)
	case "run":
		return runScheduler(cfg, opts, logger)
	default:
		flag.Usage()
		return fmt.Errorf("unknown task %q", cmd)
	}
}

// probeToken selects the credential used for synthetic traffic.
//
// Probe traffic is real traffic as far as accounting is concerned, so it needs
// its own identity: an operator can then see exactly how much the intelligence
// layer costs, and exclude it from user-facing aggregates. The reserved name is
// "probe"; a "*-probe" name is also accepted so several probe identities can be
// configured (one per upstream group, for example).
func probeToken(cfg *config.Config) string {
	isProbe := func(name string) bool { return name == "probe" || strings.HasSuffix(name, "-probe") }
	// Prefer an unlimited probe identity, which is the intended setup.
	for _, u := range cfg.Users {
		if u.Quota == 0 && isProbe(u.Name) {
			return u.Token
		}
	}
	// Fall back to any probe identity, so a quota-limited one at least starts
	// the service and shows up in the ledger as it drains.
	for _, u := range cfg.Users {
		if isProbe(u.Name) {
			return u.Token
		}
	}
	return ""
}

// models returns the canonical models to probe.
func models(cfg *config.Config, opts options) []string {
	if opts.model != "" {
		return []string{opts.model}
	}
	seen := map[string]bool{}
	var out []string
	for _, ch := range cfg.AllChannels() {
		if opts.channel != "" && ch.Name != opts.channel {
			continue
		}
		for m := range ch.Models {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	for _, p := range cfg.Prices {
		if !seen[p.Model] {
			seen[p.Model] = true
			out = append(out, p.Model)
		}
	}
	return out
}

func channels(cfg *config.Config, opts options) []config.Channel {
	if opts.channel == "" {
		return cfg.AllChannels()
	}
	var out []config.Channel
	for _, ch := range cfg.AllChannels() {
		if ch.Name == opts.channel {
			out = append(out, ch)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

func taskPrices(ctx context.Context, cfg *config.Config, opts options, logger *slog.Logger) error {
	url := opts.pricesURL
	if url == "" {
		// Fall back to the first channel that looks like a new-api gateway.
		for _, ch := range cfg.AllChannels() {
			url = config.UpstreamURL(ch.BaseURL, "/api/pricing")
			break
		}
	}
	if url == "" {
		return errors.New("no price source: set --prices-url")
	}
	logger.Info("collecting prices", "url", url, "group", opts.group)
	entries, err := intel.CollectPrices(ctx, nil, intel.PriceSource{
		Channel: cfg.AllChannels()[0].Name, Kind: "newapi", URL: url,
	}, opts.group)
	if err != nil {
		return err
	}
	cat := intel.NewCatalogue()
	path := filepath.Join(opts.outDir, "var", "catalogue.json")
	_ = cat.Load(path)
	cat.Merge(entries)
	if err := cat.Save(path); err != nil {
		return err
	}
	logger.Info("price catalogue updated", "entries", len(entries), "path", path)
	fmt.Printf("collected %d price rows into %s\n", len(entries), path)
	return nil
}

func taskFingerprint(ctx context.Context, cfg *config.Config, opts options, logger *slog.Logger) error {
	baselinesPath := filepath.Join(opts.outDir, "etc", "baselines.json")
	baselines, err := intel.LoadBaselines(baselinesPath)
	if err != nil {
		return err
	}
	results := map[string]intel.ChannelResult{}
	for _, model := range models(cfg, opts) {
		for _, ch := range channels(cfg, opts) {
			if ch.UpstreamModel(model) == "" {
				continue
			}
			r := &intel.Runner{
				BaseURL: opts.baseURL, Token: opts.token, Model: model, Channel: ch.Name,
				Client: &http.Client{Timeout: 90 * time.Second}, Sleep: 250 * time.Millisecond,
			}
			res := r.Run(ctx, intel.DefaultProbes())
			key := ch.Name + "\x00" + model
			results[key] = res
			cmp := baselines.Compare(model, res.Lengths, cfg.Policy.Metering.FingerprintThreshold)
			logger.Info("fingerprint", "channel", ch.Name, "model", model,
				"probes", len(res.Lengths), "score", cmp.Score, "verdict", cmp.Verdict)
			fmt.Printf("%-14s %-24s probes=%d js=%.4f verdict=%s\n",
				ch.Name, model, len(res.Lengths), cmp.Score, cmp.Verdict)
		}
	}
	path := filepath.Join(opts.outDir, "var", "fingerprints.json")
	if err := writeJSON(path, results); err != nil {
		return err
	}
	logger.Info("fingerprint run complete", "path", path)
	return nil
}

func taskBench(ctx context.Context, cfg *config.Config, opts options, logger *slog.Logger) error {
	suite := intel.DefaultBenchSuite()
	var reports []intel.BenchReport
	for _, model := range models(cfg, opts) {
		for _, ch := range channels(cfg, opts) {
			if ch.UpstreamModel(model) == "" {
				continue
			}
			r := &intel.BenchRunner{
				BaseURL: opts.baseURL, Token: opts.token, Model: model, Channel: ch.Name,
				Client: &http.Client{Timeout: 180 * time.Second}, IncludeOutcomes: opts.includeOut,
			}
			rep := r.Run(ctx, suite)
			reports = append(reports, rep)
			logger.Info("bench", "channel", ch.Name, "model", model,
				"passed", rep.Passed, "total", rep.Total, "score", rep.Score)
			fmt.Printf("%-14s %-24s %d/%d (%.3f)\n", ch.Name, model, rep.Passed, rep.Total, rep.Score)
		}
	}
	path := filepath.Join(opts.outDir, "var", "benchmarks.json")
	if err := writeJSON(path, reports); err != nil {
		return err
	}
	logger.Info("bench run complete", "path", path)
	return nil
}

func taskScore(cfg *config.Config, opts options, logger *slog.Logger) error {
	scr, err := buildScores(cfg, opts)
	if err != nil {
		return err
	}
	path := filepath.Join(opts.outDir, "var", "scores.json")
	if err := writeJSON(path, scr); err != nil {
		return err
	}
	logger.Info("scorecard written", "path", path)
	fmt.Printf("wrote scorecard for %d channel/model pairs to %s\n", countScores(scr), path)
	return nil
}

// buildScores folds evidence files into the routing scorecard.
func buildScores(cfg *config.Config, opts options) (map[string]map[string]route.Scores, error) {
	var reports []intel.BenchReport
	if err := readJSON(filepath.Join(opts.outDir, "var", "benchmarks.json"), &reports); err != nil {
		return nil, err
	}
	fpResults := map[string]intel.ChannelResult{}
	if err := readJSON(filepath.Join(opts.outDir, "var", "fingerprints.json"), &fpResults); err != nil {
		return nil, err
	}
	baselinesPath := filepath.Join(opts.outDir, "etc", "baselines.json")
	baselines, err := intel.LoadBaselines(baselinesPath)
	if err != nil {
		return nil, err
	}

	// Group evidence by channel.
	byChannel := map[string][]intel.BenchReport{}
	for _, r := range reports {
		byChannel[r.Channel] = append(byChannel[r.Channel], r)
	}
	fpByChannel := map[string][]intel.CompareResult{}
	observed := map[string][]int{}
	for k, res := range fpResults {
		ch, model, ok := strings.Cut(k, "\x00")
		if !ok {
			continue
		}
		cmp := baselines.Compare(model, res.Lengths, cfg.Policy.Metering.FingerprintThreshold)
		fpByChannel[ch] = append(fpByChannel[ch], cmp)
		observed[ch+"\x00"+model] = res.Lengths
	}

	// Reliability and usage integrity come from the live audit ledger, which
	// is the only place that knows what actually happened in production.
	integrity, reliability := liveIntegrity(cfg, opts)

	out := map[string]map[string]route.Scores{}
	for _, ch := range cfg.AllChannels() {
		sc := intel.AssembleScores(byChannel[ch.Name], fpByChannel[ch.Name],
			integrity[ch.Name], reliability[ch.Name])
		if len(sc) > 0 {
			out[ch.Name] = sc
		}
	}
	// Carry over channels that only have fingerprint evidence.
	for ch, cmps := range fpByChannel {
		if _, ok := out[ch]; ok {
			continue
		}
		sc := intel.AssembleScores(nil, cmps, integrity[ch], reliability[ch])
		if len(sc) > 0 {
			out[ch] = sc
		}
	}
	return out, nil
}

// liveIntegrity computes per-channel usage integrity and reliability from the
// audit ledger.
func liveIntegrity(cfg *config.Config, opts options) (integrity, reliability map[string]float64) {
	integrity = map[string]float64{}
	reliability = map[string]float64{}
	ledgerPath := config.Resolve(opts.outDir, cfg.Server.AuditPath)
	records, err := audit.ReadAll(ledgerPath)
	if err != nil || len(records) == 0 {
		return integrity, reliability
	}
	type acc struct {
		verifiable int64
		sum        float64
		total      int64
		failures   int64
	}
	agg := map[string]*acc{}
	for _, r := range records {
		a, ok := agg[r.Channel]
		if !ok {
			a = &acc{}
			agg[r.Channel] = a
		}
		a.total++
		if r.Decision == audit.DecisionUpstreamError {
			a.failures++
		}
		// Integrity uses the *verdict* the gateway recorded, not a
		// re-derivation from the deltas. The gateway applies both a relative
		// tolerance and an absolute floor, and re-deriving here would silently
		// drop the floor and resurrect every false positive it exists to
		// suppress - which is exactly the bug this comment prevents.
		if r.Usage.UpstreamReported && r.Usage.Verdict != "not_reported" {
			v := 1.0
			if r.Usage.Verdict == "over_billed" || r.Usage.Verdict == "under_billed" {
				d := r.Usage.PromptDelta
				if x := r.Usage.CompletionDelta; abs(x) > abs(d) {
					d = x
				}
				v = 1 - abs(d)
				if v < 0 {
					v = 0
				}
			}
			a.verifiable++
			a.sum += v
		}
	}
	for ch, a := range agg {
		integrity[ch] = 1
		if a.verifiable > 0 {
			integrity[ch] = a.sum / float64(a.verifiable)
		}
		reliability[ch] = 1
		if a.total > 0 {
			reliability[ch] = 1 - float64(a.failures)/float64(a.total)
		}
	}
	return integrity, reliability
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

func runScheduler(cfg *config.Config, opts options, logger *slog.Logger) error {
	sched := []struct {
		name     string
		every    time.Duration
		task     func(context.Context, *config.Config, options, *slog.Logger) error
		runFirst bool
	}{
		{"prices", 30 * time.Minute, taskPrices, true},
		{"fingerprint", 20 * time.Minute, taskFingerprint, true},
		{"bench", 6 * time.Hour, taskBench, false},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, s := range sched {
		s := s
		go func() {
			if s.runFirst {
				if err := s.task(ctx, cfg, opts, logger); err != nil {
					logger.Error("task failed", "task", s.name, "err", err)
				}
			}
			t := time.NewTicker(s.every)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					if err := s.task(ctx, cfg, opts, logger); err != nil {
						logger.Error("task failed", "task", s.name, "err", err)
					}
					if err := taskScore(cfg, opts, logger); err != nil {
						logger.Error("score refresh failed", "err", err)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Hot-reload the scorecard into a running gateway via the admin API.
	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := taskScore(cfg, opts, logger); err != nil {
					logger.Error("score refresh failed", "err", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("benchd stopping", "signal", sig.String())
	cancel()
	// Give in-flight probes a moment to finish.
	time.Sleep(500 * time.Millisecond)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(path string, v any) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(b, v)
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func countScores(m map[string]map[string]route.Scores) int {
	n := 0
	for _, models := range m {
		n += len(models)
	}
	return n
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}

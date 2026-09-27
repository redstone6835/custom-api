// Command customsctl is the operator CLI for the customs gateway.
//
// It performs the tasks an administrator needs without a browser: issuing and
// adjusting quota, suspending users, browsing the audit ledger, verifying its
// integrity, and maintaining the price catalogue. Every command talks to the
// gateway's own admin API where one exists, and to files directly where the
// task is inherently offline (for example verifying a ledger).
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/config"
	"github.com/redstone/customapi/internal/meter"
	"github.com/redstone/customapi/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "customsctl:", err)
		os.Exit(1)
	}
}

const usage = `customsctl - operator CLI for the Custom-API customs gateway

Usage: customsctl <command> [flags]

Commands:
  version                     print build identity
  config check  -config FILE  validate a configuration file
  audit verify  -config FILE  verify the audit hash chain
  audit rehash  -config FILE  rebuild the chain in the current format (preserves a backup)
  audit tail    -config FILE  print the most recent audit records
  audit stats   -config FILE  aggregate usage from the audit ledger
  users list    -admin URL    list users and their quota
  users grant   -admin URL -user NAME -quota N
  users add     -admin URL -user NAME -quota N
  users suspend -admin URL -user NAME
  users resume  -admin URL -user NAME
  prices compare -model M [-input N] [-output N] -config FILE
  prices normalize -scheme S ...   convert a raw upstream price
  fingerprint baseline -config FILE -file OUT   (see also: benchd)
`

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch strings.Join(args[:min(2, len(args))], " ") {
	case "version":
		fmt.Println(version.String())
		return nil
	case "config check":
		return cmdConfigCheck(args[2:])
	case "audit verify":
		return cmdAuditVerify(args[2:])
	case "audit rehash":
		return cmdAuditRehash(args[2:])
	case "audit tail":
		return cmdAuditTail(args[2:])
	case "audit stats":
		return cmdAuditStats(args[2:])
	case "users list":
		return cmdUsersList(args[2:])
	case "users grant":
		return cmdUserAction(args[2:], "grant")
	case "users add":
		return cmdUserAction(args[2:], "add_quota")
	case "users suspend":
		return cmdUserAction(args[2:], "suspend")
	case "users resume":
		return cmdUserAction(args[2:], "resume")
	case "prices compare":
		return cmdPricesCompare(args[2:])
	case "prices normalize":
		return cmdPricesNormalize(args[2:])
	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown command %q", strings.Join(args, " "))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Offline commands
// ---------------------------------------------------------------------------

func cmdConfigCheck(args []string) error {
	fs := flag.NewFlagSet("config check", flag.ContinueOnError)
	path := fs.String("config", "", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("--config is required")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	fmt.Printf("OK: %d channel(s), %d user(s), %d price row(s)\n",
		len(cfg.AllChannels()), len(cfg.Users), len(cfg.Prices))
	fmt.Printf("    listen=%s admin=%s strategy=%s fail_mode=%s\n",
		cfg.Server.Listen, cfg.Server.AdminListen, cfg.Server.RouteStrategy, cfg.Server.FailMode)
	for _, ch := range cfg.AllChannels() {
		fmt.Printf("    channel %-12s %-28s protocol=%-9s trust=%-9s key=%v\n",
			ch.Name, ch.BaseURL, ch.Protocol, ch.TrustLevel(), ch.APIKey != "")
	}
	return nil
}

func cmdAuditVerify(args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	path := fs.String("config", "", "configuration file")
	ledger := fs.String("ledger", "", "ledger path (overrides config)")
	anchors := fs.String("anchors", "", "anchor file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	lp := *ledger
	ap := *anchors
	if lp == "" {
		if *path == "" {
			return errors.New("either --config or --ledger is required")
		}
		cfg, err := config.Load(*path)
		if err != nil {
			return err
		}
		lp = config.Resolve(dirOf(*path), cfg.Server.AuditPath)
	}
	if ap == "" {
		ap = dirOf(lp) + "/anchor.jsonl"
		if _, err := os.Stat(ap); err != nil {
			ap = ""
		}
	}
	res, err := audit.Verify(lp, ap)
	if err != nil {
		return err
	}
	fmt.Printf("ledger:      %s\n", lp)
	if ap != "" {
		fmt.Printf("anchors:     %s\n", ap)
	}
	fmt.Printf("records:     %d\n", res.Records)
	fmt.Printf("head:        seq=%d hash=%s\n", res.HeadSeq, res.HeadHash)
	if res.AnchorsChecked > 0 || res.AnchorsIgnored > 0 {
		fmt.Printf("anchors:     checked=%d ignored=%d\n", res.AnchorsChecked, res.AnchorsIgnored)
	}
	if res.OK {
		fmt.Println("result:      OK - hash chain intact")
		return nil
	}
	fmt.Printf("result:      FAILED - %d violation(s)\n", len(res.Violations))
	for _, v := range res.Violations {
		fmt.Printf("  line %-6d seq %-6d %-20s %s\n", v.Line, v.Seq, v.Kind, v.Detail)
	}
	return errors.New("audit chain verification failed")
}

// cmdAuditRehash repairs a ledger that the current code cannot verify.
//
// Two independent problems can cause that, and they need different treatment:
//
//	chain   the record hashes were computed by an older format, so every record
//	        reports a mismatch. Rebuilding recomputes them from the records'
//	        own content.
//	anchors the anchors pin the previous chain's head, so after a rebuild they
//	        disagree by construction. They are moved aside and preserved.
//
// Treating them as one operation hid the second: the chain repair reported
// "nothing to do", the anchors were never touched, and the gateway still
// refused to start. Each is now detected and repaired on its own.
func cmdAuditRehash(args []string) error {
	fs := flag.NewFlagSet("audit rehash", flag.ExitOnError)
	path := fs.String("config", "", "configuration file")
	ledger := fs.String("ledger", "", "ledger path (overrides config)")
	anchors := fs.String("anchors", "", "anchor file path")
	confirm := fs.Bool("yes", false, "confirm the rewrite")
	if err := fs.Parse(args); err != nil {
		return err
	}
	lp := *ledger
	if lp == "" {
		if *path == "" {
			return errors.New("either --config or --ledger is required")
		}
		cfg, err := config.Load(*path)
		if err != nil {
			return err
		}
		lp = config.Resolve(dirOf(*path), cfg.Server.AuditPath)
	}
	ap := *anchors
	if ap == "" {
		ap = dirOf(lp) + "/anchor.jsonl"
		if _, err := os.Stat(ap); err != nil {
			ap = ""
		}
	}

	// --- problem 1: the chain itself ------------------------------------
	chainRes, err := audit.Verify(lp, "")
	if err != nil {
		return err
	}
	chainBroken := !chainRes.OK

	// --- problem 2: anchors that no longer match ------------------------
	anchorsStale := false
	if ap != "" {
		withAnchors, verr := audit.Verify(lp, ap)
		if verr != nil {
			return verr
		}
		anchorsStale = !withAnchors.OK
	}

	if !chainBroken && !anchorsStale {
		fmt.Printf("ledger %s verifies (%d records); nothing to do\n", lp, chainRes.Records)
		return nil
	}

	if chainBroken {
		fmt.Printf("chain:   %d violation(s) across %d records\n", len(chainRes.Violations), chainRes.Records)
		for _, v := range chainRes.Violations {
			fmt.Printf("  line %-6d seq %-6d %-20s %s\n", v.Line, v.Seq, v.Kind, v.Detail)
		}
	}
	if anchorsStale {
		fmt.Printf("anchors: %s no longer match this ledger\n", ap)
	}
	fmt.Println()
	fmt.Println("Repairing recomputes record hashes from their own content and moves")
	fmt.Println("stale anchors aside. It cannot distinguish a format change from a")
	fmt.Println("genuine tampering: review the violations above before proceeding.")
	if !*confirm {
		fmt.Println()
		fmt.Println("Re-run with -yes to proceed.")
		return errors.New("rehash not confirmed")
	}

	if chainBroken {
		out, rerr := audit.Rehash(lp)
		if rerr != nil {
			return rerr
		}
		fmt.Printf("\nrewrote %d record(s), %d hash(es) changed\n", out.Records, out.Changed)
		fmt.Printf("original ledger preserved at %s\n", out.Backup)
		fmt.Printf("new head: seq=%d hash=%s\n", out.HeadSeq, out.HeadHash)
	} else {
		fmt.Println("\nchain already consistent; only the anchors need attention")
	}

	if anchorsStale && ap != "" {
		backup := ap + ".pre-rehash"
		if err := os.Rename(ap, backup); err != nil {
			return fmt.Errorf("move stale anchors aside: %w", err)
		}
		fmt.Printf("stale anchors moved to %s\n", backup)
		fmt.Println("  (they pin the previous chain's head, so they cannot match after a rebuild;")
		fmt.Println("   keep them as evidence that the chain was rebuilt on this date)")
	}

	fmt.Println("\nVerify again with: customsctl audit verify")
	return nil
}

func cmdAuditTail(args []string) error {
	fs := flag.NewFlagSet("audit tail", flag.ContinueOnError)
	path := fs.String("config", "", "configuration file")
	n := fs.Int("n", 20, "how many records to print")
	actor := fs.String("actor", "", "filter by user")
	channel := fs.String("channel", "", "filter by channel")
	verdict := fs.String("verdict", "", "filter by usage verdict")
	jsonOut := fs.Bool("json", false, "emit raw JSON records")
	if err := fs.Parse(args); err != nil {
		return err
	}
	records, err := loadRecords(*path)
	if err != nil {
		return err
	}
	filtered := records[:0]
	for _, r := range records {
		if *actor != "" && r.Actor != *actor {
			continue
		}
		if *channel != "" && r.Channel != *channel {
			continue
		}
		if *verdict != "" && r.Usage.Verdict != *verdict {
			continue
		}
		filtered = append(filtered, r)
	}
	if len(filtered) > *n {
		filtered = filtered[len(filtered)-*n:]
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		for _, r := range filtered {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEQ\tTIME\tACTOR\tCHANNEL\tMODEL\tDECISION\tTOKENS\tUPSTREAM\tVERDICT\tCOST")
	for _, r := range filtered {
		// A request can fail before any channel is chosen (no channel serves
		// the model, or the user is out of quota). Printing a bare empty
		// column would read as a display bug, so make the reason explicit.
		channel := r.Channel
		if channel == "" {
			channel = "(unrouted)"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%.6f\n",
			r.Seq, r.Time.Format("15:04:05"), r.Actor, channel, r.Model,
			r.Decision, r.Usage.TotalTokens, r.Usage.UpstreamTotalTokens,
			r.Usage.Verdict, r.Cost.TotalCost)
	}
	return tw.Flush()
}

func cmdAuditStats(args []string) error {
	fs := flag.NewFlagSet("audit stats", flag.ContinueOnError)
	path := fs.String("config", "", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	records, err := loadRecords(*path)
	if err != nil {
		return err
	}
	models := map[string]int64{}
	channels := map[string]int64{}
	verdicts := map[string]int64{}
	var totalTokens, upstreamTokens int64
	var cost float64
	for _, r := range records {
		models[r.Model]++
		// A request that failed before routing has no channel. Grouping those
		// under an explicit label keeps the breakdown readable and makes it
		// obvious that they are a distinct outcome rather than missing data.
		channel := r.Channel
		if channel == "" {
			channel = "(unrouted)"
		}
		channels[channel]++
		verdicts[r.Usage.Verdict]++
		totalTokens += int64(r.Usage.TotalTokens)
		upstreamTokens += int64(r.Usage.UpstreamTotalTokens)
		cost += r.Cost.TotalCost
	}
	fmt.Printf("records:          %d\n", len(records))
	fmt.Printf("gateway tokens:   %d\n", totalTokens)
	fmt.Printf("upstream tokens:  %d\n", upstreamTokens)
	if totalTokens > 0 {
		fmt.Printf("token inflation:  %+.2f%%\n",
			float64(upstreamTokens-totalTokens)/float64(totalTokens)*100)
	}
	fmt.Printf("total cost:       %.6f\n", cost)
	printCounts("by channel", channels)
	printCounts("by model", models)
	printCounts("by verdict", verdicts)
	return nil
}

func printCounts(title string, m map[string]int64) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("%s:\n", title)
	for _, k := range keys {
		fmt.Printf("  %-24s %d\n", k, m[k])
	}
}

// ---------------------------------------------------------------------------
// Admin API commands
// ---------------------------------------------------------------------------

var httpClient = &http.Client{Timeout: 15 * time.Second}

func cmdUsersList(args []string) error {
	fs := flag.NewFlagSet("users list", flag.ContinueOnError)
	admin := fs.String("admin", "http://127.0.0.1:8081", "admin base URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var out struct {
		Users []struct {
			Name             string    `json:"name"`
			Trust            string    `json:"trust"`
			Period           string    `json:"period"`
			Quota            int64     `json:"quota"`
			Consumed         int64     `json:"consumed"`
			LifetimeConsumed int64     `json:"lifetime_consumed"`
			Requests         int64     `json:"requests"`
			Spend            float64   `json:"spend"`
			LastSeen         time.Time `json:"last_seen"`
		} `json:"users"`
	}
	if err := getJSON(*admin+"/admin/users", &out); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "USER\tTRUST\tPERIOD\tQUOTA\tCONSUMED\tREMAINING\tREQUESTS\tSPEND\tLAST SEEN")
	for _, u := range out.Users {
		remaining := "unlimited"
		if u.Quota > 0 {
			remaining = fmt.Sprintf("%d", u.Quota-u.Consumed)
		}
		last := "-"
		if !u.LastSeen.IsZero() {
			last = u.LastSeen.Format("01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%d\t%.6f\t%s\n",
			u.Name, u.Trust, u.Period, u.Quota, u.Consumed, remaining, u.Requests, u.Spend, last)
	}
	return tw.Flush()
}

func cmdUserAction(args []string, action string) error {
	fs := flag.NewFlagSet("users "+action, flag.ContinueOnError)
	admin := fs.String("admin", "http://127.0.0.1:8081", "admin base URL")
	user := fs.String("user", "", "user name")
	quota := fs.Int64("quota", 0, "quota amount (units of 1e-6 currency)")
	period := fs.String("period", "", "reset period for set_period")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		return errors.New("--user is required")
	}
	body := map[string]any{"user": *user, "action": action, "quota": *quota}
	if *period != "" {
		body["period"] = *period
	}
	var out map[string]any
	if err := postJSON(*admin+"/admin/users", body, &out); err != nil {
		return err
	}
	b, _ := json.Marshal(out["user"])
	fmt.Printf("%s: %s\n", action, string(b))
	return nil
}

// ---------------------------------------------------------------------------
// Price commands
// ---------------------------------------------------------------------------

func cmdPricesCompare(args []string) error {
	fs := flag.NewFlagSet("prices compare", flag.ContinueOnError)
	path := fs.String("config", "", "configuration file")
	model := fs.String("model", "", "canonical model name")
	in := fs.Int64("input", 1000, "input tokens")
	out := fs.Int64("output", 500, "output tokens")
	at := fs.String("at", "", "RFC3339 instant for time-dependent promotions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("--config is required")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	instant := time.Now()
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return fmt.Errorf("invalid --at: %w", err)
		}
		instant = t
	}
	tokens := meter.Tokens{Input: *in, Output: *out}
	type row struct {
		channel  string
		trust    string
		input    float64
		output   float64
		cost     float64
		list     float64
		discount float64
		currency string
		promos   []string
	}
	var rows []row
	for _, p := range cfg.Prices {
		if *model != "" && p.Model != *model {
			continue
		}
		ch, _ := cfg.ChannelByName(p.Channel)
		q := meter.PriceWith(p.Price, tokens, instant, time.Local)
		var promos []string
		for _, ap := range q.Applied {
			promos = append(promos, fmt.Sprintf("%s×%.3f", ap.Kind, ap.Multiplier))
		}
		rows = append(rows, row{
			channel: p.Channel, trust: string(ch.TrustLevel()),
			input: p.Price.InputPerM, output: p.Price.OutputPerM,
			cost: q.Cost, list: q.ListCost, discount: q.DiscountPct,
			currency: q.Currency, promos: promos,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].cost < rows[j].cost })
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "MODEL\t%s\t(%d in / %d out tokens)\n", *model, *in, *out)
	fmt.Fprintln(tw, "CHANNEL\tTRUST\tIN/M\tOUT/M\tCUR\tLIST\tCOST\tDISC%\tPROMOTIONS")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%.4f\t%.4f\t%s\t%.6f\t%.6f\t%.2f\t%s\n",
			r.channel, r.trust, r.input, r.output, r.currency, r.list, r.cost, r.discount,
			strings.Join(r.promos, ","))
	}
	return tw.Flush()
}

func cmdPricesNormalize(args []string) error {
	fs := flag.NewFlagSet("prices normalize", flag.ContinueOnError)
	scheme := fs.String("scheme", "multiplier", "multiplier|flat|per_request|tiered|manual")
	base := fs.Float64("base", 2.0, "base price per million (multiplier scheme)")
	ratio := fs.Float64("model-ratio", 1.0, "model multiplier")
	group := fs.Float64("group-ratio", 1.0, "group multiplier")
	completion := fs.Float64("completion-ratio", 1.0, "output/input ratio")
	input := fs.Float64("input-per-m", 0, "flat input price per million")
	perReq := fs.Float64("per-request", 0, "price per request")
	typIn := fs.Int64("typical-input", 1000, "typical input tokens (per_request scheme)")
	typOut := fs.Int64("typical-output", 500, "typical output tokens (per_request scheme)")
	fx := fs.Float64("usd-cny", 7.1, "USD/CNY exchange rate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pm, err := meter.Normalize(meter.RawPrice{
		Scheme: *scheme, BasePricePerM: *base, ModelRatio: *ratio, GroupRatio: *group,
		CompletionRatio: *completion, InputPerM: *input, PerRequestPrice: *perReq,
		TypicalInput: *typIn, TypicalOutput: *typOut, Currency: "USD", ExchangeRate: *fx,
	})
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(pm, "", "  ")
	fmt.Println(string(b))
	fmt.Printf("\neffective unit price: %.6f %s per 1M tokens (for the given mix)\n",
		meter.EffectiveUnitPrice(pm, meter.Tokens{Input: *typIn, Output: *typOut}, time.Now(), time.Local),
		pm.Currency)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func loadRecords(configPath string) ([]audit.Record, error) {
	if configPath == "" {
		return nil, errors.New("--config is required")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	return audit.ReadAll(config.Resolve(dirOf(configPath), cfg.Server.AuditPath))
}

func dirOf(p string) string {
	if p == "" {
		return "."
	}
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return "."
	}
	if i == 0 {
		return "/"
	}
	return p[:i]
}

func getJSON(url string, out any) error {
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.Unmarshal(b, out)
}

func postJSON(url string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return json.Unmarshal(rb, out)
}

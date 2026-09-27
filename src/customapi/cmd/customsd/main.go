// Command customsd runs the Custom-API customs gateway.
//
// It serves two listeners:
//
//	--config/-c   the gateway configuration file
//	listen        the user-facing proxy (default 127.0.0.1:8080)
//	admin_listen  the management API (default 127.0.0.1:8081)
//
// The process is designed to run under an rc.d script on FreeBSD with no
// privileges beyond the ability to read its configuration and write its
// ledger.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/redstone/customapi/internal/audit"
	"github.com/redstone/customapi/internal/config"
	"github.com/redstone/customapi/internal/gateway"
	"github.com/redstone/customapi/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "customsd:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", "", "path to the configuration file (required)")
		envFile     = flag.String("env-file", "", "optional KEY=VALUE file supplying secrets (upstream API keys, user tokens)")
		listenFlag  = flag.String("listen", "", "override server.listen")
		adminFlag   = flag.String("admin-listen", "", "override server.admin_listen")
		logLevel    = flag.String("log-level", "", "override server.log_level (debug|info|warn|error)")
		printVer    = flag.Bool("version", false, "print the build identity and exit")
		checkOnly   = flag.Bool("check", false, "validate the configuration and exit")
		anchorEvery = flag.Duration("anchor-interval", 5*time.Minute,
			"how often to pin the audit chain head to the anchor file (0 disables)")
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
	if *listenFlag != "" {
		cfg.Server.Listen = *listenFlag
	}
	if *adminFlag != "" {
		cfg.Server.AdminListen = *adminFlag
	}
	if *logLevel != "" {
		cfg.Server.LogLevel = *logLevel
	}
	if *checkOnly {
		fmt.Printf("configuration OK: %d channel(s), %d user(s), %d price row(s)\n",
			len(cfg.AllChannels()), len(cfg.Users), len(cfg.Prices))
		return nil
	}

	logger := newLogger(cfg.Server.LogLevel)
	logger.Info("starting", "version", version.String())

	base := filepath.Dir(*configPath)
	srv, err := gateway.New(gateway.Options{Config: cfg, BaseDir: base, Logger: logger})
	if err != nil {
		return err
	}
	defer srv.Close()

	proxySrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 20 * time.Second,
		// LLM requests can legitimately take minutes; the per-request context
		// carries the real deadline.
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}
	adminSrv := &http.Server{
		Addr:              cfg.Server.AdminListen,
		Handler:           srv.AdminHandler(),
		ReadHeaderTimeout: 20 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		logger.Info("proxy listening", "addr", cfg.Server.Listen)
		if err := proxySrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("proxy listener: %w", err)
		}
	}()
	go func() {
		logger.Info("admin listening", "addr", cfg.Server.AdminListen)
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("admin listener: %w", err)
		}
	}()

	// Periodically reset expired quota periods even if no request arrives.
	rollStop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				srv.Store().Roll()
			case <-rollStop:
				return
			}
		}
	}()

	// Periodically pin the audit chain head so that a wholesale rewrite of
	// the ledger becomes detectable.
	anchorStop := make(chan struct{})
	if *anchorEvery > 0 {
		go func() {
			t := time.NewTicker(*anchorEvery)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					writeAnchor(srv, logger)
				case <-anchorStop:
					return
				}
			}
		}()
	}

	// Model discovery runs in the background. It is started after the listeners
	// so that a slow or unreachable upstream cannot delay serving traffic.
	discoveryCtx, discoveryCancel := context.WithCancel(context.Background())
	defer discoveryCancel()
	srv.StartDiscovery(discoveryCtx)

	srv.MarkReady()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		logger.Info("shutting down", "signal", sig.String())
	}
	close(rollStop)
	close(anchorStop)

	// Final anchor so the last records are covered.
	if *anchorEvery > 0 {
		writeAnchor(srv, logger)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = adminSrv.Shutdown(ctx)
	_ = proxySrv.Shutdown(ctx)
	return nil
}

// writeAnchor pins the current chain head.
func writeAnchor(srv *gateway.Server, logger *slog.Logger) {
	ledger := srv.Ledger()
	a := audit.Anchor{
		Seq:       ledger.Seq(),
		Hash:      ledger.Head(),
		Time:      time.Now().UTC(),
		Component: "customsd",
	}
	path := anchorPathFor(ledger.Path())
	if err := audit.AppendAnchor(path, a); err != nil {
		logger.Error("anchor write failed", "err", err)
		return
	}
	logger.Debug("anchored audit chain", "seq", a.Seq, "path", path)
}

func anchorPathFor(ledgerPath string) string {
	return filepath.Join(filepath.Dir(ledgerPath), "anchor.jsonl")
}

// newLogger builds the configured structured logger.
func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}

// hostPort is a small helper used by tests to pick a free port.
func hostPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, port), nil
}

var _ = hostPort

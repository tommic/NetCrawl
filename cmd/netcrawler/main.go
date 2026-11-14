package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netcrawler/internal/config"
	"netcrawler/internal/engine"
	"netcrawler/internal/envconfig"
	"netcrawler/internal/result"
)

// Exit codes.
const (
	exitOK          = 0
	exitError       = 1
	exitInterrupted = 130
)

func main() {
	os.Exit(run())
}

func run() int {
	if err := envconfig.Load(".env"); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] load .env: %v\n", err)
		return exitError
	}
	configFile := flag.String("config", envconfig.Get("CONFIG", "config.json"), "Path to crawler configuration")
	flag.Parse()

	fmt.Printf("[INFO] Loading config: %s\n", *configFile)
	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return exitError
	}

	eng, err := engine.New(cfg, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return exitError
	}
	eng.Logf = func(format string, args ...any) { fmt.Printf(format+"\n", args...) }

	plan, err := engine.BuildPlan(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return exitError
	}
	for _, j := range plan.FullyDenied {
		fmt.Printf("[INFO] Network %s fully denied (%d address(es)), skipping\n", j.Network, j.Denied)
	}
	fmt.Printf("[INFO] Scan %s, config %s\n", eng.ScanID(), eng.ConfigHash())
	fmt.Printf("[INFO] Generated %d network job(s), %d target(s), %d port(s)\n", len(plan.Jobs), plan.TotalTargets(), len(eng.Ports()))
	if !cfg.Ports.Enabled {
		fmt.Println("[INFO] Port scanning disabled via config (ports.enabled=false); no hosts will be probed")
	}

	// First Ctrl+C/SIGTERM: finish the current /24, write it, then stop.
	// Second one: abort immediately; the unfinished /24 is not written.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		if _, ok := <-signals; !ok {
			return
		}
		fmt.Fprintln(os.Stderr, "[WARN] Interrupt received: finishing current network, press Ctrl+C again to abort immediately")
		eng.RequestStop()
		if _, ok := <-signals; !ok {
			return
		}
		fmt.Fprintln(os.Stderr, "[WARN] Second interrupt: aborting, current network is not written")
		cancel()
	}()

	err = eng.Run(ctx, plan, func(r result.NetworkResult) error {
		return result.Write(cfg.Output.Directory, r, cfg.Output.PrettyPrint)
	})
	switch {
	case err == nil:
		fmt.Println("[INFO] Scan finished")
		return exitOK
	case errors.Is(err, engine.ErrStopped), errors.Is(err, context.Canceled):
		fmt.Fprintf(os.Stderr, "[WARN] Scan interrupted: %v\n", err)
		return exitInterrupted
	default:
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return exitError
	}
}

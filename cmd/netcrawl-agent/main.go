// Command netcrawl-agent polls netcrawl-server for jobs, checks them
// against its local limits, scans and reports signed results.
//
//	netcrawl-agent --config agent.json          # poll every interval
//	netcrawl-agent --config agent.json --once   # poll once and exit
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

	"netcrawler/internal/agent"
	"netcrawler/internal/version"
)

func main() {
	os.Exit(run())
}

func run() int {
	configFile := flag.String("config", "agent.json", "agent configuration")
	once := flag.Bool("once", false, "poll once and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.Version)
		return 0
	}

	logf := func(format string, args ...any) {
		fmt.Printf("%s "+format+"\n", append([]any{time.Now().UTC().Format(time.RFC3339)}, args...)...)
	}

	// Preflight: config, interval, local limits and the lock are checked
	// before any network access. A failure ends the agent here.
	cfg, err := agent.LoadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return 1
	}
	a, err := agent.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] preflight: %v\n", err)
		return 1
	}
	defer a.Close()
	a.Logf = logf
	logf("[INFO] netcrawl-agent %s started as %q", version.Version, cfg.CrawlerID)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		out, err := a.RunOnce(ctx)
		switch {
		case err != nil:
			logf("[ERROR] %v", err)
			return 1
		case out.Rejected != "":
			logf("[WARN] job %s rejected locally: %s", out.JobID, out.Rejected)
			return 2
		case out.JobID == "":
			logf("[INFO] no job")
		default:
			logf("[INFO] job %s done, result status %d", out.JobID, out.ResultStatus)
		}
		return 0
	}
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logf("[ERROR] %v", err)
		return 1
	}
	return 0
}

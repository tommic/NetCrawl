// Command netcrawl-agent polls netcrawl-server for jobs, checks them
// against its local limits, scans and reports signed results.
//
//	netcrawl-agent --config agent.json          # poll every interval
//	netcrawl-agent --config agent.json --once   # poll once and exit
//	netcrawl-agent enroll --server URL --token CODE [--tls-pin PIN] --config-dir DIR
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"netcrawler/internal/agent"
	"netcrawler/internal/version"
)

// ExitCredentialsRejected: the server no longer accepts this crawler.
const ExitCredentialsRejected = 3

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		return runEnroll(os.Args[2:])
	}
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
		if errors.Is(err, agent.ErrCredentialsRejected) {
			// The systemd unit does not restart on this status.
			logf("[ERROR] stopping. Remove this installation (uninstall command in the web UI) or, if it should keep running, reinstall it from the web UI. Check the clock with: timedatectl")
			return ExitCredentialsRejected
		}
		return 1
	}
	return 0
}

// runEnroll redeems a one-time code and writes agent.json and
// agent.secret. Used by the install script.
func runEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "server URL, e.g. https://192.168.1.5:8443")
	token := fs.String("token", "", "one-time code (default: $NETCRAWL_ENROLL_TOKEN)")
	pin := fs.String("tls-pin", "", "pinned server key sha256//… for a self-signed certificate")
	configDir := fs.String("config-dir", "/etc/netcrawl-agent", "where agent.json and agent.secret are written")
	stateDir := fs.String("state-dir", "", "where the lock file lives (default: config dir)")
	force := fs.Bool("force", false, "replace an existing agent.json")
	_ = fs.Parse(args)
	if *token == "" {
		*token = os.Getenv("NETCRAWL_ENROLL_TOKEN")
	}
	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "enroll: --server and --token are required")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := agent.Enroll(ctx, agent.EnrollOptions{
		ServerURL: *server, Token: *token, TLSPin: *pin,
		ConfigDir: *configDir, StateDir: *stateDir, Force: *force,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return 1
	}
	fmt.Printf("Enrolled as crawler %q at %s\n", cfg.CrawlerID, cfg.ServerURL)
	fmt.Printf("Release (local limit, fixed in %s/agent.json):\n", *configDir)
	fmt.Printf("  allow:      %s\n", strings.Join(cfg.Limits.Allow, ", "))
	fmt.Printf("  max_hosts:  %d\n", cfg.Limits.MaxHosts)
	fmt.Printf("  reverse_dns: %v\n", cfg.ReverseDNS)
	return 0
}

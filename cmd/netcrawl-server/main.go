// Command netcrawl-server runs the netcrawl API and offers admin commands
// that work directly on the database.
//
//	netcrawl-server serve      [--listen 127.0.0.1:8080] [--tls-cert f --tls-key f] [--secure-cookies]
//	netcrawl-server migrate
//	netcrawl-server admin set-password [--username admin]   (password from stdin)
//	netcrawl-server crawler add  --id lab-1 --allow 127.0.0.1/32 --max-hosts 1
//	netcrawl-server crawler list
//	netcrawl-server job create   --crawler lab-1 --target 127.0.0.1/32 --ports 22,80 [--ttl 5m] [--timeout-ms 500]
//	netcrawl-server job list
//	netcrawl-server job show <id>
//
// The database is taken from --database-url or NETCRAWL_DATABASE_URL.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"netcrawler/internal/eventlog"
	"netcrawler/internal/ports"
	"netcrawler/internal/server"
	"netcrawler/internal/store"
	"netcrawler/internal/store/pgstore"
	"netcrawler/internal/tlspin"
	"netcrawler/internal/version"
)

const usage = `netcrawl-server ` + "%s" + `

Usage:
  netcrawl-server serve [--listen 127.0.0.1:8080] [--tls-cert FILE --tls-key FILE | --tls-self-signed DIR]
                        [--public-url URL] [--public-tls-pin auto|none|sha256//..] [--agent-dir DIR]
                        [--secure-cookies] [--no-migrate] [--embeddable]
  netcrawl-server migrate
  netcrawl-server admin set-password [--username admin]      (reads the password from stdin)
  netcrawl-server crawler add --id ID --allow CIDR[,CIDR] --max-hosts N
  netcrawl-server crawler list
  netcrawl-server crawler install --id ID [--reverse-dns]   (one-time install command, needs --public-url)
  netcrawl-server crawler disable|enable --id ID
  netcrawl-server job create --crawler ID --target T[,T] --ports P[,P] [--ttl 5m] [--timeout-ms 500] [--max-hosts N]
  netcrawl-server job list [--limit 20]
  netcrawl-server job show JOB_ID
  netcrawl-server network add --crawler ID --name NAME --target CIDR[,..] [--deny IP,..] [--discovery-ports P,..]
                              [--scan-ports P,.. | --scan-preset top100] [--discovery-interval 30m] [--portscan-interval 24h]
                              [--offline-info 24h] [--offline-warn 168h] [--offline-critical 1h] [--no-reverse-dns]
  netcrawl-server network update --id N [--name NAME] [--target ..] [--deny ..] [--discovery-ports ..]
                              [--scan-ports P,.. | --scan-preset NAME] [--discovery-interval 30m] [--portscan-interval 30m]
                              [--offline-info 24h] [--offline-warn 168h] [--offline-critical 1h] [--reverse-dns=false] [--enabled=false]
                              (changes only the given settings; --deny "" removes all exclusions)
  netcrawl-server network list
  netcrawl-server network scan --id N [--kind discovery|ports]
  netcrawl-server hosts [--network N]
  netcrawl-server events [--network N] [--limit 50] [--baseline]

Every command accepts --database-url (default: $NETCRAWL_DATABASE_URL).
TLS and installer flags default to $NETCRAWL_TLS_CERT, $NETCRAWL_TLS_KEY,
$NETCRAWL_TLS_SELF_SIGNED_DIR, $NETCRAWL_PUBLIC_URL, $NETCRAWL_PUBLIC_TLS_PIN
and $NETCRAWL_AGENT_DIR.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Printf(usage, version.Version)
		return nil
	}
	cmd, rest := args[0], args[1:]
	if cmd == "version" {
		fmt.Println(version.Version)
		return nil
	}
	sub := ""
	if cmd == "admin" || cmd == "crawler" || cmd == "job" || cmd == "network" {
		if len(rest) == 0 {
			return fmt.Errorf("%s: missing subcommand (see --help)", cmd)
		}
		sub, rest = rest[0], rest[1:]
	}

	fs := flag.NewFlagSet(strings.TrimSpace(cmd+" "+sub), flag.ContinueOnError)
	dbURL := fs.String("database-url", os.Getenv("NETCRAWL_DATABASE_URL"), "PostgreSQL URL")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	open := func() (*pgstore.Store, error) {
		if *dbURL == "" {
			return nil, errors.New("no database: set --database-url or NETCRAWL_DATABASE_URL")
		}
		return pgstore.Open(ctx, *dbURL)
	}

	switch cmd + " " + sub {
	case "serve ":
		listen := fs.String("listen", "127.0.0.1:8080", "listen address")
		tf := addTLSFlags(fs)
		secureCookies := fs.Bool("secure-cookies", false, "set the Secure flag on session cookies (implied by --tls-cert; use behind an HTTPS proxy)")
		noMigrate := fs.Bool("no-migrate", false, "do not apply database migrations at start")
		embeddable := fs.Bool("embeddable", false, "TEST ONLY: allow the UI inside frames of other sites (cookie SameSite=None; Secure, requires HTTPS in front)")
		eventLogDir := fs.String("event-log-dir", os.Getenv("NETCRAWL_EVENT_LOG_DIR"), "directory for the JSONL event log (one file per day, kept 180 days); empty: no file log")
		schedInterval := fs.Duration("scheduler-interval", 30*time.Second, "how often the scheduler checks for due network scans")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		tlsCert, tlsKey, install, installDefaults, err := tf.resolve()
		if err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		if !*noMigrate {
			if err := migrate(ctx, st); err != nil {
				return err
			}
		}
		opts := server.Options{SecureCookies: *secureCookies || tlsCert != "", Embeddable: *embeddable, Install: install, InstallDefaults: installDefaults}
		if *eventLogDir != "" {
			w, err := eventlog.New(*eventLogDir, eventlog.DefaultRetention)
			if err != nil {
				return err
			}
			opts.EventLog = w
		}
		return serve(ctx, st, *listen, tlsCert, tlsKey, opts, *schedInterval)

	case "migrate ":
		if err := fs.Parse(rest); err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		return migrate(ctx, st)

	case "admin set-password":
		username := fs.String("username", "admin", "admin username")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Password (read from stdin, one line):")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read password: %w", err)
		}
		hash, err := server.HashPassword(strings.TrimRight(line, "\r\n"))
		if err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.SetAdmin(ctx, *username, hash); err != nil {
			return err
		}
		_ = st.Audit(ctx, "cli", "admin.set-password", map[string]string{"username": *username})
		fmt.Printf("Password for %q set.\n", *username)
		return nil

	case "crawler add":
		id := fs.String("id", "", "crawler id")
		allow := fs.String("allow", "", "comma separated allowlist")
		maxHosts := fs.Int("max-hosts", 0, "host limit per job")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		c, secret, err := server.CreateCrawler(ctx, st, "cli", server.CrawlerRequest{ID: *id, Allow: splitList(*allow), MaxHosts: *maxHosts}, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("Crawler %q created (allow %v, max hosts %d).\n\n", c.ID, c.Allow, c.MaxHosts)
		fmt.Println("Secret (shown only once, store it in the agent's secret_file with mode 600):")
		fmt.Println(secret)
		return nil

	case "crawler install":
		id := fs.String("id", "", "crawler id")
		reverseDNS := fs.Bool("reverse-dns", false, "allow the crawler PTR lookups (hostnames)")
		tf := addTLSFlags(fs)
		if err := fs.Parse(rest); err != nil {
			return err
		}
		_, _, install, defaults, err := tf.resolve()
		if err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		if install == nil {
			// Public URL set in the web UI.
			if u, err := st.Setting(ctx, server.SettingPublicURL); err == nil && u != "" {
				ic := defaults
				ic.PublicURL = u
				if !strings.HasPrefix(u, "https://") {
					ic.TLSPin = ""
				}
				install = &ic
			}
		}
		v, err := server.CreateEnrollment(ctx, st, install, "cli", *id, *reverseDNS, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("Install command for crawler %q (valid once, until %s):\n\n  %s\n\n", v.CrawlerID, v.ExpiresAt.Local().Format("2006-01-02 15:04"), v.Command)
		fmt.Printf("Review first:\n\n  %s\n\n", v.DownloadCommand)
		fmt.Println("Running it replaces the crawler's secret; an installed agent with the old secret stops working.")
		return nil

	case "crawler disable", "crawler enable":
		id := fs.String("id", "", "crawler id")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		if err := server.SetCrawlerEnabled(ctx, st, "cli", *id, sub == "enable"); err != nil {
			return err
		}
		fmt.Printf("Crawler %q %sd.\n", *id, sub)
		return nil

	case "crawler list":
		if err := fs.Parse(rest); err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		list, err := st.ListCrawlers(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tALLOW\tMAX HOSTS\tENABLED\tLAST SEEN")
		for _, c := range list {
			seen := "-"
			if c.LastSeenAt != nil {
				seen = c.LastSeenAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%v\t%s\n", c.ID, strings.Join(c.Allow, ","), c.MaxHosts, c.Enabled, seen)
		}
		return tw.Flush()

	case "job create":
		crawler := fs.String("crawler", "", "crawler id")
		target := fs.String("target", "", "comma separated targets")
		portList := fs.String("ports", "", "comma separated ports")
		ttl := fs.Duration("ttl", server.DefaultJobTTL, "time until the job expires")
		timeout := fs.Int("timeout-ms", 0, "connect timeout per port (default 500)")
		maxHosts := fs.Int("max-hosts", 0, "host limit (default: crawler limit)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		ps, err := parsePorts(*portList)
		if err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		j, err := server.CreateJob(ctx, st, "cli", server.JobRequest{
			CrawlerID: *crawler, Targets: splitList(*target), Ports: ps, MaxHosts: *maxHosts,
			TimeoutMs: *timeout, TTLSeconds: int(ttl.Seconds()),
		}, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("Job %s created for crawler %q, expires %s.\n", j.ID, j.CrawlerID, j.ExpiresAt.UTC().Format(time.RFC3339))
		return nil

	case "job list":
		limit := fs.Int("limit", 20, "number of jobs")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		list, err := st.ListJobs(ctx, *limit)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tCRAWLER\tSTATUS\tTARGETS\tPORTS\tEXPIRES")
		now := time.Now()
		for _, j := range list {
			status := j.Status
			if j.Status != store.JobCompleted && !now.Before(j.ExpiresAt) {
				status += " (expired)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", j.ID, j.CrawlerID, status, strings.Join(j.Targets, ","),
				joinInts(j.Ports), j.ExpiresAt.UTC().Format(time.RFC3339))
		}
		return tw.Flush()

	case "network add":
		crawler := fs.String("crawler", "", "crawler id")
		name := fs.String("name", "", "network name")
		target := fs.String("target", "", "comma separated targets (CIDR, address, range)")
		deny := fs.String("deny", "", "comma separated addresses/ranges to exclude")
		discPorts := fs.String("discovery-ports", "", "ports for host discovery (default: preset discovery)")
		scanPorts := fs.String("scan-ports", "", "ports for the port scan (default: --scan-preset)")
		scanPreset := fs.String("scan-preset", "", "port preset for the port scan (default top100)")
		discEvery := fs.Duration("discovery-interval", server.DefaultDiscoveryMinutes*time.Minute, "host discovery interval")
		scanEvery := fs.Duration("portscan-interval", server.DefaultPortscanHours*time.Hour, "port scan interval")
		offInfo := fs.Duration("offline-info", server.DefaultOfflineInfoHours*time.Hour, "info event when a host is gone this long")
		offWarn := fs.Duration("offline-warn", server.DefaultOfflineWarnHours*time.Hour, "warning event when a host is gone this long")
		offCrit := fs.Duration("offline-critical", server.DefaultOfflineCriticalMinutes*time.Minute, "critical event when an important host is gone this long")
		noDNS := fs.Bool("no-reverse-dns", false, "do not ask crawlers for PTR lookups")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		dp, err := parsePorts(*discPorts)
		if err != nil {
			return err
		}
		sp := portSpecs(*scanPorts)
		crit, err := wholeMinutes("offline-critical", *offCrit)
		if err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		rdns := !*noDNS
		n, err := server.CreateNetwork(ctx, st, "cli", server.NetworkRequest{
			CrawlerID: *crawler, Name: *name, Targets: splitList(*target), Deny: splitList(*deny),
			DiscoveryPorts: dp, ScanPorts: sp, ScanPreset: *scanPreset,
			DiscoveryIntervalMinute: int(discEvery.Minutes()), PortscanIntervalMinutes: int(scanEvery.Minutes()),
			OfflineInfoHours: int(offInfo.Hours()), OfflineWarnHours: int(offWarn.Hours()),
			OfflineCriticalMinutes: crit, ReverseDNS: &rdns,
		}, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("Network %d %q created for crawler %q: %s (deny: %s), discovery every %s, port scan every %s.\n",
			n.ID, n.Name, n.CrawlerID, strings.Join(n.Targets, ","), strings.Join(n.Deny, ","), n.DiscoveryInterval, n.PortscanInterval)
		fmt.Println("The running server schedules the first discovery within its scheduler interval.")
		return nil

	case "network update":
		id := fs.Int64("id", 0, "network id")
		name := fs.String("name", "", "new name")
		target := fs.String("target", "", "comma separated targets")
		deny := fs.String("deny", "", "comma separated exclusions (\"\" removes all)")
		discPorts := fs.String("discovery-ports", "", "ports for host discovery")
		scanPorts := fs.String("scan-ports", "", "ports for the port scan")
		scanPreset := fs.String("scan-preset", "", "port preset for the port scan")
		discEvery := fs.Duration("discovery-interval", 0, "host discovery interval")
		scanEvery := fs.Duration("portscan-interval", 0, "port scan interval (at least 15m)")
		offInfo := fs.Duration("offline-info", 0, "info event when a host is gone this long")
		offWarn := fs.Duration("offline-warn", 0, "warning event when a host is gone this long")
		offCrit := fs.Duration("offline-critical", 0, "critical event when an important host is gone this long")
		rdns := fs.Bool("reverse-dns", true, "ask crawlers for PTR lookups")
		enabled := fs.Bool("enabled", true, "scan this network")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		cur, err := st.Network(ctx, *id)
		if err != nil {
			return fmt.Errorf("network %d: %w", *id, err)
		}
		req := server.RequestFromNetwork(cur)
		if set["name"] {
			req.Name = *name
		}
		if set["target"] {
			req.Targets = splitList(*target)
		}
		if set["deny"] {
			req.Deny = splitList(*deny)
		}
		if set["discovery-ports"] {
			if req.DiscoveryPorts, err = parsePorts(*discPorts); err != nil {
				return err
			}
		}
		if set["scan-ports"] {
			req.ScanPorts = portSpecs(*scanPorts)
		}
		if set["scan-preset"] {
			req.ScanPorts, req.ScanPreset = nil, *scanPreset
		}
		if set["discovery-interval"] {
			req.DiscoveryIntervalMinute = int(discEvery.Minutes())
		}
		if set["portscan-interval"] {
			req.PortscanIntervalMinutes = int(scanEvery.Minutes())
		}
		if set["offline-info"] {
			req.OfflineInfoHours = int(offInfo.Hours())
		}
		if set["offline-warn"] {
			req.OfflineWarnHours = int(offWarn.Hours())
		}
		if set["offline-critical"] {
			if req.OfflineCriticalMinutes, err = wholeMinutes("offline-critical", *offCrit); err != nil {
				return err
			}
		}
		if set["reverse-dns"] {
			req.ReverseDNS = rdns
		}
		if set["enabled"] {
			req.Enabled = enabled
		}
		n, err := server.UpdateNetwork(ctx, st, "cli", *id, req)
		if err != nil {
			return err
		}
		fmt.Printf("Network %d %q updated: %s (deny: %s), discovery every %s, port scan every %s, enabled %v.\n",
			n.ID, n.Name, strings.Join(n.Targets, ","), strings.Join(n.Deny, ","), n.DiscoveryInterval, n.PortscanInterval, n.Enabled)
		fmt.Println("The running server uses the new settings for the next scheduled scan; crawlers need nothing.")
		return nil

	case "network list":
		if err := fs.Parse(rest); err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		list, err := st.ListNetworks(ctx)
		if err != nil {
			return err
		}
		hosts, err := st.Hosts(ctx, 0)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tCRAWLER\tTARGETS\tDENY\tHOSTS\tONLINE\tENABLED\tLAST DISCOVERY")
		for _, n := range list {
			total, online := 0, 0
			for _, h := range hosts {
				if h.NetworkID == n.ID {
					total++
					if h.OfflineLevel == "" {
						online++
					}
				}
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%d\t%d\t%v\t%s\n", n.ID, n.Name, n.CrawlerID, strings.Join(n.Targets, ","),
				strings.Join(n.Deny, ","), total, online, n.Enabled, fmtTime(n.DiscoveryDoneAt))
		}
		return tw.Flush()

	case "network scan":
		id := fs.Int64("id", 0, "network id")
		kind := fs.String("kind", "discovery", "discovery or ports")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		if err := server.New(st, server.Options{}).ScanNow(ctx, "cli", *id, *kind); err != nil {
			return err
		}
		fmt.Println("Job created; the crawler picks it up at its next poll.")
		return nil

	case "hosts ":
		nid := fs.Int64("network", 0, "network id (default: all)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		hosts, err := st.Hosts(ctx, *nid)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NET\tIP\tHOSTNAME\tSTATUS\tOPEN PORTS\tFIRST SEEN\tLAST SEEN")
		for _, h := range hosts {
			status := "online"
			if h.OfflineLevel != "" {
				status = "offline (" + h.OfflineLevel + ")"
			}
			if h.Important {
				status += " *"
			}
			var ps []int
			for _, p := range h.Ports {
				ps = append(ps, p.Port)
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", h.NetworkID, h.IP, h.Hostname, status, joinInts(ps),
				fmtTime(&h.FirstSeen), fmtTime(&h.LastSeen))
		}
		return tw.Flush()

	case "events ":
		nid := fs.Int64("network", 0, "network id (default: all)")
		limit := fs.Int("limit", 50, "number of events")
		baseline := fs.Bool("baseline", false, "include events of the initial inventory")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		events, err := st.ListEvents(ctx, store.EventFilter{NetworkID: *nid, Limit: *limit, IncludeBaseline: *baseline})
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "TIME\tNET\tSEVERITY\tTYPE\tMESSAGE")
		for _, e := range events {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", fmtTime(&e.At), e.NetworkID, e.Severity, e.Type, e.Message)
		}
		return tw.Flush()

	case "job show":
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("job show: expected exactly one job id")
		}
		st, err := open()
		if err != nil {
			return err
		}
		defer st.Close()
		j, err := st.Job(ctx, fs.Arg(0))
		if err != nil {
			return fmt.Errorf("job %s: %w", fs.Arg(0), err)
		}
		out := map[string]any{
			"id": j.ID, "crawler_id": j.CrawlerID, "status": j.Status, "targets": j.Targets, "ports": j.Ports,
			"max_hosts": j.MaxHosts, "timeout_ms": j.TimeoutMs, "created_by": j.CreatedBy,
			"created_at": j.CreatedAt, "expires_at": j.ExpiresAt, "delivered_at": j.DeliveredAt, "completed_at": j.CompletedAt,
		}
		if r, err := st.Result(ctx, j.ID); err == nil {
			out["result"] = json.RawMessage(r.Body)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	return fmt.Errorf("unknown command %q (see --help)", strings.TrimSpace(cmd+" "+sub))
}

func migrate(ctx context.Context, st *pgstore.Store) error {
	applied, err := st.Migrate(ctx)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if len(applied) > 0 {
		fmt.Fprintf(os.Stderr, "Applied migrations: %v\n", applied)
	}
	return nil
}

func serve(ctx context.Context, st store.Store, listen, certFile, keyFile string, opts server.Options, schedInterval time.Duration) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	opts.Logger = logger
	if opts.Embeddable {
		logger.Warn("--embeddable is set: UI may be framed by other sites; use only for test environments")
	}
	if ic := opts.Install; ic != nil {
		logger.Info("crawler installer enabled", "public_url", ic.PublicURL, "tls_pin", ic.TLSPin)
	} else {
		logger.Info("crawler installer: no --public-url, it can be set in the web UI (Crawler tab)", "tls_pin", opts.InstallDefaults.TLSPin)
	}
	for _, arch := range server.AgentArchs {
		if _, err := os.Stat(filepath.Join(opts.InstallDefaults.AgentDir, "netcrawl-agent-linux-"+arch)); err != nil {
			logger.Warn("installer: agent binary missing, installs on this architecture will fail", "arch", arch, "dir", opts.InstallDefaults.AgentDir)
		}
	}
	srv := server.New(st, opts)
	httpServer := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go srv.RunScheduler(ctx, schedInterval)
	errCh := make(chan error, 1)
	go func() {
		logger.Info("netcrawl-server listening", "addr", listen, "tls", certFile != "", "version", version.Version)
		if certFile != "" {
			errCh <- httpServer.ListenAndServeTLS(certFile, keyFile)
		} else {
			errCh <- httpServer.ListenAndServe()
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	}
}

// tlsFlags are the TLS and installer settings shared by serve and
// crawler install.
type tlsFlags struct {
	cert, key, selfSigned, publicURL, pin, agentDir *string
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func addTLSFlags(fs *flag.FlagSet) *tlsFlags {
	return &tlsFlags{
		cert:       fs.String("tls-cert", os.Getenv("NETCRAWL_TLS_CERT"), "TLS certificate file (enables HTTPS)"),
		key:        fs.String("tls-key", os.Getenv("NETCRAWL_TLS_KEY"), "TLS key file"),
		selfSigned: fs.String("tls-self-signed", os.Getenv("NETCRAWL_TLS_SELF_SIGNED_DIR"), "enable HTTPS with a self-signed certificate kept in this directory (created on first start)"),
		publicURL:  fs.String("public-url", os.Getenv("NETCRAWL_PUBLIC_URL"), "URL crawlers use to reach this server, e.g. https://192.168.1.5:8443 (enables the installer)"),
		pin:        fs.String("public-tls-pin", envOr("NETCRAWL_PUBLIC_TLS_PIN", "auto"), "pin for install commands: auto (pin a self-signed certificate), none, or sha256//..."),
		agentDir:   fs.String("agent-dir", envOr("NETCRAWL_AGENT_DIR", "/usr/local/share/netcrawl/agent"), "directory with netcrawl-agent-linux-amd64/-arm64 for the installer"),
	}
}

// resolve returns the certificate to serve (if any) and the installer
// configuration (nil without --public-url).
// resolve returns the certificate to serve (if any), the fixed installer
// configuration (nil without --public-url) and the defaults (pin, agent
// directory) used when the public URL is set in the web UI instead.
func (t *tlsFlags) resolve() (certFile, keyFile string, ic *server.InstallConfig, defaults server.InstallConfig, err error) {
	certFile, keyFile = *t.cert, *t.key
	if (certFile == "") != (keyFile == "") {
		return "", "", nil, defaults, errors.New("--tls-cert and --tls-key must be given together")
	}
	if *t.selfSigned != "" {
		if certFile != "" {
			return "", "", nil, defaults, errors.New("use either --tls-cert/--tls-key or --tls-self-signed")
		}
		var hosts []string
		if u, err := url.Parse(*t.publicURL); err == nil && u.Hostname() != "" {
			hosts = append(hosts, u.Hostname())
		}
		if certFile, keyFile, err = tlspin.SelfSigned(*t.selfSigned, hosts); err != nil {
			return "", "", nil, defaults, fmt.Errorf("self-signed certificate: %w", err)
		}
	}
	defaults = server.InstallConfig{AgentDir: *t.agentDir}
	switch p := *t.pin; p {
	case "none", "":
	case "auto":
		if certFile != "" {
			self, err := tlspin.IsSelfSigned(certFile)
			if err != nil {
				return "", "", nil, defaults, err
			}
			if self {
				if defaults.TLSPin, err = tlspin.PinFromFile(certFile); err != nil {
					return "", "", nil, defaults, err
				}
			}
		}
	default:
		defaults.TLSPin = p
	}
	if *t.publicURL == "" {
		return certFile, keyFile, nil, defaults, nil
	}
	fixed := defaults
	fixed.PublicURL = *t.publicURL
	if err := fixed.Validate(); err != nil {
		return "", "", nil, defaults, err
	}
	return certFile, keyFile, &fixed, defaults, nil
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePorts(s string) ([]int, error) {
	var out []int
	for _, p := range splitList(s) {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}

// wholeMinutes converts a duration flag to minutes, rejecting values that
// would be rounded (e.g. 30s, 90s) instead of silently changing them.
func wholeMinutes(flag string, d time.Duration) (int, error) {
	if d < time.Minute || d%time.Minute != 0 {
		return 0, fmt.Errorf("--%s must be whole minutes, e.g. 30m or 2h (got %s)", flag, d)
	}
	return int(d.Minutes()), nil
}

// portSpecs reads "22,80,8000-8100"; the server checks the entries.
func portSpecs(s string) []ports.Spec {
	var out []ports.Spec
	for _, p := range splitList(s) {
		out = append(out, ports.Spec(p))
	}
	return out
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ",")
}

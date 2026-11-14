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
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"netcrawler/internal/server"
	"netcrawler/internal/store"
	"netcrawler/internal/store/pgstore"
	"netcrawler/internal/version"
)

const usage = `netcrawl-server ` + "%s" + `

Usage:
  netcrawl-server serve [--listen 127.0.0.1:8080] [--tls-cert FILE --tls-key FILE] [--secure-cookies] [--no-migrate]
  netcrawl-server migrate
  netcrawl-server admin set-password [--username admin]      (reads the password from stdin)
  netcrawl-server crawler add --id ID --allow CIDR[,CIDR] --max-hosts N
  netcrawl-server crawler list
  netcrawl-server job create --crawler ID --target T[,T] --ports P[,P] [--ttl 5m] [--timeout-ms 500] [--max-hosts N]
  netcrawl-server job list [--limit 20]
  netcrawl-server job show JOB_ID

Every command accepts --database-url (default: $NETCRAWL_DATABASE_URL).
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
	if cmd == "admin" || cmd == "crawler" || cmd == "job" {
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
		tlsCert := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
		tlsKey := fs.String("tls-key", "", "TLS key file")
		secureCookies := fs.Bool("secure-cookies", false, "set the Secure flag on session cookies (implied by --tls-cert; use behind an HTTPS proxy)")
		noMigrate := fs.Bool("no-migrate", false, "do not apply database migrations at start")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if (*tlsCert == "") != (*tlsKey == "") {
			return errors.New("--tls-cert and --tls-key must be given together")
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
		return serve(ctx, st, *listen, *tlsCert, *tlsKey, *secureCookies || *tlsCert != "")

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

func serve(ctx context.Context, st store.Store, listen, certFile, keyFile string, secureCookies bool) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv := server.New(st, server.Options{Logger: logger, SecureCookies: secureCookies})
	httpServer := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
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

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ",")
}

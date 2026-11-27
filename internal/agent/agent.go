package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netcrawler/internal/config"
	"netcrawler/internal/engine"
	"netcrawler/internal/iprange"
	"netcrawler/internal/ports"
	"netcrawler/internal/protocol"
	"netcrawler/internal/result"
	"netcrawler/internal/scanner/probe"
	"netcrawler/internal/scanner/tcp"
	"netcrawler/internal/scope"
	"netcrawler/internal/tlspin"
	"netcrawler/internal/version"
)

// MaxJobTimeoutMs is the highest per-connection timeout a job may request.
const MaxJobTimeoutMs = 10000

// maxScanConcurrency bounds parallel connection attempts of one job.
const maxScanConcurrency = 64

// ErrLocked means another crawl holds the lock file.
var ErrLocked = errors.New("another crawl is already running (lock file is held)")

// Agent polls for jobs and executes them.
type Agent struct {
	cfg   *Config
	allow scope.Allowlist
	lock  *os.File

	// HTTP is the client for server requests. It must not follow
	// redirects (signatures cover the path).
	HTTP *http.Client
	// Dial opens scan connections (nil: net.Dialer). Tests record them.
	Dial tcp.DialFunc
	// Now returns the current time.
	Now func() time.Time
	// Logf receives log lines.
	Logf func(format string, args ...any)
	// Services identifies the services on open ports (address -> ports).
	// Default: nmap -sV if installed, else the built-in checks.
	Services func(ctx context.Context, hosts map[string][]int) map[string]map[int]probe.Service
	// interval overrides the polling interval (tests only).
	interval time.Duration
	// updateAsked is when the updater was last asked for a version.
	updateAsked time.Time
}

// New runs the preflight checks: the config is already validated by
// LoadConfig; New additionally takes the lock file so only one crawl runs
// at a time. Nothing here touches the network. Call Close to release the
// lock.
func New(cfg *Config) (*Agent, error) {
	allow, err := scope.ParseAllowlist(cfg.Limits.Allow)
	if err != nil {
		return nil, err
	}
	if err := scope.CheckRelease(cfg.Limits.Allow, cfg.Limits.MaxHosts, cfg.Limits.AllowPublicRanges); err != nil {
		return nil, err
	}
	lock, err := acquireLock(cfg.resolve(cfg.LockFile))
	if err != nil {
		return nil, err
	}
	client, err := newHTTPClient(cfg)
	if err != nil {
		lock.Close()
		return nil, err
	}
	return &Agent{
		cfg:   cfg,
		allow: allow,
		lock:  lock,
		HTTP:  client,
		Now:   time.Now,
		Logf:  func(string, ...any) {},
		Services: func(ctx context.Context, hosts map[string][]int) map[string]map[int]probe.Service {
			return probe.Services(ctx, hosts, probe.FindNmap(), serviceTimeout, maxServiceConcurrency)
		},
	}, nil
}

// Close releases the lock.
func (a *Agent) Close() error {
	if a.lock == nil {
		return nil
	}
	err := a.lock.Close()
	a.lock = nil
	return err
}

func acquireLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("lock file: %w", err)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
	return f, nil
}

func newHTTPClient(cfg *Config) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if cfg.TLSPin != "" {
		tc, err := tlspin.ClientConfig(cfg.TLSPin)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tc
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.resolve(cfg.CAFile))
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file: no certificate found")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// Outcome describes what one poll did.
type Outcome struct {
	// JobID is set when a job was received.
	JobID string
	// Rejected is the reason a received job was refused locally (no
	// connection made, no result sent).
	Rejected string
	// Targets are the addresses scanned.
	Targets []string
	// ResultStatus is the HTTP status of the result submission (0 if
	// none was sent).
	ResultStatus int
}

// Run polls immediately and then every polling interval until ctx is
// cancelled.
func (a *Agent) Run(ctx context.Context) error {
	interval := time.Duration(a.cfg.Polling.IntervalSeconds) * time.Second
	if a.interval > 0 {
		interval = a.interval
	}
	rejected := 0
	for {
		out, err := a.RunOnce(ctx)
		if errors.Is(err, errUnauthorized) {
			rejected++
		} else {
			rejected = 0
		}
		if rejected >= MaxRejectedPolls {
			a.Logf("[ERROR] %v", err)
			return ErrCredentialsRejected
		}
		switch {
		case err != nil:
			a.Logf("[ERROR] %v", err)
		case out.Rejected != "":
			a.Logf("[WARN] job %s rejected locally: %s", out.JobID, out.Rejected)
		case out.JobID == "":
			a.Logf("[INFO] no job")
		default:
			a.Logf("[INFO] job %s done, result status %d", out.JobID, out.ResultStatus)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

// MaxRejectedPolls is how many polls in a row the server may reject
// before the agent stops.
const MaxRejectedPolls = 3

var errUnauthorized = errors.New("crawler rejected by the server")

// ErrCredentialsRejected ends Run: the server rejected the crawler several
// times in a row. Usually the crawler was reinstalled (its secret was
// replaced), disabled or deleted, so this installation is obsolete.
// Clock skew of more than 5 minutes has the same effect.
var ErrCredentialsRejected = errors.New("the server rejects this crawler: it was reinstalled elsewhere (secret replaced) or disabled, or the clock is off by more than 5 minutes")

// RunOnce polls for one job and, if one is received and passes the local
// checks, scans and submits the result.
func (a *Agent) RunOnce(ctx context.Context) (Outcome, error) {
	job, err := a.poll(ctx)
	if err != nil || job == nil {
		return Outcome{}, err
	}
	out := Outcome{JobID: job.JobID}
	token, err := a.checkJob(job)
	if err != nil {
		out.Rejected = err.Error()
		return out, nil
	}
	res, targets, err := a.scan(ctx, job)
	out.Targets = targets
	if err != nil {
		return out, fmt.Errorf("scan job %s: %w", job.JobID, err)
	}
	status, err := a.submit(ctx, job, token, res)
	out.ResultStatus = status
	return out, err
}

// newSignedRequest builds a request signed with key: poll headers, or
// result headers if result is set.
func (a *Agent) newSignedRequest(ctx context.Context, method, path, jobID string, body []byte, key []byte, result bool) (*http.Request, error) {
	nonce, err := protocol.NewNonce()
	if err != nil {
		return nil, err
	}
	ts := a.Now().Unix()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.cfg.ServerURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	sig := protocol.Sign(key, protocol.SigningString(method, path, a.cfg.CrawlerID, jobID, ts, nonce, body))
	req.Header.Set(protocol.HeaderCrawlerID, a.cfg.CrawlerID)
	if result {
		req.Header.Set(protocol.HeaderResultNonce, nonce)
		req.Header.Set(protocol.HeaderResultTimestamp, strconv.FormatInt(ts, 10))
		req.Header.Set(protocol.HeaderResultHMAC, sig)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set(protocol.HeaderRequestNonce, nonce)
		req.Header.Set(protocol.HeaderRequestTimestamp, strconv.FormatInt(ts, 10))
		req.Header.Set(protocol.HeaderRequestHMAC, sig)
	}
	req.Header.Set("User-Agent", "netcrawl-agent/"+version.Version)
	return req, nil
}

func (a *Agent) poll(ctx context.Context) (*protocol.Job, error) {
	req, err := a.newSignedRequest(ctx, http.MethodGet, protocol.PathJob, "", nil, a.cfg.secret, false)
	if err != nil {
		return nil, err
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("poll: %w", err)
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		a.checkVersion(resp.Header.Get(protocol.HeaderServerVersion))
	}
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("poll: %w (server answered %d)", errUnauthorized, resp.StatusCode)
	default:
		return nil, fmt.Errorf("poll: server answered %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var job protocol.Job
	if err := json.Unmarshal(body, &job); err != nil {
		return nil, fmt.Errorf("poll: invalid job: %w", err)
	}
	return &job, nil
}

// checkJob applies the local job validation. It returns the decoded result
// token. No network access happens here.
func (a *Agent) checkJob(job *protocol.Job) ([]byte, error) {
	if !protocol.ValidJobID(job.JobID) {
		return nil, fmt.Errorf("invalid job_id %q", job.JobID)
	}
	if job.CrawlerID != a.cfg.CrawlerID {
		return nil, fmt.Errorf("job is for crawler %q, not %q", job.CrawlerID, a.cfg.CrawlerID)
	}
	if !a.Now().Before(job.ExpiresAt) {
		return nil, fmt.Errorf("job expired at %s", job.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if _, err := scope.Check(scope.Request{Targets: job.Targets, MaxHosts: job.MaxHosts, Ports: job.Ports}, a.allow, a.cfg.Limits.MaxHosts); err != nil {
		return nil, err
	}
	if job.TimeoutMs < 1 || job.TimeoutMs > MaxJobTimeoutMs {
		return nil, fmt.Errorf("timeout_ms %d outside 1-%d", job.TimeoutMs, MaxJobTimeoutMs)
	}
	switch job.Kind {
	case "", protocol.JobKindPorts, protocol.JobKindDiscovery:
	default:
		return nil, fmt.Errorf("unknown job kind %q", job.Kind)
	}
	for _, d := range job.Deny {
		if _, err := iprange.Parse(d); err != nil {
			return nil, fmt.Errorf("deny entry %q: %w", d, err)
		}
	}
	token, err := protocol.DecodeKey(job.ResultToken)
	if err != nil {
		return nil, fmt.Errorf("result token: %w", err)
	}
	return token, nil
}

// scan runs the job with the shared scan engine: TCP connect only and no
// service probes (they would open more connections than the job
// declares). Reverse DNS runs only if both the job and the local config
// ask for it. Hosts that refuse connections are reported as alive.
func (a *Agent) scan(ctx context.Context, job *protocol.Job) (protocol.Result, []string, error) {
	custom := make([]ports.Spec, len(job.Ports))
	for i, p := range job.Ports {
		custom[i] = ports.Spec(strconv.Itoa(p))
	}
	cfg := &config.Config{
		Version: 1,
		Targets: config.Targets{Include: job.Targets, Deny: job.Deny},
		Ports:   config.Ports{Enabled: true, Preset: ports.PresetCustom, Custom: custom, TimeoutMs: job.TimeoutMs},
		Hostname: config.Hostname{
			Enabled:    job.ReverseDNS && a.cfg.ReverseDNS,
			ReverseDNS: job.ReverseDNS && a.cfg.ReverseDNS,
			TimeoutMs:  config.DefaultHostnameTimeoutMs,
		},
		Enrichment:  config.Enrichment{Enabled: false, TimeoutMs: config.DefaultEnrichmentTimeoutMs},
		Performance: config.Performance{MaxConcurrentConnections: min(maxScanConcurrency, len(job.Ports)*job.MaxHosts)},
		Output:      config.Output{Directory: "-"},
	}
	started := a.Now()
	eng, err := engine.New(cfg, started)
	if err != nil {
		return protocol.Result{}, nil, err
	}
	eng.Now = a.Now
	eng.ReportAlive = true
	eng.Dial = a.Dial
	eng.Logf = a.Logf
	plan, err := engine.BuildPlan(cfg)
	if err != nil {
		return protocol.Result{}, nil, err
	}
	var targets []string
	for _, j := range plan.Jobs {
		for _, addr := range plan.Addresses(j) {
			targets = append(targets, addr.String())
		}
	}
	res := protocol.Result{
		JobID: job.JobID, CrawlerID: a.cfg.CrawlerID, AgentVersion: version.Version,
		Started: started.UTC(), Networks: []result.NetworkResult{},
	}
	err = eng.Run(ctx, plan, func(r result.NetworkResult) error {
		res.Networks = append(res.Networks, r)
		return nil
	})
	if err == nil && job.Services && !a.cfg.NoServiceDetection && a.Services != nil {
		a.addServices(ctx, &res)
	}
	res.Finished = a.Now().UTC()
	return res, targets, err
}

func (a *Agent) submit(ctx context.Context, job *protocol.Job, token []byte, res protocol.Result) (int, error) {
	body, err := json.Marshal(res)
	if err != nil {
		return 0, err
	}
	req, err := a.newSignedRequest(ctx, http.MethodPost, protocol.ResultPath(job.JobID), job.JobID, body, token, true)
	if err != nil {
		return 0, err
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("submit result: %w", err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated {
		return resp.StatusCode, fmt.Errorf("submit result: server answered %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return resp.StatusCode, nil
}

// Service detection limits: per connection, and parallel connections.
const (
	serviceTimeout        = 2 * time.Second
	maxServiceConcurrency = 32
)

// addServices identifies the services behind the open ports of res and
// adds them to the port details. Only ports the scan found open are
// contacted, so detection stays inside the job's targets and ports.
func (a *Agent) addServices(ctx context.Context, res *protocol.Result) {
	open := map[string][]int{}
	for _, n := range res.Networks {
		for ip, h := range n.Hosts {
			if len(h.Ports) > 0 {
				open[ip] = h.Ports
			}
		}
	}
	if len(open) == 0 {
		return
	}
	method := "built-in checks"
	if probe.FindNmap() != "" {
		method = "nmap -sV"
	}
	a.Logf("[INFO] Service detection on %d host(s) (%s)", len(open), method)
	found := a.Services(ctx, open)
	for i := range res.Networks {
		for ip, h := range res.Networks[i].Hosts {
			for port, s := range found[ip] {
				if h.Details == nil {
					h.Details = map[int]result.PortInfo{}
				}
				d := h.Details[port]
				d.Service, d.Product, d.ServiceVersion, d.ServiceExtra, d.ServiceMethod = s.Name, s.Product, s.Version, s.Extra, s.Method
				h.Details[port] = d
			}
			res.Networks[i].Hosts[ip] = h
		}
	}
}

// UpdateTriggerName is the file in the state directory (next to the lock
// file) that asks netcrawl-agent-update to run.
const UpdateTriggerName = "update-requested"

// updateRetry: how long to wait before asking the updater again for the
// same mismatch (e.g. no updater installed, or the update failed).
const updateRetry = time.Hour

// checkVersion asks the updater for an update when the server runs
// another version. The trigger only starts the root updater, which
// fetches and verifies the new agent from the server itself; the file's
// content is informational.
func (a *Agent) checkVersion(server string) {
	if !protocol.ValidVersion(server) || server == version.Version {
		return
	}
	if a.cfg.AutoUpdate != nil && !*a.cfg.AutoUpdate {
		return
	}
	now := a.Now()
	if !a.updateAsked.IsZero() && now.Sub(a.updateAsked) < updateRetry {
		return
	}
	a.updateAsked = now
	path := filepath.Join(filepath.Dir(a.cfg.resolve(a.cfg.LockFile)), UpdateTriggerName)
	if err := os.WriteFile(path, []byte(server+"\n"), 0o640); err != nil {
		a.Logf("[WARN] server runs %s, this crawler %s; could not ask for an update: %v", server, version.Version, err)
		return
	}
	a.Logf("[INFO] server runs %s, this crawler %s: update requested", server, version.Version)
}

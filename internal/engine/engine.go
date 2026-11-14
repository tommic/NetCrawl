// Package engine runs a scan: it turns a validated config into /24 jobs,
// scans each job (TCP connect, optional reverse DNS and service
// enrichment) and hands every finished network result to a sink. The CLI
// writes results to JSON files; a server can store them elsewhere.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netcrawler/internal/config"
	"netcrawler/internal/result"
	"netcrawler/internal/scanner/probe"
	"netcrawler/internal/scanner/tcp"
)

// ErrStopped is returned by Run when RequestStop ended the scan before all
// networks were processed. Every network finished before that was passed
// to the sink.
var ErrStopped = errors.New("scan stopped before all networks were processed")

// MaxDNSConcurrency bounds parallel reverse DNS lookups so a large scan
// doesn't flood the local resolver.
const MaxDNSConcurrency = 32

// ScanIDFormat formats the run start time (UTC) as the scan ID.
const ScanIDFormat = "20060102-150405"

// Sink receives every completed network result, in plan order.
type Sink func(result.NetworkResult) error

// Engine scans networks according to one config.
type Engine struct {
	cfg        *config.Config
	ports      []int
	scanID     string
	configHash string
	stop       atomic.Bool

	// Logf receives progress messages. Defaults to discarding them.
	Logf func(format string, args ...any)
	// Now returns the current time. Replaceable in tests.
	Now func() time.Time
	// LookupAddr resolves PTR records. Replaceable in tests.
	LookupAddr func(ctx context.Context, addr string) ([]string, error)
}

// New prepares an engine for a validated config. started is the run's
// start time, used for the scan ID.
func New(cfg *config.Config, started time.Time) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ports, err := cfg.PortList()
	if err != nil {
		return nil, err
	}
	hash, err := ConfigHash(cfg, ports)
	if err != nil {
		return nil, err
	}
	return &Engine{
		cfg:        cfg,
		ports:      ports,
		scanID:     started.UTC().Format(ScanIDFormat),
		configHash: hash,
		Logf:       func(string, ...any) {},
		Now:        time.Now,
		LookupAddr: net.DefaultResolver.LookupAddr,
	}, nil
}

// ScanID identifies this run.
func (e *Engine) ScanID() string { return e.scanID }

// ConfigHash fingerprints the scan-relevant configuration.
func (e *Engine) ConfigHash() string { return e.configHash }

// Ports returns the resolved port list (empty if port scanning is off).
func (e *Engine) Ports() []int { return e.ports }

// RequestStop asks Run to finish the network currently being scanned and
// then return ErrStopped instead of starting the next one. Safe to call
// from another goroutine, e.g. a signal handler.
func (e *Engine) RequestStop() { e.stop.Store(true) }

// ConfigHash returns "sha256:<hex>" over the parts of the config that
// influence scan results: targets, resolved ports, timeouts, hostname and
// enrichment settings. Output and performance settings are excluded, as
// they don't change what is found.
func ConfigHash(cfg *config.Config, ports []int) (string, error) {
	relevant := struct {
		Version    int               `json:"version"`
		Targets    config.Targets    `json:"targets"`
		Ports      []int             `json:"ports"`
		PortsOn    bool              `json:"portsEnabled"`
		PortTO     int               `json:"portTimeoutMs"`
		Hostname   config.Hostname   `json:"hostname"`
		Enrichment config.Enrichment `json:"enrichment"`
	}{cfg.Version, cfg.Targets, ports, cfg.Ports.Enabled, cfg.Ports.TimeoutMs, cfg.Hostname, cfg.Enrichment}
	data, err := json.Marshal(relevant)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Run scans every job of the plan in order and passes each result to sink.
//
// If ctx is cancelled, the network in progress is abandoned (its partial
// result is not passed to sink) and ctx.Err() is returned. If RequestStop
// was called, the network in progress is completed and ErrStopped is
// returned. A sink error aborts the run.
func (e *Engine) Run(ctx context.Context, plan *Plan, sink Sink) error {
	for i, job := range plan.Jobs {
		if e.stop.Load() {
			e.Logf("[INFO] Stop requested, %d network(s) not scanned", len(plan.Jobs)-i)
			return ErrStopped
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		r, err := e.ScanNetwork(ctx, job.Network, plan.Addresses(job), job.Denied)
		if err != nil {
			return err
		}
		if err := sink(r); err != nil {
			return fmt.Errorf("store result for %s: %w", job.Network, err)
		}
	}
	return nil
}

// ScanNetwork scans the given addresses of one /24 network. It returns
// ctx.Err() instead of a partial result if ctx is cancelled.
func (e *Engine) ScanNetwork(ctx context.Context, network netip.Prefix, addresses []netip.Addr, denied int) (result.NetworkResult, error) {
	cfg := e.cfg
	started := e.Now()
	e.Logf("[INFO] Scanning %s (%d target(s))", network, len(addresses))

	found := map[string][]int{}
	if cfg.Ports.Enabled && len(e.ports) > 0 {
		found = tcp.Scan(ctx, addresses, e.ports, ms(cfg.Ports.TimeoutMs), cfg.Performance.MaxConcurrentConnections)
	}
	if err := ctx.Err(); err != nil {
		return result.NetworkResult{}, err
	}

	var details map[string]map[int]probe.Info
	if cfg.Enrichment.Enabled && len(found) > 0 {
		details = probe.Enrich(ctx, found, ms(cfg.Enrichment.TimeoutMs), cfg.Performance.MaxConcurrentConnections)
	}

	ips := make([]string, 0, len(found))
	for ip := range found {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return result.CompareIPs(ips[i], ips[j]) < 0 })

	var names map[string]string
	if cfg.Hostname.Enabled && cfg.Hostname.ReverseDNS {
		names = e.resolveHostnames(ctx, ips)
	}
	if err := ctx.Err(); err != nil {
		return result.NetworkResult{}, err
	}

	hosts := make(map[string]result.Host, len(found))
	openCount := 0
	for _, ip := range ips {
		h := result.Host{Hostname: names[ip], Ports: found[ip]}
		if info, ok := details[ip]; ok {
			h.Details = make(map[int]result.PortInfo, len(info))
			for port, d := range info {
				h.Details[port] = toPortInfo(d)
			}
		}
		hosts[ip] = h
		openCount += len(h.Ports)
		e.Logf("[FOUND] %s ports=%v hostname=%s", ip, h.Ports, h.Hostname)
	}

	finished := e.Now()
	e.Logf("[INFO] %s completed in %s", network, finished.Sub(started).Round(time.Millisecond))
	return result.NetworkResult{
		SchemaVersion: result.SchemaVersion,
		ScanID:        e.scanID,
		ConfigHash:    e.configHash,
		Network:       network.String(),
		ScanStarted:   started.UTC().Format(result.TimeFormat),
		ScanFinished:  finished.UTC().Format(result.TimeFormat),
		Hosts:         hosts,
		Statistics: result.Statistics{
			Scanned:    len(addresses),
			Denied:     denied,
			Responsive: len(hosts),
			OpenPorts:  openCount,
		},
	}, nil
}

// resolveHostnames looks up PTR records for ips in parallel. Missing
// records are not errors; those hosts simply get no hostname.
func (e *Engine) resolveHostnames(ctx context.Context, ips []string) map[string]string {
	workers := min(e.cfg.Performance.MaxConcurrentConnections, MaxDNSConcurrency, len(ips))
	if workers < 1 {
		return nil
	}
	timeout := ms(e.cfg.Hostname.TimeoutMs)
	out := make(map[string]string, len(ips))
	var mu sync.Mutex
	var wg sync.WaitGroup
	queue := make(chan string)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range queue {
				lctx, cancel := context.WithTimeout(ctx, timeout)
				names, err := e.LookupAddr(lctx, ip)
				cancel()
				if err != nil || len(names) == 0 {
					continue
				}
				mu.Lock()
				out[ip] = strings.TrimSuffix(names[0], ".")
				mu.Unlock()
			}
		}()
	}
send:
	for _, ip := range ips {
		select {
		case queue <- ip:
		case <-ctx.Done():
			break send
		}
	}
	close(queue)
	wg.Wait()
	return out
}

func toPortInfo(d probe.Info) result.PortInfo {
	return result.PortInfo{
		Banner:       d.Banner,
		HTTPTitle:    d.HTTPTitle,
		HTTPServer:   d.HTTPServer,
		TLSSubject:   d.TLSSubject,
		TLSIssuer:    d.TLSIssuer,
		TLSNotAfter:  d.TLSNotAfter,
		SSHKeyType:   d.SSHKeyType,
		SSHKeyFinger: d.SSHKeyFinger,
	}
}

func ms(v int) time.Duration { return time.Duration(v) * time.Millisecond }

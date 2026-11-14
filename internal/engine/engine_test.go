package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"netcrawler/internal/config"
	"netcrawler/internal/result"
)

func mustConfig(t *testing.T, js string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBuildPlan(t *testing.T) {
	cfg := mustConfig(t, `{"version": 1,
		"targets": {
			"include": ["192.168.1.0/24", "192.168.1.10-192.168.1.20", "10.20.0.250-10.20.1.5", "192.168.2.0/30", "192.168.10.5"],
			"deny": ["192.168.1.1", "192.168.1.100/30", "192.168.2.0/24"]
		}}`)
	plan, err := BuildPlan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, j := range plan.Jobs {
		got = append(got, fmt.Sprintf("%s:%d/%d", j.Network, j.Targets, j.Denied))
	}
	// Sorted numerically; overlapping include targets counted once;
	// deny applied before jobs are created.
	want := "10.20.0.0/24:6/0 10.20.1.0/24:6/0 192.168.1.0/24:251/5 192.168.10.0/24:1/0"
	if strings.Join(got, " ") != want {
		t.Errorf("jobs = %s\nwant   %s", strings.Join(got, " "), want)
	}
	if len(plan.FullyDenied) != 1 || plan.FullyDenied[0].Network.String() != "192.168.2.0/24" || plan.FullyDenied[0].Denied != 4 {
		t.Errorf("fully denied = %+v", plan.FullyDenied)
	}
	if plan.TotalTargets() != 264 {
		t.Errorf("TotalTargets = %d, want 264", plan.TotalTargets())
	}

	addrs := plan.Addresses(plan.Jobs[0])
	if len(addrs) != 6 || addrs[0].String() != "10.20.0.250" || addrs[5].String() != "10.20.0.255" {
		t.Errorf("Addresses(10.20.0.0/24) = %v", addrs)
	}
	for _, a := range plan.Addresses(plan.Jobs[2]) {
		if a.String() == "192.168.1.1" || a.String() == "192.168.1.101" {
			t.Errorf("denied address %s in job addresses", a)
		}
	}
}

func TestBuildPlanLimits(t *testing.T) {
	cfg := mustConfig(t, `{"version": 1, "targets": {"include": ["10.0.0.0/8"]}}`)
	plan, err := BuildPlan(cfg)
	if err != nil {
		t.Fatalf("a /8 must be allowed: %v", err)
	}
	if len(plan.Jobs) != MaxNetworks {
		t.Errorf("jobs = %d, want %d", len(plan.Jobs), MaxNetworks)
	}
	for _, include := range []string{`["10.0.0.0/7"]`, `["10.0.0.0/8", "11.0.0.0/24"]`} {
		cfg := mustConfig(t, `{"version": 1, "targets": {"include": `+include+`}}`)
		if _, err := BuildPlan(cfg); err == nil {
			t.Errorf("include %s: expected size limit error", include)
		}
	}
}

func TestConfigHash(t *testing.T) {
	base := `{"version": 1, "targets": {"include": ["10.0.0.1"]}, "ports": {"enabled": true, "preset": "tiny"}, %s}`
	hash := func(extra string) string {
		cfg := mustConfig(t, fmt.Sprintf(base, extra))
		e, err := New(cfg, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return e.ConfigHash()
	}
	h := hash(`"output": {"directory": "a"}`)
	if !strings.HasPrefix(h, "sha256:") || len(h) != len("sha256:")+64 {
		t.Errorf("unexpected hash format %q", h)
	}
	if h != hash(`"output": {"directory": "b", "prettyPrint": true}, "performance": {"maxConcurrentConnections": 7}`) {
		t.Error("output/performance settings must not change the hash")
	}
	if h == hash(`"hostname": {"enabled": true, "reverseDns": true}`) {
		t.Error("hostname settings must change the hash")
	}
}

// listen opens a loopback TCP listener that accepts and closes connections.
func listen(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return p
}

// closedPort returns a loopback port that nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	p, _ := strconv.Atoi(port)
	return p
}

func loopbackEngine(t *testing.T, ports ...int) (*Engine, *Plan) {
	t.Helper()
	custom := make([]string, len(ports))
	for i, p := range ports {
		custom[i] = strconv.Itoa(p)
	}
	cfg := mustConfig(t, fmt.Sprintf(`{"version": 1,
		"targets": {"include": ["127.0.0.1"]},
		"ports": {"enabled": true, "preset": "custom", "custom": [%s], "timeoutMs": 500},
		"hostname": {"enabled": true, "reverseDns": true}}`, strings.Join(custom, ",")))
	e, err := New(cfg, time.Date(2026, 9, 5, 10, 15, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	e.LookupAddr = func(_ context.Context, addr string) ([]string, error) {
		if addr == "127.0.0.1" {
			return []string{"localhost."}, nil
		}
		return nil, errors.New("no PTR")
	}
	plan, err := BuildPlan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e, plan
}

func TestScanNetworkLoopback(t *testing.T) {
	open := listen(t)
	closed := closedPort(t)
	e, plan := loopbackEngine(t, open, closed)

	var results []result.NetworkResult
	err := e.Run(context.Background(), plan, func(r result.NetworkResult) error {
		results = append(results, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Network != "127.0.0.0/24" || r.ScanID != "20260905-101500" || r.ConfigHash != e.ConfigHash() || r.SchemaVersion != result.SchemaVersion {
		t.Errorf("metadata = %+v", r)
	}
	if _, err := time.Parse(result.TimeFormat, r.ScanStarted); err != nil {
		t.Errorf("scanStarted %q: %v", r.ScanStarted, err)
	}
	if r.ScanFinished < r.ScanStarted {
		t.Errorf("scanFinished %s before scanStarted %s", r.ScanFinished, r.ScanStarted)
	}
	h, ok := r.Hosts["127.0.0.1"]
	if !ok {
		t.Fatalf("127.0.0.1 missing: %+v", r.Hosts)
	}
	if len(h.Ports) != 1 || h.Ports[0] != open {
		t.Errorf("ports = %v, want [%d]", h.Ports, open)
	}
	if h.Hostname != "localhost" {
		t.Errorf("hostname = %q, want localhost (trailing dot trimmed)", h.Hostname)
	}
	want := result.Statistics{Scanned: 1, Denied: 0, Responsive: 1, OpenPorts: 1}
	if r.Statistics != want {
		t.Errorf("statistics = %+v, want %+v", r.Statistics, want)
	}
}

func TestRunStopFinishesCurrentNetwork(t *testing.T) {
	open := listen(t)
	e, plan := loopbackEngine(t, open)
	// Two jobs: the stop request during the first one must let it finish
	// and be stored, and prevent the second from starting.
	plan.Jobs = append(plan.Jobs, plan.Jobs[0])

	stored := 0
	err := e.Run(context.Background(), plan, func(result.NetworkResult) error {
		stored++
		e.RequestStop()
		return nil
	})
	if !errors.Is(err, ErrStopped) {
		t.Errorf("err = %v, want ErrStopped", err)
	}
	if stored != 1 {
		t.Errorf("stored %d results, want 1", stored)
	}
}

func TestRunCancelledDoesNotStorePartialResult(t *testing.T) {
	e, plan := loopbackEngine(t, listen(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := e.Run(ctx, plan, func(result.NetworkResult) error {
		t.Error("sink must not be called after cancellation")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}

	// Cancelled while scanning: ScanNetwork reports the error instead of
	// returning a partial result.
	if _, err := e.ScanNetwork(ctx, netip.MustParsePrefix("127.0.0.0/24"), plan.Addresses(plan.Jobs[0]), 0); !errors.Is(err, context.Canceled) {
		t.Errorf("ScanNetwork err = %v, want context.Canceled", err)
	}
}

func TestRunSinkError(t *testing.T) {
	e, plan := loopbackEngine(t, listen(t))
	boom := errors.New("disk full")
	err := e.Run(context.Background(), plan, func(result.NetworkResult) error { return boom })
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want sink error", err)
	}
}

func TestPortsDisabledMakesNoConnections(t *testing.T) {
	cfg := mustConfig(t, `{"version": 1, "targets": {"include": ["127.0.0.1"]}, "ports": {"enabled": false}}`)
	e, err := New(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.LookupAddr = func(context.Context, string) ([]string, error) {
		t.Error("no lookups expected without responsive hosts")
		return nil, nil
	}
	plan, _ := BuildPlan(cfg)
	var got result.NetworkResult
	if err := e.Run(context.Background(), plan, func(r result.NetworkResult) error { got = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 0 || got.Statistics.Scanned != 1 {
		t.Errorf("result = %+v", got)
	}
}

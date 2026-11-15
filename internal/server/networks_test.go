package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netcrawler/internal/eventlog"
	"netcrawler/internal/inventory"
	"netcrawler/internal/protocol"
	"netcrawler/internal/result"
	"netcrawler/internal/store"
	"netcrawler/internal/store/memstore"
)

type netFixture struct {
	*fixture
	server *Server
	logDir string
}

// newNetFixture: crawler "lan-1" released for 10.0.0.0/24 (256 hosts).
func newNetFixture(t *testing.T) *netFixture {
	t.Helper()
	f := &fixture{t: t, st: memstore.New(), now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	dir := t.TempDir()
	w, err := eventlog.New(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := New(f.st, Options{Now: func() time.Time { return f.now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), EventLog: w})
	f.srv = httptest.NewServer(s.Handler())
	t.Cleanup(f.srv.Close)
	hash, _ := HashPassword(testPassword)
	_ = f.st.SetAdmin(context.Background(), "admin", hash)
	if _, _, err := CreateCrawler(context.Background(), f.st, "test", CrawlerRequest{ID: "lan-1", Allow: []string{"10.0.0.0/24"}, MaxHosts: 256}, f.now); err != nil {
		t.Fatal(err)
	}
	return &netFixture{fixture: f, server: s, logDir: dir}
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *netFixture) jobs() []store.Job {
	jobs, _ := f.st.ListJobs(context.Background(), 100)
	return jobs
}

func TestNetworkValidation(t *testing.T) {
	f := newNetFixture(t)
	c := withCookie(f.login())
	for name, body := range map[string]string{
		"outside release": `{"crawler_id":"lan-1","name":"x","targets":["10.0.1.0/24"]}`,
		"public":          `{"crawler_id":"lan-1","name":"x","targets":["8.8.8.0/24"]}`,
		"unknown crawler": `{"crawler_id":"nope","name":"x","targets":["10.0.0.0/24"]}`,
		"no name":         `{"crawler_id":"lan-1","targets":["10.0.0.0/24"]}`,
		"bad deny":        `{"crawler_id":"lan-1","name":"x","targets":["10.0.0.0/24"],"deny":["nope"]}`,
		"interval":        `{"crawler_id":"lan-1","name":"x","targets":["10.0.0.0/24"],"discovery_interval_minutes":1}`,
		"thresholds":      `{"crawler_id":"lan-1","name":"x","targets":["10.0.0.0/24"],"offline_info_hours":48,"offline_warn_hours":24}`,
		"preset":          `{"crawler_id":"lan-1","name":"x","targets":["10.0.0.0/24"],"scan_preset":"all"}`,
	} {
		if resp := f.do("POST", "/api/v1/admin/networks", "application/json", body, c); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, resp.StatusCode)
		}
	}
}

func TestNetworkSchedulingAndInventory(t *testing.T) {
	f := newNetFixture(t)
	ctx := context.Background()
	c := withCookie(f.login())

	resp := f.do("POST", "/api/v1/admin/networks", "application/json",
		`{"crawler_id":"lan-1","name":"Heimnetz","targets":["10.0.0.0/24"],"deny":["10.0.0.1"]}`, c)
	n := decode[NetworkView](t, resp)
	if resp.StatusCode != http.StatusCreated || n.DiscoveryIntervalMinutes != 30 || n.PortscanIntervalHours != 24 ||
		len(n.ScanPorts) != 100 || len(n.DiscoveryPorts) == 0 || !n.ReverseDNS || !n.Enabled || n.OfflineWarnHours != 168 {
		t.Fatalf("create network: %d %+v", resp.StatusCode, n)
	}

	// First tick: discovery job with deny list; no port scan before a
	// discovery result exists.
	if err := f.server.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	jobs := f.jobs()
	if len(jobs) != 1 || jobs[0].Kind != protocol.JobKindDiscovery || jobs[0].NetworkID == nil || *jobs[0].NetworkID != n.ID ||
		len(jobs[0].Deny) != 1 || !jobs[0].ReverseDNS || jobs[0].CreatedBy != "scheduler" {
		t.Fatalf("after first tick: %+v", jobs)
	}
	// Not due again yet.
	f.now = f.now.Add(time.Minute)
	_ = f.server.Tick(ctx)
	if len(f.jobs()) != 1 {
		t.Fatal("second discovery job before the interval passed")
	}

	// The crawler polls, gets the job and reports two hosts.
	if resp := f.signedPollFor("lan-1"); resp.StatusCode != 200 {
		t.Fatalf("poll: %d", resp.StatusCode)
	} else if job := decode[protocol.Job](t, resp); job.Kind != protocol.JobKindDiscovery || len(job.Deny) != 1 || !job.ReverseDNS {
		t.Fatalf("delivered job = %+v", job)
	}
	f.submit(jobs[0], map[string]result.Host{
		"10.0.0.5":  {Hostname: "nas", Ports: []int{22}},
		"10.0.0.20": {Ports: []int{}},
	})
	hosts := decode[[]HostView](t, f.do("GET", "/api/v1/admin/hosts", "", "", c))
	if len(hosts) != 2 || hosts[0].IP != "10.0.0.5" || hosts[0].Hostname != "nas" || !hosts[0].Online || hosts[0].PortsScannedAt != nil {
		t.Fatalf("hosts = %+v", hosts)
	}

	// Next tick after the interval: new discovery and the first port
	// scan for the two online hosts.
	f.now = f.now.Add(30 * time.Minute)
	_ = f.server.Tick(ctx)
	var scan *store.Job
	for _, j := range f.jobs() {
		if j.Kind == protocol.JobKindPorts {
			j := j
			scan = &j
		}
	}
	if scan == nil || strings.Join(scan.Targets, ",") != "10.0.0.5/32,10.0.0.20/32" || len(scan.Ports) != 100 {
		t.Fatalf("port scan job = %+v", scan)
	}
	if len(f.jobs()) != 3 {
		t.Errorf("jobs = %d, want 3 (2 discovery, 1 port scan)", len(f.jobs()))
	}

	// Mark important via API.
	if resp := f.do("POST", "/api/v1/admin/hosts/important", "application/json", `{"network_id":1,"ip":"10.0.0.5","important":true}`, c); resp.StatusCode != http.StatusNoContent {
		t.Errorf("important: %d", resp.StatusCode)
	}
	if resp := f.do("POST", "/api/v1/admin/hosts/important", "application/json", `{"network_id":1,"ip":"10.0.0.99","important":true}`, c); resp.StatusCode != http.StatusNotFound {
		t.Errorf("important unknown host: %d", resp.StatusCode)
	}

	// Events: baseline hidden by default, visible with baseline=1.
	if ev := decode[[]EventView](t, f.do("GET", "/api/v1/admin/events", "", "", c)); len(ev) != 0 {
		t.Errorf("default events = %+v", ev)
	}
	ev := decode[[]EventView](t, f.do("GET", "/api/v1/admin/events?baseline=1", "", "", c))
	if len(ev) != 3 || ev[0].Type != inventory.TypeBaseline {
		t.Errorf("baseline events = %+v", ev)
	}
	// Event log file written.
	if data, err := readDir(f.logDir); err != nil || !strings.Contains(data, `"type":"host.new"`) || !strings.Contains(data, `"network":"Heimnetz"`) {
		t.Errorf("event log: %v %s", err, data)
	}

	nets := decode[[]NetworkView](t, f.do("GET", "/api/v1/admin/networks", "", "", c))
	if len(nets) != 1 || nets[0].Hosts != 2 || nets[0].HostsOnline != 2 || nets[0].DiscoveryDoneAt == nil || !nets[0].BaselineDone {
		t.Errorf("network view = %+v", nets)
	}
}

func TestScanNowAndUpdate(t *testing.T) {
	f := newNetFixture(t)
	ctx := context.Background()
	c := withCookie(f.login())
	f.do("POST", "/api/v1/admin/networks", "application/json", `{"crawler_id":"lan-1","name":"Heimnetz","targets":["10.0.0.0/28"]}`, c)
	_ = f.server.Tick(ctx)

	if resp := f.do("POST", "/api/v1/admin/networks/1/scan", "application/json", `{"kind":"ports"}`, c); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("port scan before discovery: %d, want 400", resp.StatusCode)
	}
	// An open discovery job prevents a second one.
	if resp := f.do("POST", "/api/v1/admin/networks/1/scan", "application/json", `{"kind":"discovery"}`, c); resp.StatusCode != http.StatusAccepted {
		t.Errorf("scan now: %d", resp.StatusCode)
	}
	if len(f.jobs()) != 1 {
		t.Errorf("jobs = %d, want 1", len(f.jobs()))
	}
	if resp := f.do("POST", "/api/v1/admin/networks/99/scan", "application/json", `{"kind":"discovery"}`, c); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown network: %d", resp.StatusCode)
	}

	// Disable: the scheduler ignores it.
	resp := f.do("PUT", "/api/v1/admin/networks/1", "application/json",
		`{"name":"Heimnetz","targets":["10.0.0.0/28"],"enabled":false,"discovery_interval_minutes":60}`, c)
	n := decode[NetworkView](t, resp)
	if resp.StatusCode != 200 || n.Enabled || n.DiscoveryIntervalMinutes != 60 || n.CrawlerID != "lan-1" {
		t.Fatalf("update: %d %+v", resp.StatusCode, n)
	}
	f.now = f.now.Add(2 * time.Hour)
	_ = f.server.Tick(ctx)
	if len(f.jobs()) != 1 {
		t.Errorf("disabled network got jobs")
	}
}

func (f *netFixture) signedPollFor(crawlerID string) *http.Response {
	c, _ := f.st.Crawler(context.Background(), crawlerID)
	f.secret = c.Secret
	return f.signedPoll(func(h http.Header, _ *int64, _ *[]byte) { h.Set(protocol.HeaderCrawlerID, crawlerID) })
}

// submit posts a signed result for a delivered job.
func (f *netFixture) submit(j store.Job, hosts map[string]result.Host) {
	f.t.Helper()
	body, _ := json.Marshal(protocol.Result{
		JobID: j.ID, CrawlerID: j.CrawlerID, Started: f.now, Finished: f.now,
		Networks: []result.NetworkResult{{Network: "10.0.0.0/24", Hosts: hosts}},
	})
	status := postResult(f.fixture, j, body)
	if status != http.StatusCreated {
		f.t.Fatalf("submit: %d", status)
	}
}

func postResult(f *fixture, j store.Job, body []byte) int {
	nonce, _ := protocol.NewNonce()
	path := protocol.ResultPath(j.ID)
	ts := f.now.Unix()
	sig := protocol.Sign(j.ResultToken, protocol.SigningString("POST", path, j.CrawlerID, j.ID, ts, nonce, body))
	return f.do("POST", path, "application/json", string(body), func(r *http.Request) {
		r.Header.Set(protocol.HeaderCrawlerID, j.CrawlerID)
		r.Header.Set(protocol.HeaderResultNonce, nonce)
		r.Header.Set(protocol.HeaderResultTimestamp, strconv.FormatInt(ts, 10))
		r.Header.Set(protocol.HeaderResultHMAC, sig)
	}).StatusCode
}

func readDir(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		b.Write(data)
	}
	return b.String(), nil
}

func TestDisabledCrawlerGetsNothing(t *testing.T) {
	f := newNetFixture(t)
	ctx := context.Background()
	resp := f.do("POST", "/api/v1/admin/networks", "application/json",
		`{"crawler_id":"lan-1","name":"LAN","targets":["10.0.0.0/24"]}`, withCookie(f.login()))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create network: %d", resp.StatusCode)
	}
	if err := f.server.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if resp := f.signedPollFor("lan-1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("poll: %d", resp.StatusCode)
	}
	delivered := f.jobs()[0]

	if err := SetCrawlerEnabled(ctx, f.st, "test", "lan-1", false); err != nil {
		t.Fatal(err)
	}
	// Results of a disabled crawler are rejected, polls fail.
	if status := postResult(f.fixture, delivered, []byte(`{}`)); status != http.StatusUnauthorized {
		t.Fatalf("result of disabled crawler: %d", status)
	}
	if resp := f.signedPollFor("lan-1"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("poll of disabled crawler: %d", resp.StatusCode)
	}
	// The scheduler creates no new jobs for it.
	before := len(f.jobs())
	f.now = f.now.Add(2 * time.Hour)
	if err := f.server.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.jobs()); n != before {
		t.Fatalf("scheduler created %d jobs for a disabled crawler", n-before)
	}
	// ... and does not fill the audit log with errors about it.
	audit, _ := f.st.ListAudit(ctx, 50)
	for _, a := range audit {
		if a.Action == "scheduler.error" {
			t.Fatalf("scheduler error for disabled crawler: %s", a.Details)
		}
	}
}

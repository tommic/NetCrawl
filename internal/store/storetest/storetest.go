// Package storetest holds conformance tests every store.Store
// implementation must pass.
package storetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"netcrawler/internal/protocol"
	"netcrawler/internal/store"
)

// Run runs all conformance tests. newStore must return an empty store.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	tests := map[string]func(*testing.T, store.Store){
		"Admins":         testAdmins,
		"Crawlers":       testCrawlers,
		"Nonces":         testNonces,
		"JobDelivery":    testJobDelivery,
		"SubmitResult":   testSubmitResult,
		"SubmitExpired":  testSubmitExpired,
		"SubmitOrdering": testSubmitOrdering,
		"Audit":          testAudit,
		"Networks":       testNetworks,
		"NetworkJobs":    testNetworkJobs,
		"Inventory":      testInventory,
		"Enrollments":    testEnrollments,
		"Notifications":  testNotifications,
		"CrawlerRelease": testCrawlerRelease,
		"ExportTokens":   testExportTokens,
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) { fn(t, newStore(t)) })
	}
}

var t0 = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func addCrawler(t *testing.T, s store.Store, id string) store.Crawler {
	t.Helper()
	secret, _ := protocol.NewKey()
	c := store.Crawler{ID: id, Secret: secret, Allow: []string{"127.0.0.1/32"}, MaxHosts: 1, Enabled: true, CreatedAt: t0}
	mustNoErr(t, s.CreateCrawler(context.Background(), c))
	return c
}

func addJob(t *testing.T, s store.Store, crawlerID string, created time.Time, ttl time.Duration) store.Job {
	t.Helper()
	id, _ := protocol.NewID()
	token, _ := protocol.NewKey()
	j := store.Job{
		ID: id, CrawlerID: crawlerID, Targets: []string{"127.0.0.1/32"}, Ports: []int{22, 80},
		MaxHosts: 1, TimeoutMs: 500, ResultToken: token, Status: store.JobPending, CreatedBy: "admin",
		CreatedAt: created, ExpiresAt: created.Add(ttl),
	}
	mustNoErr(t, s.CreateJob(context.Background(), j))
	return j
}

func testAdmins(t *testing.T, s store.Store) {
	ctx := context.Background()
	_, err := s.AdminByUsername(ctx, "admin")
	wantErr(t, err, store.ErrNotFound)

	mustNoErr(t, s.SetAdmin(ctx, "admin", "hash1"))
	a, err := s.AdminByUsername(ctx, "admin")
	mustNoErr(t, err)
	mustNoErr(t, s.SetAdmin(ctx, "admin", "hash2"))
	b, err := s.AdminByUsername(ctx, "admin")
	mustNoErr(t, err)
	if b.ID != a.ID || b.PasswordHash != "hash2" {
		t.Errorf("SetAdmin must update in place: %+v -> %+v", a, b)
	}

	token := []byte("0123456789abcdef0123456789abcdef")
	mustNoErr(t, s.CreateSession(ctx, token, a.ID, t0.Add(time.Hour)))
	got, err := s.SessionAdmin(ctx, token, t0)
	mustNoErr(t, err)
	if got.Username != "admin" {
		t.Errorf("session admin = %+v", got)
	}
	_, err = s.SessionAdmin(ctx, token, t0.Add(time.Hour))
	wantErr(t, err, store.ErrNotFound)
	mustNoErr(t, s.DeleteSession(ctx, token))
	_, err = s.SessionAdmin(ctx, token, t0)
	wantErr(t, err, store.ErrNotFound)
}

func testCrawlers(t *testing.T, s store.Store) {
	ctx := context.Background()
	c := addCrawler(t, s, "lab-2")
	addCrawler(t, s, "lab-1")
	wantErr(t, s.CreateCrawler(ctx, c), store.ErrExists)

	got, err := s.Crawler(ctx, "lab-2")
	mustNoErr(t, err)
	if string(got.Secret) != string(c.Secret) || len(got.Allow) != 1 || got.MaxHosts != 1 || !got.Enabled || got.LastSeenAt != nil {
		t.Errorf("crawler = %+v", got)
	}
	_, err = s.Crawler(ctx, "nope")
	wantErr(t, err, store.ErrNotFound)

	mustNoErr(t, s.TouchCrawler(ctx, "lab-2", t0.Add(time.Minute), "0.10.0"))
	mustNoErr(t, s.TouchCrawler(ctx, "lab-2", t0.Add(time.Minute), "")) // unknown version keeps the last one
	if c, _ := s.Crawler(ctx, "lab-2"); c.AgentVersion != "0.10.0" {
		t.Errorf("agent version = %q", c.AgentVersion)
	}
	got, _ = s.Crawler(ctx, "lab-2")
	if got.LastSeenAt == nil || !got.LastSeenAt.Equal(t0.Add(time.Minute)) {
		t.Errorf("last seen = %v", got.LastSeenAt)
	}
	wantErr(t, s.TouchCrawler(ctx, "nope", t0, ""), store.ErrNotFound)

	list, err := s.ListCrawlers(ctx)
	mustNoErr(t, err)
	if len(list) != 2 || list[0].ID != "lab-1" || list[1].ID != "lab-2" {
		t.Errorf("list = %+v", list)
	}
}

func testNonces(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	addCrawler(t, s, "lab-2")
	mustNoErr(t, s.UseNonce(ctx, "lab-1", "nonce-0000000001", t0))
	wantErr(t, s.UseNonce(ctx, "lab-1", "nonce-0000000001", t0), store.ErrReplay)
	mustNoErr(t, s.UseNonce(ctx, "lab-2", "nonce-0000000001", t0))
	mustNoErr(t, s.PurgeNonces(ctx, t0.Add(time.Second)))
	mustNoErr(t, s.UseNonce(ctx, "lab-1", "nonce-0000000001", t0.Add(time.Hour)))
}

func testJobDelivery(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	addCrawler(t, s, "lab-2")

	_, ok, err := s.NextJob(ctx, "lab-1", t0)
	mustNoErr(t, err)
	if ok {
		t.Fatal("no job expected")
	}

	expired := addJob(t, s, "lab-1", t0.Add(-time.Hour), time.Minute)
	second := addJob(t, s, "lab-1", t0.Add(2*time.Second), 5*time.Minute)
	first := addJob(t, s, "lab-1", t0.Add(time.Second), 5*time.Minute)
	other := addJob(t, s, "lab-2", t0, 5*time.Minute)

	now := t0.Add(time.Minute)
	for _, want := range []store.Job{first, second} {
		j, ok, err := s.NextJob(ctx, "lab-1", now)
		mustNoErr(t, err)
		if !ok || j.ID != want.ID {
			t.Fatalf("NextJob = %v %v, want %s", j.ID, ok, want.ID)
		}
		if j.Status != store.JobDelivered || j.DeliveredAt == nil || !j.DeliveredAt.Equal(now) {
			t.Errorf("delivered job = %+v", j)
		}
		if string(j.ResultToken) != string(want.ResultToken) || len(j.Ports) != 2 || j.Ports[1] != 80 {
			t.Errorf("job fields not preserved: %+v", j)
		}
	}
	if _, ok, _ := s.NextJob(ctx, "lab-1", now); ok {
		t.Error("expired or delivered jobs must not be handed out")
	}
	if j, _ := s.Job(ctx, expired.ID); j.Status != store.JobPending {
		t.Errorf("expired job status = %s", j.Status)
	}
	if j, ok, _ := s.NextJob(ctx, "lab-2", now); !ok || j.ID != other.ID {
		t.Error("lab-2 must get its own job")
	}

	_, err = s.Job(ctx, "00000000-0000-4000-8000-000000000000")
	wantErr(t, err, store.ErrNotFound)
	_, err = s.Job(ctx, "not-a-uuid")
	wantErr(t, err, store.ErrNotFound)

	list, err := s.ListJobs(ctx, 2)
	mustNoErr(t, err)
	if len(list) != 2 || list[0].ID != second.ID {
		t.Errorf("ListJobs newest first, limited: %+v", list)
	}

	j := addJob(t, s, "lab-1", t0, time.Minute)
	j.CrawlerID = "nope"
	j.ID, _ = protocol.NewID()
	wantErr(t, s.CreateJob(ctx, j), store.ErrNotFound)
}

func submission(j store.Job, crawlerID, nonce string, now time.Time, valid bool) store.Submission {
	body := []byte(`{"job_id":"` + j.ID + `","networks":[]}`)
	sum := sha256.Sum256(body)
	return store.Submission{
		CrawlerID: crawlerID, JobID: j.ID, Nonce: nonce, Now: now,
		Verify:     func(token []byte) bool { return valid && string(token) == string(j.ResultToken) },
		Body:       body,
		BodySHA256: sum[:],
	}
}

func testSubmitResult(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	addCrawler(t, s, "lab-2")
	j := addJob(t, s, "lab-1", t0, 5*time.Minute)
	now := t0.Add(time.Minute)

	// Not delivered yet.
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-a-000000001", now, true)), store.ErrForbidden)
	if _, ok, _ := s.NextJob(ctx, "lab-1", now); !ok {
		t.Fatal("job not delivered")
	}
	unknown := j
	unknown.ID, _ = protocol.NewID()
	wantErr(t, s.SubmitResult(ctx, submission(unknown, "lab-1", "nonce-a-000000002", now, true)), store.ErrUnauthorized)
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-2", "nonce-a-000000003", now, true)), store.ErrForbidden)
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-a-000000004", now, false)), store.ErrUnauthorized)

	sub := submission(j, "lab-1", "nonce-a-000000005", now, true)
	mustNoErr(t, s.SubmitResult(ctx, sub))
	got, err := s.Job(ctx, j.ID)
	mustNoErr(t, err)
	if got.Status != store.JobCompleted || got.CompletedAt == nil {
		t.Errorf("job after submit = %+v", got)
	}
	r, err := s.Result(ctx, j.ID)
	mustNoErr(t, err)
	var decoded map[string]any
	if err := json.Unmarshal(r.Body, &decoded); err != nil || decoded["job_id"] != j.ID {
		t.Errorf("result body = %s (%v)", r.Body, err)
	}
	if string(r.BodySHA256) != string(sub.BodySHA256) || r.CrawlerID != "lab-1" {
		t.Errorf("result = %+v", r)
	}

	// Identical resubmission and a fresh nonce are both replays.
	wantErr(t, s.SubmitResult(ctx, sub), store.ErrReplay)
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-a-000000006", now, true)), store.ErrReplay)
	_, err = s.Result(ctx, unknown.ID)
	wantErr(t, err, store.ErrNotFound)
}

func testSubmitExpired(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	j := addJob(t, s, "lab-1", t0, 5*time.Minute)
	if _, ok, _ := s.NextJob(ctx, "lab-1", t0); !ok {
		t.Fatal("job not delivered")
	}
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-e-000000001", t0.Add(5*time.Minute), true)), store.ErrExpired)
	// A rejected submission must not consume the nonce or complete the job.
	if got, _ := s.Job(ctx, j.ID); got.Status != store.JobDelivered {
		t.Errorf("status = %s", got.Status)
	}
	mustNoErr(t, s.UseNonce(ctx, "lab-1", "nonce-e-000000001", t0))
}

func testSubmitOrdering(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	j := addJob(t, s, "lab-1", t0, 5*time.Minute)
	if _, ok, _ := s.NextJob(ctx, "lab-1", t0); !ok {
		t.Fatal("job not delivered")
	}
	// A nonce already used for a job poll can't be reused for a result.
	mustNoErr(t, s.UseNonce(ctx, "lab-1", "nonce-o-000000001", t0))
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-o-000000001", t0, true)), store.ErrReplay)
	// A tampered (invalid) submission doesn't burn the job.
	wantErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-o-000000002", t0, false)), store.ErrUnauthorized)
	mustNoErr(t, s.SubmitResult(ctx, submission(j, "lab-1", "nonce-o-000000002", t0, true)))
}

func testAudit(t *testing.T, s store.Store) {
	ctx := context.Background()
	mustNoErr(t, s.Audit(ctx, "admin", "crawler.create", map[string]string{"id": "lab-1"}))
	mustNoErr(t, s.Audit(ctx, "system", "noop", nil))
	list, err := s.ListAudit(ctx, 10)
	mustNoErr(t, err)
	if len(list) != 2 || list[0].Action != "noop" || list[1].Actor != "admin" {
		t.Fatalf("audit = %+v", list)
	}
	var d map[string]string
	if err := json.Unmarshal(list[1].Details, &d); err != nil || d["id"] != "lab-1" {
		t.Errorf("details = %s", list[1].Details)
	}
	if list, _ := s.ListAudit(ctx, 1); len(list) != 1 {
		t.Errorf("limit not applied: %d", len(list))
	}
}

func addNetwork(t *testing.T, s store.Store, crawlerID, name string) store.Network {
	t.Helper()
	n := store.Network{
		CrawlerID: crawlerID, Name: name, Targets: []string{"127.0.0.0/30"}, Deny: []string{"127.0.0.3"},
		DiscoveryPorts: []int{22, 80}, ScanPorts: []int{22, 80, 443},
		DiscoveryInterval: 30 * time.Minute, PortscanInterval: 24 * time.Hour,
		OfflineInfoAfter: 24 * time.Hour, OfflineWarnAfter: 7 * 24 * time.Hour, OfflineCriticalAfter: time.Hour,
		ServiceInterval: 24 * time.Hour, ReverseDNS: true, Enabled: true, CreatedAt: t0,
	}
	id, err := s.CreateNetwork(context.Background(), n)
	mustNoErr(t, err)
	n.ID = id
	return n
}

func testNetworks(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	n := addNetwork(t, s, "lab-1", "Heimnetz")
	_, err := s.CreateNetwork(ctx, store.Network{CrawlerID: "lab-1", Name: "Heimnetz", Targets: []string{"10.0.0.0/24"},
		DiscoveryPorts: []int{22}, ScanPorts: []int{22}, DiscoveryInterval: time.Minute, PortscanInterval: time.Minute,
		OfflineInfoAfter: time.Minute, OfflineWarnAfter: time.Minute, OfflineCriticalAfter: time.Minute, ServiceInterval: time.Minute, CreatedAt: t0})
	wantErr(t, err, store.ErrExists)
	_, err = s.CreateNetwork(ctx, store.Network{CrawlerID: "nope", Name: "x", Targets: []string{"10.0.0.0/24"},
		DiscoveryPorts: []int{22}, ScanPorts: []int{22}, DiscoveryInterval: time.Minute, PortscanInterval: time.Minute,
		OfflineInfoAfter: time.Minute, OfflineWarnAfter: time.Minute, OfflineCriticalAfter: time.Minute, ServiceInterval: time.Minute, CreatedAt: t0})
	wantErr(t, err, store.ErrNotFound)

	got, err := s.Network(ctx, n.ID)
	mustNoErr(t, err)
	if got.Name != "Heimnetz" || len(got.Targets) != 1 || len(got.Deny) != 1 || len(got.ScanPorts) != 3 ||
		got.DiscoveryInterval != 30*time.Minute || got.OfflineWarnAfter != 7*24*time.Hour || got.OfflineCriticalAfter != time.Hour || !got.ReverseDNS ||
		!got.Enabled || got.BaselineDone || got.LastDiscoveryAt != nil {
		t.Errorf("network = %+v", got)
	}

	got.Name, got.Enabled, got.DiscoveryInterval, got.Deny = "Büro", false, time.Hour, nil
	got.OfflineCriticalAfter = 15 * time.Minute
	mustNoErr(t, s.UpdateNetworkSettings(ctx, got))
	ld, lp := t0.Add(time.Minute), t0.Add(2*time.Minute)
	mustNoErr(t, s.UpdateNetworkSchedule(ctx, n.ID, &ld, &lp, &lp))
	got, _ = s.Network(ctx, n.ID)
	if got.Name != "Büro" || got.Enabled || got.DiscoveryInterval != time.Hour || len(got.Deny) != 0 || got.OfflineCriticalAfter != 15*time.Minute ||
		got.LastDiscoveryAt == nil || !got.LastDiscoveryAt.Equal(ld) || !got.LastPortscanAt.Equal(lp) ||
		got.LastServicesAt == nil || !got.LastServicesAt.Equal(lp) || got.ServiceInterval != 24*time.Hour {
		t.Errorf("updated network = %+v", got)
	}
	got.ID = 999
	wantErr(t, s.UpdateNetworkSettings(ctx, got), store.ErrNotFound)
	_, err = s.Network(ctx, 999)
	wantErr(t, err, store.ErrNotFound)

	addNetwork(t, s, "lab-1", "Zweitnetz")
	list, err := s.ListNetworks(ctx)
	mustNoErr(t, err)
	if len(list) != 2 || list[0].ID != n.ID {
		t.Errorf("list = %+v", list)
	}
	other := list[1]
	other.Name = "Büro"
	wantErr(t, s.UpdateNetworkSettings(ctx, other), store.ErrExists)
}

func testNetworkJobs(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	n := addNetwork(t, s, "lab-1", "Heimnetz")
	id, _ := protocol.NewID()
	token, _ := protocol.NewKey()
	j := store.Job{
		ID: id, CrawlerID: "lab-1", NetworkID: &n.ID, Kind: "discovery", Targets: []string{"127.0.0.0/30"},
		Deny: []string{"127.0.0.3"}, ReverseDNS: true, Ports: []int{22}, MaxHosts: 4, TimeoutMs: 500,
		ResultToken: token, Status: store.JobPending, CreatedBy: "scheduler", CreatedAt: t0, ExpiresAt: t0.Add(10 * time.Minute),
	}
	mustNoErr(t, s.CreateJob(ctx, j))
	got, err := s.Job(ctx, id)
	mustNoErr(t, err)
	if got.NetworkID == nil || *got.NetworkID != n.ID || got.Kind != "discovery" || len(got.Deny) != 1 || !got.ReverseDNS {
		t.Errorf("job = %+v", got)
	}
	plain := addJob(t, s, "lab-1", t0, time.Minute)
	if got, _ := s.Job(ctx, plain.ID); got.Kind != "ports" || got.NetworkID != nil {
		t.Errorf("plain job defaults = %+v", got)
	}

	count := func(kind string, now time.Time) int {
		c, err := s.OpenNetworkJobs(ctx, n.ID, kind, now)
		mustNoErr(t, err)
		return c
	}
	if count("discovery", t0) != 1 || count("ports", t0) != 0 || count("discovery", t0.Add(10*time.Minute)) != 0 {
		t.Error("OpenNetworkJobs counts wrong")
	}
	if _, ok, _ := s.NextJob(ctx, "lab-1", t0); !ok {
		t.Fatal("no job delivered")
	}
	if count("discovery", t0) != 1 {
		t.Error("delivered jobs are still open")
	}
}

func testInventory(t *testing.T, s store.Store) {
	ctx := context.Background()
	addCrawler(t, s, "lab-1")
	n := addNetwork(t, s, "lab-1", "Heimnetz")
	m := addNetwork(t, s, "lab-1", "Zweitnetz")
	scanned := t0.Add(time.Minute)

	err := s.UpdateInventory(ctx, n.ID, func(net *store.Network, hosts map[string]*store.Host) ([]string, []store.Event, error) {
		if len(hosts) != 0 || net.Name != "Heimnetz" {
			t.Errorf("initial state: %+v %v", net, hosts)
		}
		hosts["127.0.0.10"] = &store.Host{Hostname: "b", FirstSeen: t0, LastSeen: t0}
		hosts["127.0.0.9"] = &store.Host{Hostname: "a", FirstSeen: t0, LastSeen: t0, PortsScannedAt: &scanned,
			Ports: []store.HostPort{{Port: 443, FirstSeen: t0, LastSeen: t0}, {Port: 22, FirstSeen: t0, LastSeen: t0,
				Service: store.Service{Name: "ssh", Product: "OpenSSH", Version: "9.6p1", Extra: "Ubuntu", Method: "nmap", SeenAt: &scanned}}}}
		hosts["127.0.0.11"] = &store.Host{FirstSeen: t0, LastSeen: t0} // not in changed: not stored
		net.BaselineDone = true
		net.DiscoveryDoneAt = &scanned
		return []string{"127.0.0.9", "127.0.0.10"}, []store.Event{
			{At: t0, IP: "127.0.0.9", Type: "host.new", Severity: store.SeverityInfo, Message: "neu", Baseline: true},
			{At: t0.Add(time.Second), IP: "127.0.0.9", Type: "port.opened", Severity: store.SeverityWarning, Message: "Port 22",
				Details: json.RawMessage(`{"port":22}`), JobID: "job-1"},
		}, nil
	})
	mustNoErr(t, err)

	hosts, err := s.Hosts(ctx, n.ID)
	mustNoErr(t, err)
	if len(hosts) != 2 || hosts[0].IP != "127.0.0.9" || hosts[1].IP != "127.0.0.10" {
		t.Fatalf("hosts (numeric order) = %+v", hosts)
	}
	h := hosts[0]
	if h.NetworkID != n.ID || h.Hostname != "a" || len(h.Ports) != 2 || h.Ports[0].Port != 22 || h.PortsScannedAt == nil {
		t.Errorf("host = %+v", h)
	}
	if sv := h.Ports[0].Service; sv.Label() != "OpenSSH 9.6p1" || sv.Extra != "Ubuntu" || sv.Method != "nmap" ||
		sv.SeenAt == nil || !sv.SeenAt.Equal(scanned) || h.Ports[1].Service.Name != "" {
		t.Errorf("services = %+v", h.Ports)
	}
	got, _ := s.Network(ctx, n.ID)
	if !got.BaselineDone || got.DiscoveryDoneAt == nil || !got.DiscoveryDoneAt.Equal(scanned) {
		t.Errorf("inventory state not saved: %+v", got)
	}

	// Second update sees the stored state and can remove ports.
	err = s.UpdateInventory(ctx, n.ID, func(net *store.Network, hosts map[string]*store.Host) ([]string, []store.Event, error) {
		h := hosts["127.0.0.9"]
		if h == nil || len(h.Ports) != 2 || len(hosts) != 2 {
			t.Fatalf("stored state not loaded: %v", hosts)
		}
		h.Ports = h.Ports[:1]
		h.OfflineLevel = store.SeverityInfo
		return []string{"127.0.0.9"}, nil, nil
	})
	mustNoErr(t, err)
	hosts, _ = s.Hosts(ctx, n.ID)
	if len(hosts[0].Ports) != 1 || hosts[0].OfflineLevel != store.SeverityInfo {
		t.Errorf("after update: %+v", hosts[0])
	}

	// A failing update changes nothing.
	boom := errors.New("boom")
	err = s.UpdateInventory(ctx, n.ID, func(net *store.Network, hosts map[string]*store.Host) ([]string, []store.Event, error) {
		hosts["127.0.0.9"].Hostname = "changed"
		return []string{"127.0.0.9"}, nil, boom
	})
	wantErr(t, err, boom)
	if hosts, _ := s.Hosts(ctx, n.ID); hosts[0].Hostname != "a" {
		t.Error("failed update was stored")
	}
	wantErr(t, s.UpdateInventory(ctx, 999, func(*store.Network, map[string]*store.Host) ([]string, []store.Event, error) {
		return nil, nil, nil
	}), store.ErrNotFound)

	mustNoErr(t, s.SetHostImportant(ctx, n.ID, "127.0.0.10", true))
	wantErr(t, s.SetHostImportant(ctx, n.ID, "127.0.0.99", true), store.ErrNotFound)
	if hosts, _ := s.Hosts(ctx, n.ID); !hosts[1].Important {
		t.Error("important flag not stored")
	}

	// Custom names survive inventory updates of the same host.
	mustNoErr(t, s.SetHostCustomName(ctx, n.ID, "127.0.0.10", "Drucker Büro"))
	wantErr(t, s.SetHostCustomName(ctx, n.ID, "127.0.0.99", "x"), store.ErrNotFound)
	mustNoErr(t, s.UpdateInventory(ctx, n.ID, func(net *store.Network, hosts map[string]*store.Host) ([]string, []store.Event, error) {
		hosts["127.0.0.10"].Hostname = "printer.lan"
		hosts["127.0.0.10"].CustomName = "" // updates must not clear it
		return []string{"127.0.0.10"}, nil, nil
	}))
	if hosts, _ := s.Hosts(ctx, n.ID); hosts[1].CustomName != "Drucker Büro" || hosts[1].Hostname != "printer.lan" {
		t.Errorf("custom name after update = %q / %q", hosts[1].CustomName, hosts[1].Hostname)
	}
	mustNoErr(t, s.SetHostCustomName(ctx, n.ID, "127.0.0.10", ""))
	if hosts, _ := s.Hosts(ctx, n.ID); hosts[1].CustomName != "" {
		t.Error("custom name not removed")
	}

	mustNoErr(t, s.UpdateInventory(ctx, m.ID, func(net *store.Network, hosts map[string]*store.Host) ([]string, []store.Event, error) {
		hosts["127.0.0.1"] = &store.Host{FirstSeen: t0, LastSeen: t0}
		return []string{"127.0.0.1"}, []store.Event{{At: t0.Add(time.Hour), IP: "127.0.0.1", Type: "host.new", Severity: store.SeverityInfo, Message: "neu"}}, nil
	}))
	if all, _ := s.Hosts(ctx, 0); len(all) != 3 || all[0].NetworkID != n.ID || all[2].NetworkID != m.ID {
		t.Errorf("all hosts = %+v", all)
	}

	events, err := s.ListEvents(ctx, store.EventFilter{Limit: 10})
	mustNoErr(t, err)
	if len(events) != 2 || events[0].NetworkID != m.ID || events[1].Type != "port.opened" || events[1].JobID != "job-1" {
		t.Fatalf("events without baseline, newest first = %+v", events)
	}
	var d map[string]int
	if err := json.Unmarshal(events[1].Details, &d); err != nil || d["port"] != 22 {
		t.Errorf("details = %s", events[1].Details)
	}
	if ev, _ := s.ListEvents(ctx, store.EventFilter{IncludeBaseline: true, Limit: 10}); len(ev) != 3 {
		t.Errorf("with baseline: %d events", len(ev))
	}
	if ev, _ := s.ListEvents(ctx, store.EventFilter{NetworkID: n.ID, IncludeBaseline: true}); len(ev) != 2 {
		t.Errorf("network filter: %d events", len(ev))
	}
	if ev, _ := s.ListEvents(ctx, store.EventFilter{IP: "127.0.0.1"}); len(ev) != 1 {
		t.Errorf("ip filter: %d events", len(ev))
	}
	if ev, _ := s.ListEvents(ctx, store.EventFilter{IncludeBaseline: true, Limit: 1}); len(ev) != 1 || ev[0].NetworkID != m.ID {
		t.Errorf("limit: %+v", ev)
	}
}

func testEnrollments(t *testing.T, s store.Store) {
	ctx := context.Background()
	c := addCrawler(t, s, "lab-1")
	hash := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

	wantErr(t, s.CreateEnrollment(ctx, store.Enrollment{TokenHash: hash(9), CrawlerID: "nope", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}), store.ErrNotFound)

	first := store.Enrollment{TokenHash: hash(1), CrawlerID: c.ID, ReverseDNS: true, CreatedAt: t0, ExpiresAt: t0.Add(30 * time.Minute)}
	mustNoErr(t, s.CreateEnrollment(ctx, first))
	e, err := s.Enrollment(ctx, hash(1), t0.Add(time.Minute))
	mustNoErr(t, err)
	if e.CrawlerID != c.ID || !e.ReverseDNS || e.UsedAt != nil {
		t.Fatalf("enrollment = %+v", e)
	}
	_, err = s.Enrollment(ctx, hash(1), t0.Add(30*time.Minute))
	wantErr(t, err, store.ErrNotFound) // expired

	// A new code replaces the unused one.
	mustNoErr(t, s.CreateEnrollment(ctx, store.Enrollment{TokenHash: hash(2), CrawlerID: c.ID, CreatedAt: t0, ExpiresAt: t0.Add(30 * time.Minute)}))
	_, err = s.Enrollment(ctx, hash(1), t0.Add(time.Minute))
	wantErr(t, err, store.ErrNotFound)

	newSecret := bytes.Repeat([]byte{7}, 32)
	_, _, err = s.RedeemEnrollment(ctx, hash(2), newSecret, t0.Add(31*time.Minute))
	wantErr(t, err, store.ErrNotFound) // expired
	got, e2, err := s.RedeemEnrollment(ctx, hash(2), newSecret, t0.Add(time.Minute))
	mustNoErr(t, err)
	if !bytes.Equal(got.Secret, newSecret) || e2.UsedAt == nil || got.ID != c.ID {
		t.Fatalf("redeem = %+v, %+v", got, e2)
	}
	stored, err := s.Crawler(ctx, c.ID)
	mustNoErr(t, err)
	if !bytes.Equal(stored.Secret, newSecret) {
		t.Fatal("secret not rotated")
	}
	_, _, err = s.RedeemEnrollment(ctx, hash(2), hash(8), t0.Add(2*time.Minute))
	wantErr(t, err, store.ErrNotFound) // used once
	_, err = s.Enrollment(ctx, hash(2), t0.Add(2*time.Minute))
	wantErr(t, err, store.ErrNotFound)

	wantErr(t, s.SetCrawlerEnabled(ctx, "nope", false), store.ErrNotFound)
	mustNoErr(t, s.SetCrawlerEnabled(ctx, c.ID, false))
	if got, _ := s.Crawler(ctx, c.ID); got.Enabled {
		t.Fatal("crawler still enabled")
	}
	mustNoErr(t, s.SetCrawlerEnabled(ctx, c.ID, true))

	// Disabled crawlers cannot enroll.
	d := store.Crawler{ID: "off", Secret: hash(3), Allow: []string{"127.0.0.1/32"}, MaxHosts: 1, Enabled: false, CreatedAt: t0}
	mustNoErr(t, s.CreateCrawler(ctx, d))
	mustNoErr(t, s.CreateEnrollment(ctx, store.Enrollment{TokenHash: hash(4), CrawlerID: "off", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}))
	_, _, err = s.RedeemEnrollment(ctx, hash(4), newSecret, t0.Add(time.Minute))
	wantErr(t, err, store.ErrForbidden)
}

func testNotifications(t *testing.T, s store.Store) {
	ctx := context.Background()
	got, err := s.NotificationSettings(ctx)
	mustNoErr(t, err)
	if got.Enabled || got.DiscordURL != "" {
		t.Fatalf("default settings = %+v", got)
	}
	mustNoErr(t, s.RecordNotification(ctx, nil, "ignored without settings"))

	set := store.NotificationSettings{DiscordURL: "https://discord.com/api/webhooks/1/x", MinSeverity: "warning", Enabled: true, Since: t0, UpdatedAt: t0}
	mustNoErr(t, s.SaveNotificationSettings(ctx, set))
	sent := t0.Add(time.Hour)
	mustNoErr(t, s.RecordNotification(ctx, &sent, ""))
	mustNoErr(t, s.RecordNotification(ctx, nil, "429 rate limited"))
	got, err = s.NotificationSettings(ctx)
	mustNoErr(t, err)
	if got.DiscordURL != set.DiscordURL || got.MinSeverity != "warning" || !got.Enabled || !got.Since.Equal(t0) ||
		got.LastSentAt == nil || !got.LastSentAt.Equal(sent) || got.LastError != "429 rate limited" {
		t.Fatalf("settings = %+v", got)
	}
	// Saving keeps the delivery status.
	set.MinSeverity = "critical"
	mustNoErr(t, s.SaveNotificationSettings(ctx, set))
	if got, _ = s.NotificationSettings(ctx); got.LastError != "429 rate limited" || got.MinSeverity != "critical" {
		t.Fatalf("after save = %+v", got)
	}

	addCrawler(t, s, "lab-1")
	n := addNetwork(t, s, "lab-1", "Heimnetz")
	mustNoErr(t, s.UpdateInventory(ctx, n.ID, func(*store.Network, map[string]*store.Host) ([]string, []store.Event, error) {
		return nil, []store.Event{
			{At: t0.Add(-time.Minute), IP: "127.0.0.1", Type: "port.opened", Severity: store.SeverityWarning, Message: "before since"},
			{At: t0, IP: "127.0.0.1", Type: "host.new", Severity: store.SeverityInfo, Message: "baseline", Baseline: true},
			{At: t0.Add(2 * time.Second), IP: "127.0.0.2", Type: "host.offline", Severity: store.SeverityCritical, Message: "c"},
			{At: t0.Add(time.Second), IP: "127.0.0.1", Type: "port.opened", Severity: store.SeverityWarning, Message: "w"},
			{At: t0.Add(3 * time.Second), IP: "127.0.0.3", Type: "host.new", Severity: store.SeverityInfo, Message: "i"},
		}, nil
	}))
	pending, err := s.PendingEvents(ctx, t0, []string{"warning", "critical"}, 10)
	mustNoErr(t, err)
	if len(pending) != 2 || pending[0].Message != "w" || pending[1].Message != "c" || pending[0].NetworkID != n.ID {
		t.Fatalf("pending = %+v", pending)
	}
	if p, _ := s.PendingEvents(ctx, t0, []string{"warning", "critical"}, 1); len(p) != 1 || p[0].Message != "w" {
		t.Fatalf("limit: %+v", p)
	}
	mustNoErr(t, s.MarkEventsNotified(ctx, []int64{pending[0].ID}, t0.Add(time.Hour)))
	pending, err = s.PendingEvents(ctx, t0, []string{"info", "warning", "critical"}, 10)
	mustNoErr(t, err)
	if len(pending) != 2 || pending[0].Message != "c" || pending[1].Message != "i" {
		t.Fatalf("pending after mark = %+v", pending)
	}
}

func testCrawlerRelease(t *testing.T, s store.Store) {
	ctx := context.Background()
	c := addCrawler(t, s, "lab-1")
	open := addJob(t, s, c.ID, t0, 10*time.Minute)
	now := t0.Add(time.Minute)

	wantErr(t, s.UpdateCrawlerRelease(ctx, "nope", []string{"127.0.0.0/29"}, 8, now), store.ErrNotFound)
	mustNoErr(t, s.UpdateCrawlerRelease(ctx, c.ID, []string{"127.0.0.0/29", "10.0.0.0/24"}, 300, now))
	got, err := s.Crawler(ctx, c.ID)
	mustNoErr(t, err)
	if strings.Join(got.Allow, ",") != "127.0.0.0/29,10.0.0.0/24" || got.MaxHosts != 300 || !got.ReinstallRequired {
		t.Fatalf("crawler = %+v", got)
	}
	// Open jobs were planned under the old release: they expire.
	if _, ok, err := s.NextJob(ctx, c.ID, now); err != nil || ok {
		t.Fatalf("open job still deliverable: ok=%v err=%v", ok, err)
	}
	j, _ := s.Job(ctx, open.ID)
	if j.ExpiresAt.After(now) {
		t.Fatalf("job expires %v", j.ExpiresAt)
	}

	// Reinstalling clears the flag.
	mustNoErr(t, s.CreateEnrollment(ctx, store.Enrollment{TokenHash: bytes.Repeat([]byte{5}, 32), CrawlerID: c.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))
	got, _, err = s.RedeemEnrollment(ctx, bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32), now)
	mustNoErr(t, err)
	if got.ReinstallRequired {
		t.Fatal("redeem: flag not cleared in result")
	}
	if got, _ = s.Crawler(ctx, c.ID); got.ReinstallRequired {
		t.Fatal("redeem: flag not cleared")
	}

	// Settings.
	v, err := s.Setting(ctx, "public_url")
	mustNoErr(t, err)
	if v != "" {
		t.Fatalf("unset setting = %q", v)
	}
	mustNoErr(t, s.SetSetting(ctx, "public_url", "https://192.168.1.5:8443", now))
	mustNoErr(t, s.SetSetting(ctx, "public_url", "https://10.0.0.2:8443", now))
	if v, _ = s.Setting(ctx, "public_url"); v != "https://10.0.0.2:8443" {
		t.Fatalf("setting = %q", v)
	}
}

func testExportTokens(t *testing.T, s store.Store) {
	ctx := context.Background()
	id, err := s.CreateExportToken(ctx, store.ExportToken{Name: "KI-Agent", TokenHash: []byte("hash-1"), CreatedBy: "admin", CreatedAt: t0})
	mustNoErr(t, err)
	_, err = s.CreateExportToken(ctx, store.ExportToken{Name: "doppelt", TokenHash: []byte("hash-1"), CreatedBy: "admin", CreatedAt: t0})
	wantErr(t, err, store.ErrExists)

	used, err := s.UseExportToken(ctx, []byte("hash-1"), t0.Add(time.Hour))
	mustNoErr(t, err)
	if used.ID != id || used.Name != "KI-Agent" || used.LastUsedAt == nil || !used.LastUsedAt.Equal(t0.Add(time.Hour)) {
		t.Errorf("used = %+v", used)
	}
	_, err = s.UseExportToken(ctx, []byte("other"), t0)
	wantErr(t, err, store.ErrNotFound)

	list, err := s.ListExportTokens(ctx)
	mustNoErr(t, err)
	if len(list) != 1 || list[0].CreatedBy != "admin" || list[0].LastUsedAt == nil {
		t.Errorf("list = %+v", list)
	}
	mustNoErr(t, s.DeleteExportToken(ctx, id))
	wantErr(t, s.DeleteExportToken(ctx, id), store.ErrNotFound)
	_, err = s.UseExportToken(ctx, []byte("hash-1"), t0)
	wantErr(t, err, store.ErrNotFound)
}

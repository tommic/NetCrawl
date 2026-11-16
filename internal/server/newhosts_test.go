package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"netcrawler/internal/protocol"
	"netcrawler/internal/result"
	"netcrawler/internal/store"
)

func (f *netFixture) portJobs() []store.Job {
	var out []store.Job
	for _, j := range f.jobs() {
		if j.Kind == protocol.JobKindPorts {
			out = append(out, j)
		}
	}
	return out
}

// A host that a discovery finds after the baseline gets its own port scan
// job right away; the baseline itself does not trigger one.
func TestNewHostIsPortScannedRightAway(t *testing.T) {
	f := newNetFixture(t)
	ctx := context.Background()
	c := withCookie(f.login())
	resp := f.do("POST", "/api/v1/admin/networks", "application/json",
		`{"crawler_id":"lan-1","name":"Heimnetz","targets":["10.0.0.0/24"]}`, c)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create network: %d", resp.StatusCode)
	}

	discover := func(hosts map[string]result.Host) {
		t.Helper()
		if err := f.server.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		var disc *store.Job
		for _, j := range f.jobs() {
			if j.Kind == protocol.JobKindDiscovery && j.Status == store.JobPending && f.now.Before(j.ExpiresAt) {
				j := j
				disc = &j
			}
		}
		if disc == nil {
			t.Fatal("no open discovery job")
		}
		// Other open jobs may be handed out first.
		for i := 0; ; i++ {
			if j, _ := f.st.Job(ctx, disc.ID); j.DeliveredAt != nil {
				break
			}
			if i == 5 {
				t.Fatal("discovery job never delivered")
			}
			if resp := f.signedPollFor("lan-1"); resp.StatusCode != http.StatusOK {
				t.Fatalf("poll: %d", resp.StatusCode)
			}
		}
		f.submit(*disc, hosts)
	}

	// Baseline: no immediate port scan (the regular one follows).
	discover(map[string]result.Host{"10.0.0.5": {Hostname: "nas"}})
	if jobs := f.portJobs(); len(jobs) != 0 {
		t.Fatalf("baseline created port scan jobs: %+v", jobs)
	}

	// Regular port scan for the known host, delivered and answered.
	f.now = f.now.Add(30 * time.Minute)
	_ = f.server.Tick(ctx)
	if jobs := f.portJobs(); len(jobs) != 1 {
		t.Fatalf("regular port scan jobs = %d", len(jobs))
	}
	lastScan := func() *time.Time {
		n, _ := f.st.Network(ctx, 1)
		return n.LastPortscanAt
	}
	before := lastScan()

	// Next discovery finds a new host: immediate port scan for it only.
	f.now = f.now.Add(30 * time.Minute)
	discover(map[string]result.Host{"10.0.0.5": {Hostname: "nas"}, "10.0.0.30": {Hostname: "printer"}})
	jobs := f.portJobs()
	if len(jobs) != 2 {
		t.Fatalf("port scan jobs = %d, want 2", len(jobs))
	}
	var found bool
	for _, j := range jobs {
		if strings.Join(j.Targets, ",") == "10.0.0.30/32" {
			found = true
			if len(j.Ports) != 100 || j.CreatedBy != scheduledActor {
				t.Errorf("new host job = %+v", j)
			}
		}
	}
	if !found {
		t.Fatalf("no port scan job for the new host: %+v", jobs)
	}
	if after := lastScan(); (before == nil) != (after == nil) || (before != nil && !before.Equal(*after)) {
		t.Errorf("regular port scan schedule moved: %v → %v", before, after)
	}

	// A discovery without new hosts creates no extra job.
	f.now = f.now.Add(30 * time.Minute)
	discover(map[string]result.Host{"10.0.0.5": {Hostname: "nas"}, "10.0.0.30": {Hostname: "printer"}})
	if n := len(f.portJobs()); n != 2 {
		t.Errorf("port scan jobs = %d, want still 2", n)
	}
}

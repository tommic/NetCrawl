package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"netcrawler/internal/protocol"
	"netcrawler/internal/result"
)

// Port scan intervals in minutes (min. 15), the legacy hours field, the
// detected scan preset, and RequestFromNetwork as a base for edits.
func TestNetworkEditIntervals(t *testing.T) {
	f := newNetFixture(t)
	ctx := context.Background()
	c := withCookie(f.login())
	resp := f.do("POST", "/api/v1/admin/networks", "application/json",
		`{"crawler_id":"lan-1","name":"Heimnetz","targets":["10.0.0.0/28"],"deny":["10.0.0.1"],"scan_preset":"web","offline_info_hours":12}`, c)
	n := decode[NetworkView](t, resp)
	if resp.StatusCode != http.StatusCreated || n.PortscanIntervalMinutes != 24*60 || n.PortscanIntervalHours != 24 || n.ScanPreset != "web" {
		t.Fatalf("create: %d %+v", resp.StatusCode, n)
	}

	put := func(body string) (*http.Response, NetworkView) {
		t.Helper()
		resp := f.do("PUT", "/api/v1/admin/networks/1", "application/json", body, c)
		if resp.StatusCode != http.StatusOK {
			return resp, NetworkView{}
		}
		return resp, decode[NetworkView](t, resp)
	}
	if resp, n := put(`{"name":"Heimnetz","targets":["10.0.0.0/28"],"portscan_interval_minutes":30,"scan_ports":[22,8080]}`); resp.StatusCode != 200 ||
		n.PortscanIntervalMinutes != 30 || n.PortscanIntervalHours != 0 || n.ScanPreset != "custom" {
		t.Fatalf("30 minutes: %d %+v", resp.StatusCode, n)
	}
	if resp, _ := put(`{"name":"Heimnetz","targets":["10.0.0.0/28"],"portscan_interval_minutes":10}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("10 minutes: %d, want 400", resp.StatusCode)
	}
	// Minutes win over hours; hours alone still work.
	if _, n := put(`{"name":"Heimnetz","targets":["10.0.0.0/28"],"portscan_interval_minutes":45,"portscan_interval_hours":5}`); n.PortscanIntervalMinutes != 45 {
		t.Errorf("minutes over hours: %+v", n)
	}
	if _, n := put(`{"name":"Heimnetz","targets":["10.0.0.0/28"],"portscan_interval_hours":2}`); n.PortscanIntervalMinutes != 120 || n.ScanPreset != "top100" {
		t.Errorf("hours: %+v", n)
	}

	// A request built from the stored network changes nothing.
	cur, _ := f.st.Network(ctx, 1)
	req := RequestFromNetwork(cur)
	req.PortscanIntervalMinutes = 30
	got, err := UpdateNetwork(ctx, f.st, "test", 1, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.PortscanInterval != 30*time.Minute || got.Name != cur.Name || len(got.Deny) != len(cur.Deny) ||
		len(got.ScanPorts) != len(cur.ScanPorts) || got.OfflineInfoAfter != cur.OfflineInfoAfter || got.ReverseDNS != cur.ReverseDNS {
		t.Errorf("round trip changed settings: %+v → %+v", cur, got)
	}

	// The scheduler uses the new interval: a port scan 30 minutes after
	// the last one.
	_ = f.server.Tick(ctx) // discovery job
	for _, j := range f.jobs() {
		if j.Kind == protocol.JobKindDiscovery {
			f.signedPollFor("lan-1")
			f.submit(j, map[string]result.Host{"10.0.0.5": {Ports: []int{}}})
		}
	}
	_ = f.server.Tick(ctx)
	count := func() int {
		n := 0
		for _, j := range f.jobs() {
			if j.Kind == protocol.JobKindPorts {
				n++
			}
		}
		return n
	}
	first := count()
	f.now = f.now.Add(61 * time.Minute) // past the 60 min TTL of the open job
	_ = f.server.Tick(ctx)
	if count() != first+1 {
		t.Errorf("port scan jobs %d → %d after 61 min with a 30 min interval", first, count())
	}
}

// The UI lists the built-in presets with their ports.
func TestPortPresets(t *testing.T) {
	f := newNetFixture(t)
	c := withCookie(f.login())
	resp := f.do("GET", "/api/v1/admin/port-presets", "", "", c)
	got := map[string][]int{}
	for _, p := range decode[[]PortPreset](t, resp) {
		got[p.Name] = p.Ports
	}
	if resp.StatusCode != http.StatusOK || len(got["top100"]) != 100 || len(got["tiny"]) != 3 || len(got["discovery"]) == 0 {
		t.Fatalf("presets: %d %v", resp.StatusCode, got)
	}
	if _, ok := got["all"]; ok {
		t.Error("preset all must not be offered")
	}
	if resp := f.do("GET", "/api/v1/admin/port-presets", "", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("without login: %d", resp.StatusCode)
	}
}

// Important hosts: own threshold in minutes, default 60, at least 5.
func TestNetworkCriticalThreshold(t *testing.T) {
	f := newNetFixture(t)
	c := withCookie(f.login())
	resp := f.do("POST", "/api/v1/admin/networks", "application/json",
		`{"crawler_id":"lan-1","name":"Heimnetz","targets":["10.0.0.0/28"]}`, c)
	if n := decode[NetworkView](t, resp); resp.StatusCode != http.StatusCreated || n.OfflineCriticalMinutes != 60 {
		t.Fatalf("default: %d %+v", resp.StatusCode, n)
	}
	resp = f.do("PUT", "/api/v1/admin/networks/1", "application/json",
		`{"name":"Heimnetz","targets":["10.0.0.0/28"],"offline_critical_minutes":15}`, c)
	if n := decode[NetworkView](t, resp); resp.StatusCode != http.StatusOK || n.OfflineCriticalMinutes != 15 {
		t.Fatalf("15 minutes: %d %+v", resp.StatusCode, n)
	}
	if cur, _ := f.st.Network(context.Background(), 1); RequestFromNetwork(cur).OfflineCriticalMinutes != 15 {
		t.Errorf("RequestFromNetwork lost the threshold")
	}
	resp = f.do("PUT", "/api/v1/admin/networks/1", "application/json",
		`{"name":"Heimnetz","targets":["10.0.0.0/28"],"offline_critical_minutes":2}`, c)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("2 minutes: %d, want 400", resp.StatusCode)
	}
}

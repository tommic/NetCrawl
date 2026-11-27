package inventory

import (
	"context"
	"strings"
	"testing"
	"time"

	"netcrawler/internal/protocol"
	"netcrawler/internal/result"
	"netcrawler/internal/store"
	"netcrawler/internal/store/memstore"
)

var t0 = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

type fixture struct {
	t  *testing.T
	st *memstore.Store
	id int64
}

func newFixture(t *testing.T) *fixture {
	st := memstore.New()
	ctx := context.Background()
	if err := st.CreateCrawler(ctx, store.Crawler{ID: "c1", Secret: make([]byte, 32), Allow: []string{"10.0.0.0/24"}, MaxHosts: 256, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateNetwork(ctx, store.Network{
		CrawlerID: "c1", Name: "Heimnetz", Targets: []string{"10.0.0.0/24"},
		DiscoveryPorts: []int{22}, ScanPorts: []int{22, 80},
		DiscoveryInterval: 30 * time.Minute, PortscanInterval: 24 * time.Hour,
		OfflineInfoAfter: 24 * time.Hour, OfflineWarnAfter: 7 * 24 * time.Hour, OfflineCriticalAfter: time.Hour, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, st: st, id: id}
}

// hostSpec: ip -> "hostname:port,port"
func resultOf(hosts map[string]string) protocol.Result {
	nr := result.NetworkResult{Network: "10.0.0.0/24", Hosts: map[string]result.Host{}}
	for ip, spec := range hosts {
		name, portList, _ := strings.Cut(spec, ":")
		h := result.Host{Hostname: name, Ports: []int{}}
		for _, p := range strings.Split(portList, ",") {
			if p == "" {
				continue
			}
			var n int
			for _, c := range p {
				n = n*10 + int(c-'0')
			}
			h.Ports = append(h.Ports, n)
		}
		nr.Hosts[ip] = h
	}
	return protocol.Result{Networks: []result.NetworkResult{nr}}
}

func (f *fixture) apply(kind string, at time.Time, hosts map[string]string) []store.Event {
	f.t.Helper()
	return f.applyResult(kind, at, resultOf(hosts))
}

func (f *fixture) applyResult(kind string, at time.Time, res protocol.Result) []store.Event {
	f.t.Helper()
	before, _ := f.st.ListEvents(context.Background(), store.EventFilter{IncludeBaseline: true})
	if err := f.st.UpdateInventory(context.Background(), f.id, ApplyResult(kind, "job", res, at)); err != nil {
		f.t.Fatal(err)
	}
	after, _ := f.st.ListEvents(context.Background(), store.EventFilter{IncludeBaseline: true})
	// newest first; return the new ones oldest first
	var out []store.Event
	for i := len(after) - len(before) - 1; i >= 0; i-- {
		out = append(out, after[i])
	}
	return out
}

func types(events []store.Event) string {
	var s []string
	for _, e := range events {
		t := e.Type + "/" + e.Severity
		if e.IP != "" {
			t += "@" + e.IP
		}
		if e.Baseline {
			t += "(baseline)"
		}
		s = append(s, t)
	}
	return strings.Join(s, " ")
}

func (f *fixture) host(ip string) store.Host {
	f.t.Helper()
	hosts, _ := f.st.Hosts(context.Background(), f.id)
	for _, h := range hosts {
		if h.IP == ip {
			return h
		}
	}
	f.t.Fatalf("host %s not in inventory", ip)
	return store.Host{}
}

func expect(t *testing.T, got []store.Event, want string) {
	t.Helper()
	if g := types(got); g != want {
		t.Errorf("events:\n got %s\nwant %s", g, want)
	}
}

func TestDiscoveryBaselineAndChanges(t *testing.T) {
	f := newFixture(t)
	disc := protocol.JobKindDiscovery

	ev := f.apply(disc, t0, map[string]string{"10.0.0.1": "router:", "10.0.0.20": ":"})
	expect(t, ev, "host.new/info@10.0.0.1(baseline) host.new/info@10.0.0.20(baseline) inventory.baseline/info(baseline)")
	if n, _ := f.st.Network(context.Background(), f.id); !n.BaselineDone || !n.DiscoveryDoneAt.Equal(t0) {
		t.Errorf("network state %+v", n)
	}
	if h := f.host("10.0.0.1"); h.Hostname != "router" || !h.FirstSeen.Equal(t0) {
		t.Errorf("host = %+v", h)
	}
	// Only non-baseline events are shown by default.
	if ev, _ := f.st.ListEvents(context.Background(), store.EventFilter{}); len(ev) != 0 {
		t.Errorf("baseline events must be hidden by default: %v", types(ev))
	}

	t1 := t0.Add(30 * time.Minute)
	ev = f.apply(disc, t1, map[string]string{"10.0.0.1": "gateway:", "10.0.0.20": ":", "10.0.0.30": "nas:"})
	expect(t, ev, "host.hostname_changed/info@10.0.0.1 host.new/info@10.0.0.30")
	if h := f.host("10.0.0.20"); !h.LastSeen.Equal(t1) || !h.FirstSeen.Equal(t0) {
		t.Errorf("last/first seen not updated: %+v", h)
	}

	// An empty hostname (PTR missing this time) doesn't count as a change.
	ev = f.apply(disc, t1.Add(30*time.Minute), map[string]string{"10.0.0.1": ":", "10.0.0.20": ":", "10.0.0.30": "nas:"})
	expect(t, ev, "")
	if h := f.host("10.0.0.1"); h.Hostname != "gateway" {
		t.Errorf("hostname lost: %q", h.Hostname)
	}
}

func TestPortBaselineAndChanges(t *testing.T) {
	f := newFixture(t)
	f.apply(protocol.JobKindDiscovery, t0, map[string]string{"10.0.0.5": "srv:"})

	ev := f.apply(protocol.JobKindPorts, t0.Add(time.Hour), map[string]string{"10.0.0.5": "srv:22,80"})
	expect(t, ev, "ports.baseline/info@10.0.0.5(baseline)")
	if !strings.Contains(ev[0].Message, "22, 80") {
		t.Errorf("baseline message %q", ev[0].Message)
	}
	h := f.host("10.0.0.5")
	if len(h.Ports) != 2 || h.Ports[0].Port != 22 || h.PortsScannedAt == nil {
		t.Errorf("ports = %+v", h.Ports)
	}

	t2 := t0.Add(25 * time.Hour)
	ev = f.apply(protocol.JobKindPorts, t2, map[string]string{"10.0.0.5": "srv:22,443,8080"})
	expect(t, ev, "port.opened/warning@10.0.0.5 port.opened/warning@10.0.0.5 port.closed/info@10.0.0.5")
	h = f.host("10.0.0.5")
	if len(h.Ports) != 3 || h.Ports[0].Port != 22 || !h.Ports[0].FirstSeen.Equal(t0.Add(time.Hour)) || !h.Ports[0].LastSeen.Equal(t2) ||
		h.Ports[1].Port != 443 || !h.Ports[1].FirstSeen.Equal(t2) {
		t.Errorf("ports after change = %+v", h.Ports)
	}

	// A host seen first by a port scan is new, and its first scan is its
	// baseline.
	ev = f.apply(protocol.JobKindPorts, t2.Add(time.Hour), map[string]string{"10.0.0.5": "srv:22,443,8080", "10.0.0.6": ":3389"})
	expect(t, ev, "host.new/info@10.0.0.6 ports.baseline/info@10.0.0.6(baseline)")

	// A host that didn't answer the port scan keeps its baseline.
	ev = f.apply(protocol.JobKindPorts, t2.Add(2*time.Hour), map[string]string{"10.0.0.6": ":3389"})
	expect(t, ev, "")
	if h := f.host("10.0.0.5"); len(h.Ports) != 3 {
		t.Errorf("offline host lost its ports: %+v", h.Ports)
	}
}

func TestOfflineAndBack(t *testing.T) {
	f := newFixture(t)
	disc := protocol.JobKindDiscovery
	f.apply(disc, t0, map[string]string{"10.0.0.1": ":", "10.0.0.2": "tv:", "10.0.0.3": "nas:"})
	if err := f.st.SetHostImportant(context.Background(), f.id, "10.0.0.3", true); err != nil {
		t.Fatal(err)
	}
	present := map[string]string{"10.0.0.1": ":"}

	// Important hosts have their own short threshold (here 1 h).
	expect(t, f.apply(disc, t0.Add(30*time.Minute), present), "")
	expect(t, f.apply(disc, t0.Add(time.Hour), present), "host.offline/critical@10.0.0.3")
	expect(t, f.apply(disc, t0.Add(23*time.Hour), present), "")
	expect(t, f.apply(disc, t0.Add(24*time.Hour), present), "host.offline/info@10.0.0.2")
	// No repeated events at the same level.
	expect(t, f.apply(disc, t0.Add(48*time.Hour), present), "")
	// After 7 days: warning for normal hosts; important ones are critical already.
	ev := f.apply(disc, t0.Add(7*24*time.Hour), present)
	expect(t, ev, "host.offline/warning@10.0.0.2")
	if !strings.Contains(ev[0].Message, "7 Tagen") {
		t.Errorf("message %q", ev[0].Message)
	}
	expect(t, f.apply(disc, t0.Add(8*24*time.Hour), present), "")
	if h := f.host("10.0.0.3"); h.OfflineLevel != store.SeverityCritical {
		t.Errorf("offline level = %q", h.OfflineLevel)
	}

	ev = f.apply(disc, t0.Add(8*24*time.Hour+time.Hour), map[string]string{"10.0.0.1": ":", "10.0.0.2": "tv:"})
	expect(t, ev, "host.back/info@10.0.0.2")
	if h := f.host("10.0.0.2"); h.OfflineLevel != "" {
		t.Errorf("offline level not reset: %q", h.OfflineLevel)
	}
}

func TestOfflineMeasuredAgainstDiscoveryRuns(t *testing.T) {
	f := newFixture(t)
	f.apply(protocol.JobKindDiscovery, t0, map[string]string{"10.0.0.1": ":"})
	// No discovery ran for 10 days (crawler down): a sweep at "now" must
	// not mark hosts offline.
	if err := f.st.UpdateInventory(context.Background(), f.id, Sweep(t0.Add(10*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if ev, _ := f.st.ListEvents(context.Background(), store.EventFilter{}); len(ev) != 0 {
		t.Errorf("crawler outage must not raise offline events: %s", types(ev))
	}
	// Port scans don't move the reference point either.
	f.apply(protocol.JobKindPorts, t0.Add(10*24*time.Hour), map[string]string{})
	if ev, _ := f.st.ListEvents(context.Background(), store.EventFilter{}); len(ev) != 0 {
		t.Errorf("port scan raised offline events: %s", types(ev))
	}
}

// withService adds a detected service to a port of a result.
func withService(res protocol.Result, ip string, port int, name, product, version, method string) protocol.Result {
	h := res.Networks[0].Hosts[ip]
	if h.Details == nil {
		h.Details = map[int]result.PortInfo{}
	}
	h.Details[port] = result.PortInfo{Service: name, Product: product, ServiceVersion: version, ServiceMethod: method}
	res.Networks[0].Hosts[ip] = h
	return res
}

func TestServices(t *testing.T) {
	f := newFixture(t)
	ports := protocol.JobKindPorts
	f.apply(protocol.JobKindDiscovery, t0, map[string]string{"10.0.0.5": ":"})

	// First port scan: services are stored, no events beyond the baseline.
	res := withService(resultOf(map[string]string{"10.0.0.5": ":22,80"}), "10.0.0.5", 22, "ssh", "OpenSSH", "9.6p1", "nmap")
	res = withService(res, "10.0.0.5", 80, "http", "nginx", "1.24.0", "nmap")
	expect(t, f.applyResult(ports, t0.Add(time.Hour), res), "ports.baseline/info@10.0.0.5(baseline)")
	if s := f.host("10.0.0.5").Ports[0].Service; s.Label() != "OpenSSH 9.6p1" || s.SeenAt == nil || s.Method != "nmap" {
		t.Fatalf("service = %+v", s)
	}

	// Version update: info. Other product: warning. No result: kept.
	res = withService(resultOf(map[string]string{"10.0.0.5": ":22,80"}), "10.0.0.5", 22, "ssh", "OpenSSH", "9.7p1", "nmap")
	res = withService(res, "10.0.0.5", 80, "http", "Apache httpd", "2.4.58", "nmap")
	ev := f.applyResult(ports, t0.Add(2*time.Hour), res)
	expect(t, ev, "service.changed/info@10.0.0.5 service.changed/warning@10.0.0.5")
	if !strings.Contains(ev[0].Message, "OpenSSH 9.6p1 → OpenSSH 9.7p1") {
		t.Errorf("message %q", ev[0].Message)
	}
	expect(t, f.apply(ports, t0.Add(3*time.Hour), map[string]string{"10.0.0.5": ":22,80"}), "")
	if s := f.host("10.0.0.5").Ports[0].Service; s.Version != "9.7p1" {
		t.Errorf("service without new result = %+v", s)
	}

	// Found another way (built-in check, other wording): stored, no event.
	res = withService(resultOf(map[string]string{"10.0.0.5": ":22,80"}), "10.0.0.5", 22, "ssh", "OpenSSH", "9.7p1 Debian", "banner")
	expect(t, f.applyResult(ports, t0.Add(4*time.Hour), res), "")

	// A new port names its service in the port.opened event.
	res = withService(resultOf(map[string]string{"10.0.0.5": ":22,80,3306"}), "10.0.0.5", 3306, "mysql", "MySQL", "8.0.36", "banner")
	ev = f.applyResult(ports, t0.Add(5*time.Hour), res)
	expect(t, ev, "port.opened/warning@10.0.0.5")
	if !strings.HasSuffix(ev[0].Message, "(MySQL 8.0.36)") {
		t.Errorf("message %q", ev[0].Message)
	}
}

package e2e

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"netcrawler/internal/inventory"
	"netcrawler/internal/ports"
	"netcrawler/internal/server"
	"netcrawler/internal/store"
)

// listener is a loopback TCP listener that can be closed mid-test.
func listener(t *testing.T) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
}

// TestInventoryFlow runs the M2 cycle with the real agent: network with
// deny list, host discovery, port baseline, a newly opened and a closed
// port. Targets are loopback addresses only (127.0.0.1-127.0.0.3; every
// 127.x address answers locally, which makes them usable as "hosts").
func TestInventoryFlow(t *testing.T) {
	e := setupCrawler(t, "M2-01", "Inventar: Erkennung, Deny-Liste, Port-Baseline, Änderungen", []string{"127.0.0.0/29"}, 8)
	a := e.startAgent()
	ctx := context.Background()

	portA, stopA := listener(t)
	portB := closedPort(t)

	n, err := server.CreateNetwork(ctx, e.st, "e2e", server.NetworkRequest{
		CrawlerID: crawlerID, Name: "Loopback", Targets: []string{"127.0.0.1-127.0.0.3"}, Deny: []string{"127.0.0.3"},
		DiscoveryPorts: []int{portA, portB}, ScanPorts: ports.Specs([]int{portA, portB}),
	}, e.srvClock.Now())
	if err != nil {
		t.Fatal(err)
	}

	// cycle: scheduler tick, then the agent processes every open job.
	cycle := func(advance time.Duration) {
		t.Helper()
		e.srvClock.Add(advance)
		e.agClock.Add(advance)
		if err := e.server.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			out, err := a.RunOnce(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if out.Rejected != "" {
				t.Fatalf("job rejected: %s", out.Rejected)
			}
			if out.JobID == "" {
				return
			}
		}
	}
	events := func() string {
		ev, _ := e.st.ListEvents(ctx, store.EventFilter{NetworkID: n.ID, IncludeBaseline: true})
		var s []string
		for i := len(ev) - 1; i >= 0; i-- {
			s = append(s, ev[i].Type+"/"+ev[i].Severity+"@"+ev[i].IP)
		}
		return strings.Join(s, " ")
	}

	cycle(0) // discovery
	cycle(time.Minute)
	hosts, _ := e.st.Hosts(ctx, n.ID)
	if len(hosts) != 2 || hosts[0].IP != "127.0.0.1" || hosts[1].IP != "127.0.0.2" {
		t.Fatalf("hosts = %+v", hosts)
	}
	if len(hosts[0].Ports) != 1 || hosts[0].Ports[0].Port != portA || hosts[0].PortsScannedAt == nil || len(hosts[1].Ports) != 0 {
		t.Fatalf("port baseline = %+v / %+v", hosts[0], hosts[1])
	}
	want := "host.new/info@127.0.0.1 host.new/info@127.0.0.2 inventory.baseline/info@ ports.baseline/info@127.0.0.1 ports.baseline/info@127.0.0.2"
	if got := events(); got != want {
		t.Fatalf("baseline events:\n got %s\nwant %s", got, want)
	}
	e.proof("Initialbestand: 127.0.0.1 und 127.0.0.2 erkannt, 127.0.0.3 (Deny-Liste) nie kontaktiert; Port-Baseline 127.0.0.1 = Test-Port A.")

	// A service starts on port B: the next daily port scan warns.
	lnB, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(portB)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lnB.Close() })
	go func() {
		for {
			c, err := lnB.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	cycle(24*time.Hour + time.Minute)
	ev, _ := e.st.ListEvents(ctx, store.EventFilter{NetworkID: n.ID})
	if len(ev) != 1 || ev[0].Type != inventory.TypePortOpened || ev[0].Severity != store.SeverityWarning || ev[0].IP != "127.0.0.1" {
		t.Fatalf("after opening port B: %+v", ev)
	}
	e.proof("Neu geöffneter Port → Ereignis „%s“ (Warnung).", ev[0].Message)

	// Port A stops: closed port is reported as info.
	stopA()
	cycle(24*time.Hour + time.Minute)
	ev, _ = e.st.ListEvents(ctx, store.EventFilter{NetworkID: n.ID})
	if len(ev) != 2 || ev[0].Type != inventory.TypePortClosed || ev[0].Severity != store.SeverityInfo {
		t.Fatalf("after closing port A: %+v", ev)
	}
	e.proof("Geschlossener Port → Ereignis „%s“ (Info).", ev[0].Message)

	for _, d := range e.dials.all() {
		if strings.HasPrefix(d, "127.0.0.3:") {
			t.Errorf("denied address contacted: %s", d)
		}
		if !strings.HasPrefix(d, "127.0.0.1:") && !strings.HasPrefix(d, "127.0.0.2:") {
			t.Errorf("unexpected target %s", d)
		}
	}
	e.ev.Result = "Inventar, Deny-Liste und Änderungsmeldungen funktionieren mit echtem Crawler."
}

func itoa(n int) string { return strconv.Itoa(n) }

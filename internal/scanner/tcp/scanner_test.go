package tcp

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestScanLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	open, _ := strconv.Atoi(ps)

	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	_, cs, _ := net.SplitHostPort(tmp.Addr().String())
	tmp.Close()
	closed, _ := strconv.Atoi(cs)

	addrs := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	// concurrency 0 must not deadlock.
	for _, concurrency := range []int{0, 1, 8} {
		got := Scan(context.Background(), addrs, []int{closed, open}, time.Second, concurrency)
		if len(got) != 1 || len(got["127.0.0.1"]) != 1 || got["127.0.0.1"][0] != open {
			t.Errorf("concurrency %d: got %v, want only port %d open", concurrency, got, open)
		}
	}
}

func TestScanCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := Scan(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, []int{1, 2, 3}, time.Second, 2)
	if len(got) != 0 {
		t.Errorf("cancelled scan found %v", got)
	}
}

func TestProbeAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	open := ln.Addr().(*net.TCPAddr).Port
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	addrs := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}
	res := Probe(context.Background(), nil, addrs, []int{open, closed}, time.Second, 4)
	// 127.0.0.1 has an open port; 127.0.0.2 only refuses (the listener is
	// bound to 127.0.0.1), but that still proves it is alive.
	if len(res.Open["127.0.0.1"]) != 1 || !res.Alive["127.0.0.1"] {
		t.Errorf("127.0.0.1: open %v alive %v", res.Open["127.0.0.1"], res.Alive["127.0.0.1"])
	}
	if len(res.Open["127.0.0.2"]) != 0 || !res.Alive["127.0.0.2"] {
		t.Errorf("127.0.0.2: open %v alive %v, want refused-but-alive", res.Open["127.0.0.2"], res.Alive["127.0.0.2"])
	}

	// A host that doesn't answer at all (dial error other than refused)
	// is not alive.
	dead := func(context.Context, string, string) (net.Conn, error) { return nil, context.DeadlineExceeded }
	if res := Probe(context.Background(), dead, addrs[:1], []int{open}, time.Second, 1); len(res.Alive) != 0 {
		t.Errorf("timeouts must not count as alive: %v", res.Alive)
	}
}

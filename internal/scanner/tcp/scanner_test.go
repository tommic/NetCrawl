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

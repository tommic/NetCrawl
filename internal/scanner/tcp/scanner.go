// Package tcp implements a parallel TCP connect scan. It needs no raw
// sockets and normally no root privileges.
package tcp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// DialFunc opens a connection, like net.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Result of a probe run.
type Result struct {
	// Open lists the open ports per address, sorted.
	Open map[string][]int
	// Alive holds every address that answered on at least one port,
	// either by accepting the connection or by actively refusing it
	// (TCP RST). A refusal proves the host is up even if every probed
	// port is closed.
	Alive map[string]bool
}

// Scan tries every (address, port) pair with at most concurrency parallel
// connection attempts and returns the open ports per address. If ctx is
// cancelled, Scan stops early and returns what it found so far; callers
// should check ctx.Err() to tell a partial result from a complete one.
func Scan(ctx context.Context, addresses []netip.Addr, ports []int, timeout time.Duration, concurrency int) map[string][]int {
	return Probe(ctx, nil, addresses, ports, timeout, concurrency).Open
}

// ScanWithDialer is Scan with a custom dial function (nil uses
// net.Dialer). Each attempt is bounded by timeout via its context.
func ScanWithDialer(ctx context.Context, dial DialFunc, addresses []netip.Addr, ports []int, timeout time.Duration, concurrency int) map[string][]int {
	return Probe(ctx, dial, addresses, ports, timeout, concurrency).Open
}

// Probe is ScanWithDialer that also reports which hosts are alive.
func Probe(ctx context.Context, dial DialFunc, addresses []netip.Addr, ports []int, timeout time.Duration, concurrency int) Result {
	type job struct {
		addr netip.Addr
		port int
	}
	if concurrency < 1 {
		concurrency = 1
	}
	jobs := make(chan job)
	res := Result{Open: map[string][]int{}, Alive: map[string]bool{}}
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			dialFn := dial
			if dialFn == nil {
				dialFn = d.DialContext
			}
			for j := range jobs {
				dctx, cancel := context.WithTimeout(ctx, timeout)
				c, err := dialFn(dctx, "tcp", net.JoinHostPort(j.addr.String(), strconv.Itoa(j.port)))
				cancel()
				key := j.addr.String()
				switch {
				case err == nil:
					c.Close()
					mu.Lock()
					res.Open[key] = append(res.Open[key], j.port)
					res.Alive[key] = true
					mu.Unlock()
				case errors.Is(err, syscall.ECONNREFUSED):
					mu.Lock()
					res.Alive[key] = true
					mu.Unlock()
				}
			}
		}()
	}
send:
	for _, a := range addresses {
		for _, p := range ports {
			select {
			case jobs <- job{a, p}:
			case <-ctx.Done():
				break send
			}
		}
	}
	close(jobs)
	wg.Wait()
	for k := range res.Open {
		sort.Ints(res.Open[k])
	}
	return res
}

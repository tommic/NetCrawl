// Package tcp implements a parallel TCP connect scan. It needs no raw
// sockets and normally no root privileges.
package tcp

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Scan tries every (address, port) pair with at most concurrency parallel
// connection attempts and returns the open ports per address. If ctx is
// cancelled, Scan stops early and returns what it found so far; callers
// should check ctx.Err() to tell a partial result from a complete one.
func Scan(ctx context.Context, addresses []netip.Addr, ports []int, timeout time.Duration, concurrency int) map[string][]int {
	type job struct {
		addr netip.Addr
		port int
	}
	if concurrency < 1 {
		concurrency = 1
	}
	jobs := make(chan job)
	result := make(map[string][]int)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			for j := range jobs {
				c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(j.addr.String(), strconv.Itoa(j.port)))
				if err == nil {
					c.Close()
					mu.Lock()
					result[j.addr.String()] = append(result[j.addr.String()], j.port)
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
	for k := range result {
		sort.Ints(result[k])
	}
	return result
}

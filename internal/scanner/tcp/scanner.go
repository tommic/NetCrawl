package tcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

var presets = map[string][]int{
	"tiny":     {22, 80, 443},
	"common":   {21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443},
	"web":      {80, 443, 8000, 8080, 8081, 8443, 8888},
	"database": {1433, 1521, 3306, 5432, 6379, 27017},
}

func Ports(preset string, custom []int) []int {
	m := map[int]bool{}
	for _, p := range presets[preset] {
		m[p] = true
	}
	for _, p := range custom {
		if p > 0 && p <= 65535 {
			m[p] = true
		}
	}
	out := make([]int, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func Scan(ctx context.Context, addresses []netip.Addr, ports []int, timeout time.Duration, concurrency int) map[string][]int {
	type job struct {
		addr netip.Addr
		port int
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
				c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(j.addr.String(), fmt.Sprint(j.port)))
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

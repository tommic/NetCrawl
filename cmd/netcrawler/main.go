package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"netcrawler/internal/config"
	"netcrawler/internal/denylist"
	"netcrawler/internal/iprange"
	"netcrawler/internal/result"
	"netcrawler/internal/scanner/tcp"
)

func main() {
	configFile := flag.String("config", "config.json", "Path to crawler configuration")
	flag.Parse()

	fmt.Printf("[INFO] Loading config: %s\n", *configFile)
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	deny, err := denylist.New(cfg.Targets.Deny)
	if err != nil {
		log.Fatalf("denylist: %v", err)
	}

	jobs := map[string][]netip.Addr{}
	seen := map[string]bool{}
	denied := map[string]int{}

	for _, target := range cfg.Targets.Include {
		r, err := iprange.Parse(target)
		if err != nil {
			log.Fatalf("target %q: %v", target, err)
		}
		for _, a := range iprange.Addresses(r) {
			p := netip.PrefixFrom(a, 24).Masked().String()
			if deny.Contains(a) {
				denied[p]++
				continue
			}
			key := a.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			jobs[p] = append(jobs[p], a)
		}
	}

	networks := make([]string, 0, len(jobs))
	for n := range jobs {
		networks = append(networks, n)
	}
	sort.Strings(networks)
	ports := tcp.Ports(cfg.Ports.Preset, cfg.Ports.Custom)
	fmt.Printf("[INFO] Generated %d network job(s), %d port(s)\n", len(networks), len(ports))

	for _, network := range networks {
		addresses := jobs[network]
		fmt.Printf("[INFO] Scanning %s (%d target(s))\n", network, len(addresses))
		start := time.Now()
		found := tcp.Scan(context.Background(), addresses, ports, time.Duration(cfg.Ports.TimeoutMs)*time.Millisecond, cfg.Performance.MaxConcurrentConnections)

		hosts := map[string]result.Host{}
		openCount := 0
		for ip, ps := range found {
			h := result.Host{Ports: ps}
			if cfg.Hostname.Enabled && cfg.Hostname.ReverseDNS {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Hostname.TimeoutMs)*time.Millisecond)
				names, err := net.DefaultResolver.LookupAddr(ctx, ip)
				cancel()
				if err == nil && len(names) > 0 {
					h.Hostname = strings.TrimSuffix(names[0], ".")
				}
			}
			hosts[ip] = h
			openCount += len(ps)
			fmt.Printf("[FOUND] %s ports=%v hostname=%s\n", ip, ps, h.Hostname)
		}

		r := result.NetworkResult{
			SchemaVersion: 1,
			Network:       network,
			Hosts:         hosts,
			Statistics: result.Statistics{
				Scanned: len(addresses), Denied: denied[network],
				Responsive: len(hosts), OpenPorts: openCount,
			},
		}
		if err := result.Write(cfg.Output.Directory, r, cfg.Output.PrettyPrint); err != nil {
			log.Fatalf("write result: %v", err)
		}
		fmt.Printf("[INFO] %s completed in %s\n", network, time.Since(start).Round(time.Millisecond))
	}
}

// Package scope checks scan targets against an allowlist and a host limit.
// Both the server (when creating a job) and the agent (before connecting to
// anything) apply these checks, so neither side alone can widen what gets
// scanned.
package scope

import (
	"errors"
	"fmt"
	"net/netip"

	"netcrawler/internal/iprange"
)

// MaxHostsLimit is the highest host limit a crawler may have (a /16).
const MaxHostsLimit = 1 << 16

// privateRanges are the address ranges a crawler may be released for
// without explicitly allowing public ranges: RFC 1918, loopback,
// link-local and carrier-grade NAT.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

func isPrivate(r iprange.Range) bool {
	for _, p := range privateRanges {
		if p.Contains(r.First) && p.Contains(r.Last) {
			return true
		}
	}
	return false
}

// MaxPortsPerJob bounds the number of ports in one job.
const MaxPortsPerJob = 1024

// Allowlist is a set of permitted IPv4 ranges.
type Allowlist struct {
	entries []string
	ranges  []iprange.Range
}

// ParseAllowlist parses allowlist entries (address, CIDR or range).
func ParseAllowlist(entries []string) (Allowlist, error) {
	if len(entries) == 0 {
		return Allowlist{}, errors.New("allowlist is empty")
	}
	a := Allowlist{entries: entries}
	for _, e := range entries {
		r, err := iprange.Parse(e)
		if err != nil {
			return Allowlist{}, fmt.Errorf("allowlist entry %q: %w", e, err)
		}
		a.ranges = append(a.ranges, r)
	}
	return a, nil
}

// Entries returns the original entries.
func (a Allowlist) Entries() []string { return a.entries }

// covers reports whether r lies completely inside one allowlist entry.
func (a Allowlist) covers(r iprange.Range) bool {
	for _, allowed := range a.ranges {
		if allowed.Contains(r.First) && allowed.Contains(r.Last) {
			return true
		}
	}
	return false
}

// CheckRelease validates what a crawler is released to scan: the allowlist
// must be non-empty and valid, and the host limit between 1 and
// MaxHostsLimit. Unless allowPublic is set, every entry must lie in a
// private range (RFC 1918, loopback, link-local, CGNAT), so a typo can't
// release a public network.
func CheckRelease(allow []string, maxHosts int, allowPublic bool) error {
	a, err := ParseAllowlist(allow)
	if err != nil {
		return err
	}
	if maxHosts < 1 || maxHosts > MaxHostsLimit {
		return fmt.Errorf("host limit must be between 1 and %d, got %d", MaxHostsLimit, maxHosts)
	}
	if !allowPublic {
		for i, r := range a.ranges {
			if !isPrivate(r) {
				return fmt.Errorf("allowlist entry %q is not a private address range; public ranges need an explicit allow_public_ranges", a.entries[i])
			}
		}
	}
	return nil
}

// Request is the part of a job that determines what would be contacted.
type Request struct {
	Targets  []string
	MaxHosts int
	Ports    []int
}

// Check validates a scan request against an allowlist and a local host
// limit. It returns the number of distinct target addresses.
//
// Every target must lie entirely inside a single allowlist entry, the
// request's max_hosts must not exceed the local limit, the distinct
// address count must not exceed the request's max_hosts, and ports must be
// valid, unique and at most MaxPortsPerJob.
func Check(req Request, allow Allowlist, maxHosts int) (int, error) {
	if len(req.Targets) == 0 {
		return 0, errors.New("no targets")
	}
	if req.MaxHosts < 1 {
		return 0, fmt.Errorf("invalid max_hosts %d", req.MaxHosts)
	}
	if req.MaxHosts > maxHosts {
		return 0, fmt.Errorf("max_hosts %d exceeds the host limit of %d", req.MaxHosts, maxHosts)
	}
	limit := req.MaxHosts

	var ranges []iprange.Range
	var total uint64
	for _, t := range req.Targets {
		r, err := iprange.Parse(t)
		if err != nil {
			return 0, fmt.Errorf("target %q: %w", t, err)
		}
		if !allow.covers(r) {
			return 0, fmt.Errorf("target %q is outside the allowlist %q", t, allow.entries)
		}
		total += r.Size()
		if total > uint64(limit)*uint64(len(req.Targets)) {
			// Even fully overlapping targets can't get below the limit.
			return 0, fmt.Errorf("targets exceed the host limit of %d", limit)
		}
		ranges = append(ranges, r)
	}
	seen := map[netip.Addr]bool{}
	for _, r := range ranges {
		for _, a := range iprange.Addresses(r) {
			seen[a] = true
		}
	}
	if len(seen) > limit {
		return 0, fmt.Errorf("targets cover %d hosts, exceeding the host limit of %d", len(seen), limit)
	}

	if len(req.Ports) == 0 {
		return 0, errors.New("no ports")
	}
	if len(req.Ports) > MaxPortsPerJob {
		return 0, fmt.Errorf("%d ports exceed the limit of %d per job", len(req.Ports), MaxPortsPerJob)
	}
	dup := map[int]bool{}
	for _, p := range req.Ports {
		if p < 1 || p > 65535 {
			return 0, fmt.Errorf("invalid port %d", p)
		}
		if dup[p] {
			return 0, fmt.Errorf("duplicate port %d", p)
		}
		dup[p] = true
	}
	return len(seen), nil
}

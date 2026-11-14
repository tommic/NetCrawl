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

// PilotTarget is the only scope released for this version: the
// loopback-only pilot (see docs/E2E-ABNAHME.md). Any other scope needs a
// documented approval first and a code change that lifts PilotOnly.
const PilotTarget = "127.0.0.1/32"

// PilotMaxHosts is the host limit of the loopback pilot.
const PilotMaxHosts = 1

// PilotOnly restricts every scope to the loopback pilot.
const PilotOnly = true

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

// CheckPilot enforces the loopback pilot: the allowlist must be exactly
// 127.0.0.1/32 and the host limit exactly 1.
func CheckPilot(allow []string, maxHosts int) error {
	if !PilotOnly {
		return nil
	}
	if len(allow) != 1 || allow[0] != PilotTarget {
		return fmt.Errorf("only the loopback pilot is released: allowlist must be exactly [%q], got %q", PilotTarget, allow)
	}
	if maxHosts != PilotMaxHosts {
		return fmt.Errorf("only the loopback pilot is released: host limit must be %d, got %d", PilotMaxHosts, maxHosts)
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

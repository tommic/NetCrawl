package engine

import (
	"fmt"
	"net/netip"
	"sort"

	"netcrawler/internal/config"
	"netcrawler/internal/denylist"
	"netcrawler/internal/iprange"
)

// MaxNetworks caps a single plan at 65,536 /24 networks (the size of a /8),
// so a mistyped prefix like 10.0.0.0/1 fails fast instead of planning
// millions of work units.
const MaxNetworks = 1 << 16

// Job is one /24 work unit of a plan.
type Job struct {
	Network netip.Prefix
	// Targets is the number of addresses that will be scanned.
	Targets int
	// Denied is the number of included addresses excluded by the denylist.
	Denied int
}

// Plan lists the /24 work units for a config. Addresses are not stored;
// they are derived per job on demand so even large targets stay small in
// memory.
type Plan struct {
	// Jobs are the networks with at least one address to scan, sorted.
	Jobs []Job
	// FullyDenied are networks whose included addresses are all denied.
	FullyDenied []Job

	include []iprange.Range
	deny    *denylist.List
}

// BuildPlan expands targets.include into /24 jobs, applying the denylist
// before any job is created.
func BuildPlan(cfg *config.Config) (*Plan, error) {
	deny, err := denylist.New(cfg.Targets.Deny)
	if err != nil {
		return nil, err
	}
	p := &Plan{deny: deny}
	blocks := map[netip.Prefix]bool{}
	for _, target := range cfg.Targets.Include {
		r, err := iprange.Parse(target)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", target, err)
		}
		if r.Size() > MaxNetworks*256 {
			return nil, fmt.Errorf("target %q is too large (%d addresses, limit is a /8)", target, r.Size())
		}
		p.include = append(p.include, r)
		for _, b := range iprange.Blocks24(r) {
			blocks[b] = true
		}
		if len(blocks) > MaxNetworks {
			return nil, fmt.Errorf("targets cover more than %d /24 networks (limit is a /8)", MaxNetworks)
		}
	}

	networks := make([]netip.Prefix, 0, len(blocks))
	for b := range blocks {
		networks = append(networks, b)
	}
	sort.Slice(networks, func(i, j int) bool { return networks[i].Addr().Less(networks[j].Addr()) })

	for _, n := range networks {
		job := Job{Network: n}
		p.walk(n, func(_ netip.Addr, denied bool) {
			if denied {
				job.Denied++
			} else {
				job.Targets++
			}
		})
		switch {
		case job.Targets > 0:
			p.Jobs = append(p.Jobs, job)
		case job.Denied > 0:
			p.FullyDenied = append(p.FullyDenied, job)
		}
	}
	return p, nil
}

// Addresses returns the addresses to scan in a job's network.
func (p *Plan) Addresses(job Job) []netip.Addr {
	out := make([]netip.Addr, 0, job.Targets)
	p.walk(job.Network, func(a netip.Addr, denied bool) {
		if !denied {
			out = append(out, a)
		}
	})
	return out
}

// TotalTargets returns the number of addresses that will be scanned.
func (p *Plan) TotalTargets() int {
	n := 0
	for _, j := range p.Jobs {
		n += j.Targets
	}
	return n
}

// walk calls fn for every included address of the /24 network, in order,
// reporting whether the denylist excludes it. Overlapping include targets
// are visited once.
func (p *Plan) walk(network netip.Prefix, fn func(a netip.Addr, denied bool)) {
	a := network.Addr()
	for i := 0; i < 256; i++ {
		if p.included(a) {
			fn(a, p.deny.Contains(a))
		}
		a = a.Next()
	}
}

func (p *Plan) included(a netip.Addr) bool {
	for _, r := range p.include {
		if r.Contains(a) {
			return true
		}
	}
	return false
}

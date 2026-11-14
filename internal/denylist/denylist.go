// Package denylist holds addresses and ranges that must never be scanned.
package denylist

import (
	"fmt"
	"net/netip"

	"netcrawler/internal/iprange"
)

// List is a set of excluded IPv4 ranges.
type List struct{ ranges []iprange.Range }

// New parses each entry with the same formats as include targets.
func New(entries []string) (*List, error) {
	l := &List{}
	for _, e := range entries {
		r, err := iprange.Parse(e)
		if err != nil {
			return nil, fmt.Errorf("deny entry %q: %w", e, err)
		}
		l.ranges = append(l.ranges, r)
	}
	return l, nil
}

// Contains reports whether a is excluded.
func (l *List) Contains(a netip.Addr) bool {
	for _, r := range l.ranges {
		if r.Contains(a) {
			return true
		}
	}
	return false
}

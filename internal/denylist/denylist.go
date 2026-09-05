package denylist

import (
	"net/netip"
	"netcrawler/internal/iprange"
)

type List struct{ ranges []iprange.Range }

func New(entries []string) (*List, error) {
	l := &List{}
	for _, e := range entries {
		r, err := iprange.Parse(e)
		if err != nil {
			return nil, err
		}
		l.ranges = append(l.ranges, r)
	}
	return l, nil
}

func (l *List) Contains(a netip.Addr) bool {
	for _, r := range l.ranges {
		if a.Compare(r.First) >= 0 && a.Compare(r.Last) <= 0 {
			return true
		}
	}
	return false
}

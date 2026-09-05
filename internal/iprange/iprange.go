package iprange

import (
	"fmt"
	"net/netip"
	"strings"
)

type Range struct {
	First netip.Addr
	Last  netip.Addr
}

func Parse(value string) (Range, error) {
	value = strings.TrimSpace(value)
	if p, err := netip.ParsePrefix(value); err == nil {
		if !p.Addr().Is4() { return Range{}, fmt.Errorf("IPv6 is not supported") }
		p = p.Masked()
		first := p.Addr()
		b := first.As4()
		hostBits := 32 - p.Bits()
		n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		if hostBits == 32 { n = ^uint32(0) } else { n |= (uint32(1)<<hostBits)-1 }
		last := netip.AddrFrom4([4]byte{byte(n>>24), byte(n>>16), byte(n>>8), byte(n)})
		return Range{first, last}, nil
	}
	if a, err := netip.ParseAddr(value); err == nil {
		if !a.Is4() { return Range{}, fmt.Errorf("IPv6 is not supported") }
		return Range{a, a}, nil
	}
	parts := strings.Split(value, "-")
	if len(parts) == 2 {
		a, e1 := netip.ParseAddr(strings.TrimSpace(parts[0]))
		b, e2 := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if e1 != nil || e2 != nil || !a.Is4() || !b.Is4() || a.Compare(b) > 0 {
			return Range{}, fmt.Errorf("invalid IPv4 range: %s", value)
		}
		return Range{a, b}, nil
	}
	return Range{}, fmt.Errorf("invalid target: %s", value)
}

func Addresses(r Range) []netip.Addr {
	var out []netip.Addr
	for a := r.First; a.IsValid() && a.Compare(r.Last) <= 0; a = a.Next() {
		out = append(out, a)
	}
	return out
}

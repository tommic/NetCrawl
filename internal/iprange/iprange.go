// Package iprange parses IPv4 targets (single address, CIDR prefix, or
// "first-last" range) into inclusive address ranges.
package iprange

import (
	"fmt"
	"net/netip"
	"strings"
)

// Range is an inclusive IPv4 address range.
type Range struct {
	First netip.Addr
	Last  netip.Addr
}

// Parse accepts "192.168.1.20", "192.168.1.0/24" or
// "192.168.1.20-192.168.1.80". IPv6 is rejected.
func Parse(value string) (Range, error) {
	value = strings.TrimSpace(value)
	if p, err := netip.ParsePrefix(value); err == nil {
		if !p.Addr().Is4() {
			return Range{}, fmt.Errorf("IPv6 is not supported: %s", value)
		}
		p = p.Masked()
		first := toUint(p.Addr())
		hostBits := 32 - p.Bits()
		last := first
		if hostBits == 32 {
			last = ^uint32(0)
		} else {
			last |= (uint32(1) << hostBits) - 1
		}
		return Range{fromUint(first), fromUint(last)}, nil
	}
	if a, err := netip.ParseAddr(value); err == nil {
		if !a.Is4() {
			return Range{}, fmt.Errorf("IPv6 is not supported: %s", value)
		}
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

// Contains reports whether a lies within the range.
func (r Range) Contains(a netip.Addr) bool {
	return a.Is4() && a.Compare(r.First) >= 0 && a.Compare(r.Last) <= 0
}

// Size returns the number of addresses in the range.
func (r Range) Size() uint64 {
	return uint64(toUint(r.Last)-toUint(r.First)) + 1
}

// Blocks24 returns every /24 network that overlaps the range, in ascending
// order, without materializing the individual addresses.
func Blocks24(r Range) []netip.Prefix {
	start := toUint(r.First) &^ 0xff
	end := toUint(r.Last) &^ 0xff
	out := make([]netip.Prefix, 0, (end-start)/256+1)
	for n := start; ; n += 256 {
		out = append(out, netip.PrefixFrom(fromUint(n), 24))
		if n == end {
			break
		}
	}
	return out
}

// Addresses returns every address in the range. Only use it for small
// ranges such as a single /24.
func Addresses(r Range) []netip.Addr {
	var out []netip.Addr
	for a := r.First; a.IsValid() && a.Compare(r.Last) <= 0; a = a.Next() {
		out = append(out, a)
	}
	return out
}

func toUint(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fromUint(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

package denylist

import (
	"net/netip"
	"testing"
)

func TestContains(t *testing.T) {
	l, err := New([]string{"192.168.1.10", "192.168.10.0/24", "10.0.0.20-10.0.0.50"})
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"192.168.1.10":   true,
		"192.168.1.11":   false,
		"192.168.10.0":   true,
		"192.168.10.255": true,
		"192.168.11.0":   false,
		"10.0.0.19":      false,
		"10.0.0.20":      true,
		"10.0.0.50":      true,
		"10.0.0.51":      false,
	} {
		if got := l.Contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestEmpty(t *testing.T) {
	l, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if l.Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Error("empty denylist must not contain anything")
	}
}

func TestInvalidEntry(t *testing.T) {
	if _, err := New([]string{"192.168.1.10", "nope"}); err == nil {
		t.Error("expected error for invalid entry")
	}
}

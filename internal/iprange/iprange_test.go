package iprange

import (
	"net/netip"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in          string
		first, last string
	}{
		{"192.168.1.42", "192.168.1.42", "192.168.1.42"},
		{" 192.168.1.42 ", "192.168.1.42", "192.168.1.42"},
		{"192.168.1.0/24", "192.168.1.0", "192.168.1.255"},
		{"192.168.1.77/24", "192.168.1.0", "192.168.1.255"},
		{"10.20.0.0/16", "10.20.0.0", "10.20.255.255"},
		{"10.0.0.5/32", "10.0.0.5", "10.0.0.5"},
		{"0.0.0.0/0", "0.0.0.0", "255.255.255.255"},
		{"10.20.0.1-10.20.0.50", "10.20.0.1", "10.20.0.50"},
		{"10.20.0.1 - 10.20.0.50", "10.20.0.1", "10.20.0.50"},
	}
	for _, tt := range tests {
		r, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.in, err)
			continue
		}
		if r.First.String() != tt.first || r.Last.String() != tt.last {
			t.Errorf("Parse(%q) = %s-%s, want %s-%s", tt.in, r.First, r.Last, tt.first, tt.last)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	for _, in := range []string{
		"", "foo", "192.168.1", "192.168.1.256", "192.168.1.0/33",
		"10.0.0.50-10.0.0.1", "10.0.0.1-", "10.0.0.1-10.0.0.2-10.0.0.3",
		"::1", "2001:db8::/64", "10.0.0.1-::1",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q): expected error", in)
		}
	}
}

func TestContainsAndSize(t *testing.T) {
	r, _ := Parse("10.0.0.10-10.0.0.20")
	if !r.Contains(netip.MustParseAddr("10.0.0.10")) || !r.Contains(netip.MustParseAddr("10.0.0.20")) {
		t.Error("bounds must be inclusive")
	}
	if r.Contains(netip.MustParseAddr("10.0.0.9")) || r.Contains(netip.MustParseAddr("10.0.0.21")) {
		t.Error("addresses outside the range must not be contained")
	}
	if r.Contains(netip.MustParseAddr("::ffff:10.0.0.15")) {
		t.Error("IPv6 addresses must not be contained")
	}
	if got := r.Size(); got != 11 {
		t.Errorf("Size = %d, want 11", got)
	}
	all, _ := Parse("0.0.0.0/0")
	if got := all.Size(); got != 1<<32 {
		t.Errorf("Size(/0) = %d, want %d", got, uint64(1)<<32)
	}
}

func TestBlocks24(t *testing.T) {
	tests := []struct {
		in    string
		first string
		last  string
		count int
	}{
		{"192.168.1.5", "192.168.1.0/24", "192.168.1.0/24", 1},
		{"192.168.1.0/24", "192.168.1.0/24", "192.168.1.0/24", 1},
		{"192.168.1.128/25", "192.168.1.0/24", "192.168.1.0/24", 1},
		{"192.168.1.250-192.168.3.2", "192.168.1.0/24", "192.168.3.0/24", 3},
		{"10.20.0.0/16", "10.20.0.0/24", "10.20.255.0/24", 256},
		{"255.255.255.0/24", "255.255.255.0/24", "255.255.255.0/24", 1},
	}
	for _, tt := range tests {
		r, err := Parse(tt.in)
		if err != nil {
			t.Fatal(err)
		}
		b := Blocks24(r)
		if len(b) != tt.count || b[0].String() != tt.first || b[len(b)-1].String() != tt.last {
			t.Errorf("Blocks24(%q) = %d blocks %s..%s, want %d blocks %s..%s",
				tt.in, len(b), b[0], b[len(b)-1], tt.count, tt.first, tt.last)
		}
	}
}

func TestAddresses(t *testing.T) {
	r, _ := Parse("10.0.0.254-10.0.1.1")
	got := Addresses(r)
	want := []string{"10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"}
	if len(got) != len(want) {
		t.Fatalf("Addresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("Addresses[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	top, _ := Parse("255.255.255.254/31")
	if n := len(Addresses(top)); n != 2 {
		t.Errorf("Addresses at the top of the address space = %d, want 2", n)
	}
}

package scope

import (
	"strings"
	"testing"
)

func TestCheckRelease(t *testing.T) {
	for _, allow := range [][]string{
		{"127.0.0.1/32"}, {"192.168.1.0/24"}, {"10.0.0.0/8"}, {"172.16.0.0/12"},
		{"169.254.1.0/24"}, {"100.64.0.0/10"}, {"192.168.1.10-192.168.1.20", "10.1.2.3"},
	} {
		if err := CheckRelease(allow, 256, false); err != nil {
			t.Errorf("CheckRelease(%q): %v", allow, err)
		}
	}
	bad := []struct {
		allow []string
		max   int
		want  string
	}{
		{[]string{"8.8.8.0/24"}, 256, "not a private"},
		{[]string{"192.168.1.0/24", "1.1.1.1"}, 256, "not a private"},
		{[]string{"172.15.0.0/16"}, 256, "not a private"},
		{[]string{"192.168.0.0/15"}, 256, "not a private"},
		{nil, 1, "empty"},
		{[]string{"nope"}, 1, "allowlist entry"},
		{[]string{"192.168.1.0/24"}, 0, "host limit"},
		{[]string{"192.168.1.0/24"}, MaxHostsLimit + 1, "host limit"},
	}
	for _, b := range bad {
		err := CheckRelease(b.allow, b.max, false)
		if err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("CheckRelease(%q, %d) = %v, want %q", b.allow, b.max, err, b.want)
		}
	}
	if err := CheckRelease([]string{"8.8.8.0/24"}, 256, true); err != nil {
		t.Errorf("public range with allowPublic: %v", err)
	}
}

func TestCheck(t *testing.T) {
	pilot, err := ParseAllowlist([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	wide, _ := ParseAllowlist([]string{"10.0.0.0/24", "10.0.1.10-10.0.1.20"})

	ok := []struct {
		allow Allowlist
		req   Request
		max   int
		hosts int
	}{
		{pilot, Request{[]string{"127.0.0.1/32"}, 1, []int{22, 80}}, 1, 1},
		{pilot, Request{[]string{"127.0.0.1", "127.0.0.1/32"}, 1, []int{22}}, 1, 1},
		{wide, Request{[]string{"10.0.0.0/30", "10.0.1.12-10.0.1.13"}, 10, []int{22}}, 10, 6},
	}
	for _, tt := range ok {
		hosts, err := Check(tt.req, tt.allow, tt.max)
		if err != nil || hosts != tt.hosts {
			t.Errorf("Check(%+v) = %d, %v; want %d hosts", tt.req, hosts, err, tt.hosts)
		}
	}

	bad := []struct {
		allow Allowlist
		req   Request
		max   int
		want  string
	}{
		{pilot, Request{[]string{"127.0.0.2/32"}, 1, []int{22}}, 1, "outside the allowlist"},
		{pilot, Request{[]string{"192.168.1.10"}, 1, []int{22}}, 1, "outside the allowlist"},
		{pilot, Request{[]string{"127.0.0.0/31"}, 1, []int{22}}, 1, "outside the allowlist"},
		{pilot, Request{[]string{"127.0.0.1/32"}, 2, []int{22}}, 1, "exceeds the host limit"},
		{pilot, Request{[]string{"127.0.0.0/30"}, 1, []int{22}}, 1, "outside the allowlist"},
		{wide, Request{[]string{"10.0.0.0/24"}, 300, []int{22}}, 10, "host limit"},
		{wide, Request{[]string{"10.0.0.0/30"}, 2, []int{22}}, 10, "host limit"},
		{wide, Request{[]string{"10.0.1.0/24"}, 300, []int{22}}, 300, "outside the allowlist"},
		{pilot, Request{nil, 1, []int{22}}, 1, "no targets"},
		{pilot, Request{[]string{"127.0.0.1/32"}, 0, []int{22}}, 1, "max_hosts"},
		{pilot, Request{[]string{"127.0.0.1/32"}, 1, nil}, 1, "no ports"},
		{pilot, Request{[]string{"127.0.0.1/32"}, 1, []int{0}}, 1, "invalid port"},
		{pilot, Request{[]string{"127.0.0.1/32"}, 1, []int{22, 22}}, 1, "duplicate port"},
		{pilot, Request{[]string{"nope"}, 1, []int{22}}, 1, "target"},
	}
	for _, tt := range bad {
		_, err := Check(tt.req, tt.allow, tt.max)
		if tt.want == "" {
			if err != nil {
				t.Errorf("Check(%+v): unexpected error %v", tt.req, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("Check(%+v) err = %v, want %q", tt.req, err, tt.want)
		}
	}

	ports := make([]int, MaxPortsPerJob+1)
	for i := range ports {
		ports[i] = i + 1
	}
	if _, err := Check(Request{[]string{"127.0.0.1/32"}, 1, ports}, pilot, 1); err == nil {
		t.Error("too many ports accepted")
	}
	if _, err := ParseAllowlist(nil); err == nil {
		t.Error("empty allowlist accepted")
	}
}

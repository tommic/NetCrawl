package scope

import (
	"strings"
	"testing"
)

func TestCheckPilot(t *testing.T) {
	if err := CheckPilot([]string{"127.0.0.1/32"}, 1); err != nil {
		t.Errorf("pilot scope rejected: %v", err)
	}
	for _, tt := range []struct {
		allow []string
		max   int
	}{
		{[]string{"127.0.0.2/32"}, 1},
		{[]string{"127.0.0.1"}, 1},
		{[]string{"127.0.0.0/8"}, 1},
		{[]string{"192.168.1.0/24"}, 1},
		{[]string{"127.0.0.1/32", "10.0.0.1"}, 1},
		{nil, 1},
		{[]string{"127.0.0.1/32"}, 2},
		{[]string{"127.0.0.1/32"}, 0},
	} {
		if err := CheckPilot(tt.allow, tt.max); err == nil {
			t.Errorf("CheckPilot(%q, %d) accepted", tt.allow, tt.max)
		}
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

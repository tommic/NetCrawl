package result

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestCompareIPs(t *testing.T) {
	ips := []string{"192.168.0.102", "192.168.0.3", "10.0.0.1", "192.168.0.20"}
	sort.Slice(ips, func(i, j int) bool { return CompareIPs(ips[i], ips[j]) < 0 })
	want := []string{"10.0.0.1", "192.168.0.3", "192.168.0.20", "192.168.0.102"}
	if !reflect.DeepEqual(ips, want) {
		t.Errorf("got %v, want %v", ips, want)
	}
	if CompareIPs("b", "a") <= 0 {
		t.Error("unparsable values must fall back to string comparison")
	}
}

func TestCompareNetworks(t *testing.T) {
	nets := []string{"192.168.10.0/24", "192.168.2.0/24", "192.168.2.0/16", "10.0.0.0/24"}
	sort.Slice(nets, func(i, j int) bool { return CompareNetworks(nets[i], nets[j]) < 0 })
	want := []string{"10.0.0.0/24", "192.168.2.0/16", "192.168.2.0/24", "192.168.10.0/24"}
	if !reflect.DeepEqual(nets, want) {
		t.Errorf("got %v, want %v", nets, want)
	}
}

func TestFormatDetails(t *testing.T) {
	details := map[int]PortInfo{
		443: {TLSSubject: "router.local", TLSIssuer: "CA", TLSNotAfter: "2027-01-01"},
		22:  {Banner: "SSH-2.0-OpenSSH_9.6", SSHKeyType: "ssh-ed25519", SSHKeyFinger: "SHA256:abc"},
		80:  {},
	}
	got := FormatDetails(details, "; ")
	want := "22: banner=SSH-2.0-OpenSSH_9.6 sshKey=ssh-ed25519 sshFingerprint=SHA256:abc; 80; 443: cn=router.local issuer=CA expires=2027-01-01"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if FormatDetails(nil, "; ") != "" {
		t.Error("no details must render as empty string")
	}
}

func TestWriteRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "results")
	r := NetworkResult{
		SchemaVersion: SchemaVersion,
		ScanID:        "20260905-101500",
		ConfigHash:    "sha256:abc",
		Network:       "192.168.10.0/24",
		ScanStarted:   "2026-09-05T10:15:00Z",
		ScanFinished:  "2026-09-05T10:15:08Z",
		Hosts: map[string]Host{
			"192.168.10.15": {Hostname: "server01", Ports: []int{22, 443}, Details: map[int]PortInfo{22: {Banner: "SSH-2.0"}}},
		},
		Statistics: Statistics{Scanned: 254, Denied: 2, Responsive: 1, OpenPorts: 2},
	}
	for _, pretty := range []bool{true, false} {
		if err := Write(dir, r, pretty); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "192.168.10.0_24.json"))
		if err != nil {
			t.Fatal(err)
		}
		var got NetworkResult
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, r) {
			t.Errorf("pretty=%v: round trip mismatch\n got %+v\nwant %+v", pretty, got, r)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected only the result file, temp files left behind: %v", entries)
	}
}

func TestReadLegacyResult(t *testing.T) {
	// Files written before scan metadata existed must still decode.
	legacy := `{"schemaVersion":1,"network":"192.168.1.0/24","hosts":{"192.168.1.20":{"ports":[22]}},"statistics":{"scanned":253,"denied":1,"responsive":1,"openPorts":1}}`
	var r NetworkResult
	if err := json.Unmarshal([]byte(legacy), &r); err != nil {
		t.Fatal(err)
	}
	if r.ScanID != "" || r.Network != "192.168.1.0/24" || r.Hosts["192.168.1.20"].Ports[0] != 22 {
		t.Errorf("unexpected decode: %+v", r)
	}
}

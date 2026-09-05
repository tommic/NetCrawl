package result

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

type Host struct {
	Hostname string `json:"hostname,omitempty"`
	Ports    []int  `json:"ports"`
}

type NetworkResult struct {
	SchemaVersion int             `json:"schemaVersion"`
	Network       string          `json:"network"`
	Hosts         map[string]Host `json:"hosts"`
	Statistics    Statistics      `json:"statistics"`
}

type Statistics struct {
	Scanned    int `json:"scanned"`
	Denied     int `json:"denied"`
	Responsive int `json:"responsive"`
	OpenPorts  int `json:"openPorts"`
}

// CompareIPs orders two IP address strings numerically instead of
// lexicographically, so 192.168.0.3 sorts before 192.168.0.102.
// Values that fail to parse fall back to a plain string comparison.
func CompareIPs(a, b string) int {
	addrA, errA := netip.ParseAddr(a)
	addrB, errB := netip.ParseAddr(b)
	if errA == nil && errB == nil {
		return addrA.Compare(addrB)
	}
	return strings.Compare(a, b)
}

// CompareNetworks orders two CIDR strings by address and then prefix
// length, so "192.168.2.0/24" sorts before "192.168.10.0/24". Values
// that fail to parse fall back to a plain string comparison.
func CompareNetworks(a, b string) int {
	prefixA, errA := netip.ParsePrefix(a)
	prefixB, errB := netip.ParsePrefix(b)
	if errA == nil && errB == nil {
		if c := prefixA.Addr().Compare(prefixB.Addr()); c != 0 {
			return c
		}
		return prefixA.Bits() - prefixB.Bits()
	}
	return strings.Compare(a, b)
}

func Write(dir string, r NetworkResult, pretty bool) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	var data []byte
	var err error
	if pretty {
		data, err = json.MarshalIndent(r, "", "  ")
	} else {
		data, err = json.Marshal(r)
	}
	if err != nil {
		return err
	}
	name := strings.ReplaceAll(r.Network, "/", "_") + ".json"
	tmp := filepath.Join(dir, "."+name+".tmp")
	final := filepath.Join(dir, name)
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	fmt.Printf("[INFO] Written %s\n", final)
	return nil
}

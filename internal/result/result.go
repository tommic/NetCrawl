package result

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PortInfo holds optional service details gathered for a single open port:
// TLS certificate metadata, an HTTP title/Server header, or a plain-text
// protocol greeting banner. Fields are populated depending on which of
// these applies to the port; unrecognized ports have no PortInfo entry.
type PortInfo struct {
	Banner      string `json:"banner,omitempty"`
	HTTPTitle   string `json:"httpTitle,omitempty"`
	HTTPServer  string `json:"httpServer,omitempty"`
	TLSSubject  string `json:"tlsSubject,omitempty"`
	TLSIssuer   string `json:"tlsIssuer,omitempty"`
	TLSNotAfter string `json:"tlsNotAfter,omitempty"`
}

type Host struct {
	Hostname string           `json:"hostname,omitempty"`
	Ports    []int            `json:"ports"`
	Details  map[int]PortInfo `json:"details,omitempty"`
}

// FormatPortInfo renders one port's enrichment details as a single
// human-readable line, e.g. "443: cn=router.local issuer=Self expires=2027-01-01".
func FormatPortInfo(port int, info PortInfo) string {
	var parts []string
	if info.Banner != "" {
		parts = append(parts, "banner="+info.Banner)
	}
	if info.HTTPServer != "" {
		parts = append(parts, "server="+info.HTTPServer)
	}
	if info.HTTPTitle != "" {
		parts = append(parts, "title="+info.HTTPTitle)
	}
	if info.TLSSubject != "" {
		parts = append(parts, "cn="+info.TLSSubject)
	}
	if info.TLSIssuer != "" {
		parts = append(parts, "issuer="+info.TLSIssuer)
	}
	if info.TLSNotAfter != "" {
		parts = append(parts, "expires="+info.TLSNotAfter)
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d", port)
	}
	return fmt.Sprintf("%d: %s", port, strings.Join(parts, " "))
}

// FormatDetails renders every port's enrichment details as one line each,
// sorted by port, joined by sep. Hosts with no details render as "".
func FormatDetails(details map[int]PortInfo, sep string) string {
	if len(details) == 0 {
		return ""
	}
	ports := make([]int, 0, len(details))
	for p := range details {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	lines := make([]string, 0, len(ports))
	for _, p := range ports {
		lines = append(lines, FormatPortInfo(p, details[p]))
	}
	return strings.Join(lines, sep)
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
	// Include the PID so two concurrent netcrawler runs writing to the
	// same output directory don't race on the same temp file.
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.%d.tmp", name, os.Getpid()))
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

// Package ports resolves the configured port selection (a named preset plus
// custom single ports and port ranges) into a sorted, de-duplicated list.
package ports

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// MinPort and MaxPort bound every valid TCP port.
const (
	MinPort = 1
	MaxPort = 65535
)

// PresetAll selects every TCP port (1-65535).
const PresetAll = "all"

// PresetCustom (or an empty preset) selects no preset ports, only the
// entries listed under ports.custom.
const PresetCustom = "custom"

var presets = map[string][]int{
	"tiny":     {22, 80, 443},
	"common":   {21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443},
	"web":      {80, 443, 8000, 8080, 8081, 8443, 8888},
	"database": {1433, 1521, 3306, 5432, 6379, 27017},
	// top100: the 100 most common TCP ports (as used by nmap --top-ports 100).
	"top100": {
		7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110,
		111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513,
		514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
		1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
		3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
		6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153,
		49154, 49155, 49156, 49157,
	},
	// discovery: a small set of ports that most hosts answer on (open or
	// refused), for fast host discovery.
	"discovery": {22, 53, 80, 135, 139, 443, 445, 3389, 5000, 8080, 8443, 62078},
}

// Specs turns a port list back into entries for Resolve.
func Specs(list []int) []Spec {
	out := make([]Spec, len(list))
	for i, p := range list {
		out[i] = Spec(strconv.Itoa(p))
	}
	return out
}

// named holds every named preset with its ports sorted, built once.
var named = func() map[string][]int {
	out := make(map[string][]int, len(presets))
	for name, list := range presets {
		out[name] = append([]int(nil), list...)
		sort.Ints(out[name])
	}
	return out
}()

// Named returns the sorted ports of a named preset (not "all" or
// "custom"). The slice is shared: callers must not modify it.
func Named(name string) ([]int, bool) {
	list, ok := named[name]
	return list, ok
}

// Presets returns all valid preset names, sorted.
func Presets() []string {
	names := []string{PresetAll, PresetCustom}
	for name := range presets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Spec is one entry of ports.custom: either a single port ("8080" or the
// JSON number 8080) or an inclusive range ("9000-9010").
type Spec string

// UnmarshalJSON accepts both JSON numbers and strings, so existing configs
// with plain numeric ports keep working.
func (s *Spec) UnmarshalJSON(data []byte) error {
	var n json.Number
	if err := json.Unmarshal(data, &n); err == nil {
		*s = Spec(n.String())
		return nil
	}
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("port entry must be a number or a string like \"9000-9010\", got %s", string(data))
	}
	*s = Spec(str)
	return nil
}

// Bounds parses the entry and returns its inclusive port range.
func (s Spec) Bounds() (lo, hi int, err error) {
	value := strings.TrimSpace(string(s))
	if from, to, ok := strings.Cut(value, "-"); ok {
		lo, err = parsePort(from)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid port range %q: %w", value, err)
		}
		hi, err = parsePort(to)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid port range %q: %w", value, err)
		}
		if lo > hi {
			return 0, 0, fmt.Errorf("invalid port range %q: start is greater than end", value)
		}
		return lo, hi, nil
	}
	p, err := parsePort(value)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q: %w", value, err)
	}
	return p, p, nil
}

func parsePort(value string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("not a number")
	}
	if p < MinPort || p > MaxPort {
		return 0, fmt.Errorf("out of range %d-%d", MinPort, MaxPort)
	}
	return p, nil
}

// Resolve combines a preset with custom entries into a sorted list of unique
// ports. Unknown presets and malformed entries are errors rather than being
// silently ignored, so a typo can't quietly shrink the scan.
func Resolve(preset string, custom []Spec) ([]int, error) {
	selected := map[int]bool{}
	switch name := strings.TrimSpace(preset); name {
	case "", PresetCustom:
	case PresetAll:
		for p := MinPort; p <= MaxPort; p++ {
			selected[p] = true
		}
	default:
		list, ok := presets[name]
		if !ok {
			return nil, fmt.Errorf("unknown port preset %q (valid: %s)", name, strings.Join(Presets(), ", "))
		}
		for _, p := range list {
			selected[p] = true
		}
	}
	for _, spec := range custom {
		lo, hi, err := spec.Bounds()
		if err != nil {
			return nil, err
		}
		for p := lo; p <= hi; p++ {
			selected[p] = true
		}
	}
	out := make([]int, 0, len(selected))
	for p := range selected {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

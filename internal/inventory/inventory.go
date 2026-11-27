// Package inventory turns scan results into inventory changes and events:
// the initial baseline, new hosts, hosts that disappear or come back,
// hostname changes, and ports that open or close.
//
// The functions here are pure: they return a store.InventoryUpdate that the
// store runs atomically against the current state of one network.
package inventory

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"netcrawler/internal/protocol"
	"netcrawler/internal/store"
)

// Event types.
const (
	TypeBaseline        = "inventory.baseline"
	TypeHostNew         = "host.new"
	TypeHostBack        = "host.back"
	TypeHostOffline     = "host.offline"
	TypeHostnameChanged = "host.hostname_changed"
	TypePortsBaseline   = "ports.baseline"
	TypePortOpened      = "port.opened"
	TypePortClosed      = "port.closed"
)

// seen collects what a result reports per address.
type seen struct {
	hostname string
	ports    []int
}

func collect(res protocol.Result) map[string]seen {
	out := map[string]seen{}
	for _, n := range res.Networks {
		for ip, h := range n.Hosts {
			out[ip] = seen{hostname: h.Hostname, ports: h.Ports}
		}
	}
	return out
}

func details(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

func label(ip, hostname string) string {
	if hostname == "" {
		return ip
	}
	return ip + " (" + hostname + ")"
}

func joinPorts(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

func sortedKeys(m map[string]seen) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ApplyResult returns the update for an accepted job result of a network
// job. Discovery results mark hosts as seen; port scan results also
// compare open ports against the port baseline.
func ApplyResult(kind, jobID string, res protocol.Result, now time.Time) store.InventoryUpdate {
	found := collect(res)
	return func(n *store.Network, hosts map[string]*store.Host) ([]string, []store.Event, error) {
		u := updater{n: n, hosts: hosts, now: now, jobID: jobID, baseline: !n.BaselineDone}
		for _, ip := range sortedKeys(found) {
			u.markSeen(ip, found[ip].hostname)
			if kind == protocol.JobKindPorts {
				u.comparePorts(ip, found[ip].ports)
			}
		}
		switch kind {
		case protocol.JobKindDiscovery:
			t := now
			n.DiscoveryDoneAt = &t
			if !n.BaselineDone {
				n.BaselineDone = true
				u.event(store.Event{
					Type: TypeBaseline, Severity: store.SeverityInfo, Baseline: true,
					Message: fmt.Sprintf("Initialbestand für %q erfasst: %d Host(s)", n.Name, len(found)),
					Details: details(map[string]int{"hosts": len(found)}),
				})
			}
			u.sweep()
		case protocol.JobKindPorts:
			t := now
			n.PortscanDoneAt = &t
		}
		return u.changedList(), u.events, nil
	}
}

// Sweep returns an update that only checks for offline hosts.
func Sweep(now time.Time) store.InventoryUpdate {
	return func(n *store.Network, hosts map[string]*store.Host) ([]string, []store.Event, error) {
		u := updater{n: n, hosts: hosts, now: now}
		u.sweep()
		return u.changedList(), u.events, nil
	}
}

type updater struct {
	n        *store.Network
	hosts    map[string]*store.Host
	now      time.Time
	jobID    string
	baseline bool
	changed  map[string]bool
	events   []store.Event
}

func (u *updater) touch(ip string) {
	if u.changed == nil {
		u.changed = map[string]bool{}
	}
	u.changed[ip] = true
}

func (u *updater) changedList() []string {
	out := make([]string, 0, len(u.changed))
	for ip := range u.changed {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func (u *updater) event(e store.Event) {
	e.At = u.now
	e.JobID = u.jobID
	if e.Details == nil {
		e.Details = json.RawMessage("null")
	}
	u.events = append(u.events, e)
}

// markSeen records that ip answered: new host, host back, hostname change.
func (u *updater) markSeen(ip, hostname string) {
	h, ok := u.hosts[ip]
	u.touch(ip)
	if !ok {
		u.hosts[ip] = &store.Host{NetworkID: u.n.ID, IP: ip, Hostname: hostname, FirstSeen: u.now, LastSeen: u.now}
		u.event(store.Event{
			IP: ip, Type: TypeHostNew, Severity: store.SeverityInfo, Baseline: u.baseline,
			Message: "Neuer Host " + label(ip, hostname),
			Details: details(map[string]string{"hostname": hostname}),
		})
		return
	}
	if h.OfflineLevel != "" {
		u.event(store.Event{
			IP: ip, Type: TypeHostBack, Severity: store.SeverityInfo,
			Message: fmt.Sprintf("Host %s wieder erreichbar (zuletzt gesehen %s)", label(ip, h.Hostname), h.LastSeen.UTC().Format(time.RFC3339)),
			Details: details(map[string]any{"last_seen": h.LastSeen, "offline_level": h.OfflineLevel}),
		})
		h.OfflineLevel = ""
	}
	if hostname != "" && hostname != h.Hostname {
		if h.Hostname != "" {
			u.event(store.Event{
				IP: ip, Type: TypeHostnameChanged, Severity: store.SeverityInfo,
				Message: fmt.Sprintf("Hostname von %s geändert: %s → %s", ip, h.Hostname, hostname),
				Details: details(map[string]string{"old": h.Hostname, "new": hostname}),
			})
		}
		h.Hostname = hostname
	}
	h.LastSeen = u.now
}

// comparePorts updates the port baseline of a host that answered a port
// scan. The first scan of a host establishes its baseline without
// warnings.
func (u *updater) comparePorts(ip string, open []int) {
	h := u.hosts[ip]
	u.touch(ip)
	first := h.PortsScannedAt == nil
	t := u.now
	h.PortsScannedAt = &t

	current := map[int]bool{}
	for _, p := range open {
		current[p] = true
	}
	var kept []store.HostPort
	var closed, opened []int
	known := map[int]bool{}
	for _, p := range h.Ports {
		known[p.Port] = true
		if current[p.Port] {
			p.LastSeen = u.now
			kept = append(kept, p)
		} else {
			closed = append(closed, p.Port)
		}
	}
	for _, p := range open {
		if !known[p] {
			kept = append(kept, store.HostPort{Port: p, FirstSeen: u.now, LastSeen: u.now})
			opened = append(opened, p)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Port < kept[j].Port })
	h.Ports = kept

	if first {
		msg := "Port-Baseline für " + label(ip, h.Hostname) + ": "
		if len(opened) == 0 {
			msg += "keine offenen Ports"
		} else {
			msg += joinPorts(opened)
		}
		u.event(store.Event{
			IP: ip, Type: TypePortsBaseline, Severity: store.SeverityInfo, Baseline: true,
			Message: msg, Details: details(map[string][]int{"ports": nonNilInts(opened)}),
		})
		return
	}
	for _, p := range opened {
		u.event(store.Event{
			IP: ip, Type: TypePortOpened, Severity: store.SeverityWarning,
			Message: fmt.Sprintf("Port %d neu offen auf %s", p, label(ip, h.Hostname)),
			Details: details(map[string]int{"port": p}),
		})
	}
	for _, p := range closed {
		u.event(store.Event{
			IP: ip, Type: TypePortClosed, Severity: store.SeverityInfo,
			Message: fmt.Sprintf("Port %d auf %s nicht mehr offen", p, label(ip, h.Hostname)),
			Details: details(map[string]int{"port": p}),
		})
	}
}

func nonNilInts(v []int) []int {
	if v == nil {
		return []int{}
	}
	return v
}

// sweep raises offline events. Absence is measured against the last
// completed discovery run, not the clock, so a crawler outage doesn't
// mark every host as gone.
func (u *updater) sweep() {
	if u.n.DiscoveryDoneAt == nil {
		return
	}
	ref := *u.n.DiscoveryDoneAt
	ips := make([]string, 0, len(u.hosts))
	for ip := range u.hosts {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		h := u.hosts[ip]
		missing := ref.Sub(h.LastSeen)
		var level string
		switch {
		case h.Important && missing >= u.n.OfflineCriticalAfter:
			level = store.SeverityCritical
		case missing >= u.n.OfflineWarnAfter:
			level = store.SeverityWarning
		case missing >= u.n.OfflineInfoAfter:
			level = store.SeverityInfo
		default:
			continue
		}
		if rank(level) <= rank(h.OfflineLevel) {
			continue
		}
		h.OfflineLevel = level
		u.touch(ip)
		u.event(store.Event{
			IP: ip, Type: TypeHostOffline, Severity: level,
			Message: fmt.Sprintf("Host %s seit %s nicht mehr gesehen", label(ip, h.Hostname), humanDuration(missing)),
			Details: details(map[string]any{"last_seen": h.LastSeen, "missing_seconds": int(missing.Seconds()), "important": h.Important}),
		})
	}
}

func rank(level string) int {
	switch level {
	case store.SeverityInfo:
		return 1
	case store.SeverityWarning:
		return 2
	case store.SeverityCritical:
		return 3
	}
	return 0
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d Tagen", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%d Stunden", int(d.Hours()))
	default:
		return fmt.Sprintf("%d Minuten", int(d.Minutes()))
	}
}

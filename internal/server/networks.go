package server

import (
	"context"
	"errors"
	"strings"
	"time"

	"netcrawler/internal/iprange"
	"netcrawler/internal/ports"
	"netcrawler/internal/scope"
	"netcrawler/internal/store"
)

// Network defaults (see the project decisions: discovery every 30 min,
// port scan daily with the top 100 ports, offline info after 24 h and
// warning after 7 days).
const (
	DefaultDiscoveryMinutes = 30
	MinDiscoveryMinutes     = 5
	DefaultPortscanHours    = 24
	DefaultOfflineInfoHours = 24
	DefaultOfflineWarnHours = 7 * 24
	DefaultDiscoveryPreset  = "discovery"
	DefaultScanPreset       = "top100"
)

// NetworkRequest describes a network to scan. Zero values get defaults.
type NetworkRequest struct {
	CrawlerID      string   `json:"crawler_id"`
	Name           string   `json:"name"`
	Targets        []string `json:"targets"`
	Deny           []string `json:"deny"`
	DiscoveryPorts []int    `json:"discovery_ports"`
	// ScanPreset selects the port scan ports if ScanPorts is empty
	// (default "top100").
	ScanPreset              string `json:"scan_preset"`
	ScanPorts               []int  `json:"scan_ports"`
	DiscoveryIntervalMinute int    `json:"discovery_interval_minutes"`
	PortscanIntervalHours   int    `json:"portscan_interval_hours"`
	OfflineInfoHours        int    `json:"offline_info_hours"`
	OfflineWarnHours        int    `json:"offline_warn_hours"`
	ReverseDNS              *bool  `json:"reverse_dns"`
	Enabled                 *bool  `json:"enabled"`
}

// buildNetwork validates a request against the crawler's release and
// returns the network settings.
func buildNetwork(ctx context.Context, st store.Store, req NetworkRequest) (store.Network, error) {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 64 {
		return store.Network{}, invalid("name must be 1-64 characters")
	}
	c, err := st.Crawler(ctx, req.CrawlerID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Network{}, invalid("unknown crawler %q", req.CrawlerID)
	}
	if err != nil {
		return store.Network{}, err
	}
	if len(req.DiscoveryPorts) == 0 {
		req.DiscoveryPorts, _ = ports.Resolve(DefaultDiscoveryPreset, nil)
	}
	if len(req.ScanPorts) == 0 {
		preset := req.ScanPreset
		if preset == "" {
			preset = DefaultScanPreset
		}
		list, err := ports.Resolve(preset, nil)
		if err != nil {
			return store.Network{}, invalid("scan_preset: %v", err)
		}
		if len(list) == 0 || len(list) > scope.MaxPortsPerJob {
			return store.Network{}, invalid("scan_preset %q is not usable for scheduled scans", preset)
		}
		req.ScanPorts = list
	}
	allow, err := scope.ParseAllowlist(c.Allow)
	if err != nil {
		return store.Network{}, err
	}
	hosts, err := scope.Check(scope.Request{Targets: req.Targets, MaxHosts: c.MaxHosts, Ports: req.DiscoveryPorts}, allow, c.MaxHosts)
	if err != nil {
		return store.Network{}, invalid("%v", err)
	}
	if _, err := scope.Check(scope.Request{Targets: req.Targets, MaxHosts: hosts, Ports: req.ScanPorts}, allow, c.MaxHosts); err != nil {
		return store.Network{}, invalid("scan ports: %v", err)
	}
	for _, d := range req.Deny {
		if _, err := iprange.Parse(d); err != nil {
			return store.Network{}, invalid("deny: %v", err)
		}
	}
	def := func(v, d int) int {
		if v == 0 {
			return d
		}
		return v
	}
	n := store.Network{
		CrawlerID: c.ID, Name: req.Name, Targets: req.Targets, Deny: req.Deny,
		DiscoveryPorts: req.DiscoveryPorts, ScanPorts: req.ScanPorts,
		DiscoveryInterval: time.Duration(def(req.DiscoveryIntervalMinute, DefaultDiscoveryMinutes)) * time.Minute,
		PortscanInterval:  time.Duration(def(req.PortscanIntervalHours, DefaultPortscanHours)) * time.Hour,
		OfflineInfoAfter:  time.Duration(def(req.OfflineInfoHours, DefaultOfflineInfoHours)) * time.Hour,
		OfflineWarnAfter:  time.Duration(def(req.OfflineWarnHours, DefaultOfflineWarnHours)) * time.Hour,
		ReverseDNS:        req.ReverseDNS == nil || *req.ReverseDNS,
		Enabled:           req.Enabled == nil || *req.Enabled,
	}
	switch {
	case n.DiscoveryInterval < MinDiscoveryMinutes*time.Minute:
		return store.Network{}, invalid("discovery_interval_minutes must be at least %d", MinDiscoveryMinutes)
	case n.PortscanInterval < time.Hour:
		return store.Network{}, invalid("portscan_interval_hours must be at least 1")
	case n.OfflineInfoAfter < time.Hour || n.OfflineWarnAfter < n.OfflineInfoAfter:
		return store.Network{}, invalid("offline_info_hours must be at least 1 and offline_warn_hours at least offline_info_hours")
	}
	return n, nil
}

// CreateNetwork validates and stores a network.
func CreateNetwork(ctx context.Context, st store.Store, actor string, req NetworkRequest, now time.Time) (store.Network, error) {
	n, err := buildNetwork(ctx, st, req)
	if err != nil {
		return store.Network{}, err
	}
	n.CreatedAt = now.UTC()
	id, err := st.CreateNetwork(ctx, n)
	if errors.Is(err, store.ErrExists) {
		return store.Network{}, invalid("a network named %q already exists", n.Name)
	}
	if err != nil {
		return store.Network{}, err
	}
	n.ID = id
	_ = st.Audit(ctx, actor, "network.create", map[string]any{
		"id": n.ID, "name": n.Name, "crawler_id": n.CrawlerID, "targets": n.Targets, "deny": n.Deny,
	})
	return n, nil
}

// UpdateNetwork replaces a network's settings; the crawler can't change.
func UpdateNetwork(ctx context.Context, st store.Store, actor string, id int64, req NetworkRequest) (store.Network, error) {
	cur, err := st.Network(ctx, id)
	if err != nil {
		return store.Network{}, err
	}
	req.CrawlerID = cur.CrawlerID
	n, err := buildNetwork(ctx, st, req)
	if err != nil {
		return store.Network{}, err
	}
	n.ID = id
	if err := st.UpdateNetworkSettings(ctx, n); err != nil {
		if errors.Is(err, store.ErrExists) {
			return store.Network{}, invalid("a network named %q already exists", n.Name)
		}
		return store.Network{}, err
	}
	_ = st.Audit(ctx, actor, "network.update", map[string]any{
		"id": id, "name": n.Name, "targets": n.Targets, "deny": n.Deny, "enabled": n.Enabled,
	})
	return st.Network(ctx, id)
}

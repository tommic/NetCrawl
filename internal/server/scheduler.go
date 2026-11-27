package server

import (
	"context"
	"fmt"
	"time"

	"netcrawler/internal/eventlog"
	"netcrawler/internal/inventory"
	"netcrawler/internal/protocol"
	"netcrawler/internal/store"
)

// Job lifetimes of scheduled jobs.
const (
	discoveryJobTTL = 10 * time.Minute
	portscanJobTTL  = 60 * time.Minute
	scheduledActor  = "scheduler"
)

// applyInventory runs an inventory update, writes its events to the log
// and returns them.
func (s *Server) applyInventory(ctx context.Context, networkID int64, fn store.InventoryUpdate) ([]store.Event, error) {
	var events []store.Event
	var name string
	err := s.st.UpdateInventory(ctx, networkID, func(n *store.Network, hosts map[string]*store.Host) ([]string, []store.Event, error) {
		changed, ev, err := fn(n, hosts)
		events, name = ev, n.Name
		return changed, ev, err
	})
	if err != nil {
		return nil, err
	}
	entries := make([]eventlog.Entry, 0, len(events))
	for _, e := range events {
		entries = append(entries, eventlog.Entry{
			At: e.At, Network: name, NetworkID: networkID, IP: e.IP, Type: e.Type, Severity: e.Severity,
			Message: e.Message, Details: e.Details, JobID: e.JobID, Baseline: e.Baseline,
		})
		if !e.Baseline {
			s.log.Info("inventory event", "network", name, "severity", e.Severity, "type", e.Type, "ip", e.IP, "msg", e.Message)
		}
	}
	if err := s.events.Write(entries); err != nil {
		s.log.Error("event log", "err", err)
	}
	return events, nil
}

// newHostIPs returns the addresses of hosts that a discovery found for the
// first time after the network's baseline.
func newHostIPs(events []store.Event) []string {
	var ips []string
	for _, e := range events {
		if e.Type == inventory.TypeHostNew && !e.Baseline {
			ips = append(ips, e.IP)
		}
	}
	return ips
}

// scanNewHosts creates a port scan job for hosts that just appeared, so
// their ports are known right away instead of after the next regular
// port scan. It does not move the network's port scan schedule.
func (s *Server) scanNewHosts(ctx context.Context, networkID int64, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	n, err := s.st.Network(ctx, networkID)
	if err != nil {
		return err
	}
	if !n.Enabled {
		return nil
	}
	if c, err := s.st.Crawler(ctx, n.CrawlerID); err != nil || !c.Enabled {
		return err
	}
	targets := make([]string, len(ips))
	for i, ip := range ips {
		targets[i] = ip + "/32"
	}
	// New hosts get their services identified right away as well.
	if _, err := s.networkJob(ctx, n, protocol.JobKindPorts, targets, n.ScanPorts, true, portscanJobTTL, s.now()); err != nil {
		return fmt.Errorf("port scan job for new hosts: %w", err)
	}
	return nil
}

// RunScheduler calls Tick every interval until ctx is done.
func (s *Server) RunScheduler(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("scheduler", "err", err)
		}
		if err := s.Notify(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("notifications", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Tick creates due discovery and port scan jobs for all enabled networks.
// A network gets at most one open job per kind.
func (s *Server) Tick(ctx context.Context) error {
	now := s.now()
	networks, err := s.st.ListNetworks(ctx)
	if err != nil {
		return err
	}
	for _, n := range networks {
		if !n.Enabled {
			continue
		}
		if c, err := s.st.Crawler(ctx, n.CrawlerID); err != nil || !c.Enabled {
			continue // a disabled crawler would never pick the jobs up
		}
		if err := s.scheduleNetwork(ctx, n, now); err != nil {
			s.log.Warn("scheduler: network skipped", "network", n.Name, "err", err)
			_ = s.st.Audit(ctx, scheduledActor, "scheduler.error", map[string]any{"network_id": n.ID, "error": err.Error()})
		}
	}
	return nil
}

func due(last *time.Time, interval time.Duration, now time.Time) bool {
	return last == nil || !now.Before(last.Add(interval))
}

func (s *Server) scheduleNetwork(ctx context.Context, n store.Network, now time.Time) error {
	lastDisc, lastScan, lastSvc := n.LastDiscoveryAt, n.LastPortscanAt, n.LastServicesAt
	created := false

	if due(lastDisc, n.DiscoveryInterval, now) {
		open, err := s.st.OpenNetworkJobs(ctx, n.ID, protocol.JobKindDiscovery, now)
		if err != nil {
			return err
		}
		if open == 0 {
			if _, err := s.networkJob(ctx, n, protocol.JobKindDiscovery, n.Targets, n.DiscoveryPorts, false, discoveryJobTTL, now); err != nil {
				return fmt.Errorf("discovery job: %w", err)
			}
			t := now
			lastDisc, created = &t, true
		}
	}

	// Port scans need a discovery result first; they only target hosts
	// currently considered present.
	if n.DiscoveryDoneAt != nil && due(lastScan, n.PortscanInterval, now) {
		open, err := s.st.OpenNetworkJobs(ctx, n.ID, protocol.JobKindPorts, now)
		if err != nil {
			return err
		}
		if open == 0 {
			hosts, err := s.st.Hosts(ctx, n.ID)
			if err != nil {
				return err
			}
			var targets []string
			for _, h := range hosts {
				if h.OfflineLevel == "" {
					targets = append(targets, h.IP+"/32")
				}
			}
			// Service detection rides along when it is due.
			services := due(lastSvc, n.ServiceInterval, now)
			if len(targets) > 0 {
				if _, err := s.networkJob(ctx, n, protocol.JobKindPorts, targets, n.ScanPorts, services, portscanJobTTL, now); err != nil {
					return fmt.Errorf("port scan job: %w", err)
				}
			}
			t := now
			lastScan, created = &t, true
			if services {
				lastSvc = &t
			}
		}
	}

	if created {
		return s.st.UpdateNetworkSchedule(ctx, n.ID, lastDisc, lastScan, lastSvc)
	}
	return nil
}

func (s *Server) networkJob(ctx context.Context, n store.Network, kind string, targets []string, ports []int, services bool, ttl time.Duration, now time.Time) (store.Job, error) {
	c, err := s.st.Crawler(ctx, n.CrawlerID)
	if err != nil {
		return store.Job{}, err
	}
	id := n.ID
	return CreateJob(ctx, s.st, scheduledActor, JobRequest{
		CrawlerID: n.CrawlerID, Targets: targets, Deny: n.Deny, Ports: ports, MaxHosts: c.MaxHosts,
		TTLSeconds: int(ttl.Seconds()), Kind: kind, ReverseDNS: n.ReverseDNS, Services: services, NetworkID: &id,
	}, now)
}

// ScanNow makes the next Tick create a job of the given kind for the
// network (if none is open) and runs it.
func (s *Server) ScanNow(ctx context.Context, actor string, id int64, kind string) error {
	n, err := s.st.Network(ctx, id)
	if err != nil {
		return err
	}
	lastDisc, lastScan, lastSvc := n.LastDiscoveryAt, n.LastPortscanAt, n.LastServicesAt
	switch kind {
	case protocol.JobKindDiscovery:
		lastDisc = nil
	case protocol.JobKindPorts:
		if n.DiscoveryDoneAt == nil {
			return invalid("no discovery result yet: run a discovery first")
		}
		lastScan, lastSvc = nil, nil // "port scan now" includes the services
	default:
		return invalid("kind must be %q or %q", protocol.JobKindDiscovery, protocol.JobKindPorts)
	}
	if !n.Enabled {
		return invalid("network %q is disabled", n.Name)
	}
	if err := s.st.UpdateNetworkSchedule(ctx, id, lastDisc, lastScan, lastSvc); err != nil {
		return err
	}
	_ = s.st.Audit(ctx, actor, "network.scan_now", map[string]any{"id": id, "kind": kind})
	n.LastDiscoveryAt, n.LastPortscanAt, n.LastServicesAt = lastDisc, lastScan, lastSvc
	return s.scheduleNetwork(ctx, n, s.now())
}

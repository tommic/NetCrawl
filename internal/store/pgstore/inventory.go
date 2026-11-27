package pgstore

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"netcrawler/internal/store"
)

func secs(d time.Duration) int { return int(d / time.Second) }
func dur(s int) time.Duration  { return time.Duration(s) * time.Second }

func ints(v []int32) []int {
	out := make([]int, len(v))
	for i, p := range v {
		out[i] = int(p)
	}
	return out
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

const networkColumns = `id, crawler_id, name, targets, deny, discovery_ports, scan_ports, discovery_interval_s,
	portscan_interval_s, offline_info_s, offline_warn_s, offline_critical_s, reverse_dns, enabled, created_at,
	last_discovery_at, last_portscan_at, discovery_done_at, portscan_done_at, baseline_done`

func scanNetwork(row pgx.Row) (store.Network, error) {
	var n store.Network
	var dp, sp []int32
	var di, pi, oi, ow, oc int
	err := row.Scan(&n.ID, &n.CrawlerID, &n.Name, &n.Targets, &n.Deny, &dp, &sp, &di, &pi, &oi, &ow, &oc,
		&n.ReverseDNS, &n.Enabled, &n.CreatedAt, &n.LastDiscoveryAt, &n.LastPortscanAt,
		&n.DiscoveryDoneAt, &n.PortscanDoneAt, &n.BaselineDone)
	n.DiscoveryPorts, n.ScanPorts = ints(dp), ints(sp)
	n.DiscoveryInterval, n.PortscanInterval = dur(di), dur(pi)
	n.OfflineInfoAfter, n.OfflineWarnAfter, n.OfflineCriticalAfter = dur(oi), dur(ow), dur(oc)
	return n, err
}

func (s *Store) CreateNetwork(ctx context.Context, n store.Network) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO networks (crawler_id, name, targets, deny, discovery_ports, scan_ports,
		discovery_interval_s, portscan_interval_s, offline_info_s, offline_warn_s, reverse_dns, enabled, created_at,
		offline_critical_s)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id`,
		n.CrawlerID, n.Name, n.Targets, nonNil(n.Deny), n.DiscoveryPorts, n.ScanPorts,
		secs(n.DiscoveryInterval), secs(n.PortscanInterval), secs(n.OfflineInfoAfter), secs(n.OfflineWarnAfter),
		n.ReverseDNS, n.Enabled, n.CreatedAt, secs(n.OfflineCriticalAfter)).Scan(&id)
	switch {
	case isUniqueViolation(err):
		return 0, store.ErrExists
	case isForeignKeyViolation(err):
		return 0, store.ErrNotFound
	}
	return id, err
}

func (s *Store) Network(ctx context.Context, id int64) (store.Network, error) {
	n, err := scanNetwork(s.pool.QueryRow(ctx, `SELECT `+networkColumns+` FROM networks WHERE id = $1`, id))
	return n, notFound(err)
}

func (s *Store) ListNetworks(ctx context.Context) ([]store.Network, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+networkColumns+` FROM networks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Network
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) UpdateNetworkSettings(ctx context.Context, n store.Network) error {
	tag, err := s.pool.Exec(ctx, `UPDATE networks SET name = $2, targets = $3, deny = $4, discovery_ports = $5,
		scan_ports = $6, discovery_interval_s = $7, portscan_interval_s = $8, offline_info_s = $9,
		offline_warn_s = $10, reverse_dns = $11, enabled = $12, offline_critical_s = $13 WHERE id = $1`,
		n.ID, n.Name, n.Targets, nonNil(n.Deny), n.DiscoveryPorts, n.ScanPorts,
		secs(n.DiscoveryInterval), secs(n.PortscanInterval), secs(n.OfflineInfoAfter), secs(n.OfflineWarnAfter),
		n.ReverseDNS, n.Enabled, secs(n.OfflineCriticalAfter))
	if isUniqueViolation(err) {
		return store.ErrExists
	}
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) UpdateNetworkSchedule(ctx context.Context, id int64, lastDiscovery, lastPortscan *time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE networks SET last_discovery_at = $2, last_portscan_at = $3 WHERE id = $1`,
		id, lastDiscovery, lastPortscan)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) OpenNetworkJobs(ctx context.Context, networkID int64, kind string, now time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE network_id = $1 AND kind = $2
		AND status <> 'completed' AND expires_at > $3`, networkID, kind, now).Scan(&n)
	return n, err
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// loadHosts reads hosts (with ports) of one network, or all if networkID
// is 0.
func loadHosts(ctx context.Context, q querier, networkID int64) ([]store.Host, error) {
	rows, err := q.Query(ctx, `SELECT network_id, ip, hostname, custom_name, first_seen, last_seen, important, offline_level,
		ports_scanned_at FROM hosts WHERE $1 = 0 OR network_id = $1`, networkID)
	if err != nil {
		return nil, err
	}
	type key struct {
		net int64
		ip  string
	}
	var hosts []store.Host
	index := map[key]int{}
	for rows.Next() {
		var h store.Host
		if err := rows.Scan(&h.NetworkID, &h.IP, &h.Hostname, &h.CustomName, &h.FirstSeen, &h.LastSeen, &h.Important,
			&h.OfflineLevel, &h.PortsScannedAt); err != nil {
			rows.Close()
			return nil, err
		}
		index[key{h.NetworkID, h.IP}] = len(hosts)
		hosts = append(hosts, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT network_id, ip, port, first_seen, last_seen FROM host_ports
		WHERE $1 = 0 OR network_id = $1 ORDER BY port`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k key
		var p store.HostPort
		if err := rows.Scan(&k.net, &k.ip, &p.Port, &p.FirstSeen, &p.LastSeen); err != nil {
			return nil, err
		}
		if i, ok := index[k]; ok {
			hosts[i].Ports = append(hosts[i].Ports, p)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].NetworkID != hosts[j].NetworkID {
			return hosts[i].NetworkID < hosts[j].NetworkID
		}
		a, errA := netip.ParseAddr(hosts[i].IP)
		b, errB := netip.ParseAddr(hosts[j].IP)
		if errA != nil || errB != nil {
			return hosts[i].IP < hosts[j].IP
		}
		return a.Less(b)
	})
	return hosts, nil
}

func (s *Store) Hosts(ctx context.Context, networkID int64) ([]store.Host, error) {
	return loadHosts(ctx, s.pool, networkID)
}

func (s *Store) UpdateInventory(ctx context.Context, networkID int64, fn store.InventoryUpdate) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	n, err := scanNetwork(tx.QueryRow(ctx, `SELECT `+networkColumns+` FROM networks WHERE id = $1 FOR UPDATE`, networkID))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	list, err := loadHosts(ctx, tx, networkID)
	if err != nil {
		return err
	}
	hosts := make(map[string]*store.Host, len(list))
	for i := range list {
		hosts[list[i].IP] = &list[i]
	}
	changed, events, err := fn(&n, hosts)
	if err != nil {
		return err
	}

	batch := &pgx.Batch{}
	for _, ip := range changed {
		h, ok := hosts[ip]
		if !ok {
			continue
		}
		batch.Queue(`INSERT INTO hosts (network_id, ip, hostname, first_seen, last_seen, important, offline_level, ports_scanned_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (network_id, ip) DO UPDATE SET hostname = EXCLUDED.hostname, first_seen = EXCLUDED.first_seen,
			last_seen = EXCLUDED.last_seen, important = EXCLUDED.important, offline_level = EXCLUDED.offline_level,
			ports_scanned_at = EXCLUDED.ports_scanned_at`,
			networkID, ip, h.Hostname, h.FirstSeen, h.LastSeen, h.Important, h.OfflineLevel, h.PortsScannedAt)
		batch.Queue(`DELETE FROM host_ports WHERE network_id = $1 AND ip = $2`, networkID, ip)
		for _, p := range h.Ports {
			batch.Queue(`INSERT INTO host_ports (network_id, ip, port, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5)`,
				networkID, ip, p.Port, p.FirstSeen, p.LastSeen)
		}
	}
	for _, e := range events {
		details := e.Details
		if details == nil {
			details = []byte("null")
		}
		batch.Queue(`INSERT INTO events (at, network_id, ip, type, severity, message, details, job_id, baseline)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			e.At, networkID, e.IP, e.Type, e.Severity, e.Message, string(details), e.JobID, e.Baseline)
	}
	batch.Queue(`UPDATE networks SET discovery_done_at = $2, portscan_done_at = $3, baseline_done = $4 WHERE id = $1`,
		networkID, n.DiscoveryDoneAt, n.PortscanDoneAt, n.BaselineDone)
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) SetHostImportant(ctx context.Context, networkID int64, ip string, important bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE hosts SET important = $3 WHERE network_id = $1 AND ip = $2`, networkID, ip, important)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) SetHostCustomName(ctx context.Context, networkID int64, ip, name string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE hosts SET custom_name = $3 WHERE network_id = $1 AND ip = $2`, networkID, ip, name)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) ListEvents(ctx context.Context, f store.EventFilter) ([]store.Event, error) {
	if f.Limit <= 0 {
		f.Limit = 1000
	}
	rows, err := s.pool.Query(ctx, `SELECT id, at, coalesce(network_id, 0), ip, type, severity, message, details::text, job_id, baseline
		FROM events
		WHERE ($1 = 0 OR network_id = $1) AND ($2 = '' OR ip = $2) AND ($3 OR NOT baseline)
		ORDER BY at DESC, id DESC LIMIT $4`, f.NetworkID, f.IP, f.IncludeBaseline, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Event
	for rows.Next() {
		var e store.Event
		var details string
		if err := rows.Scan(&e.ID, &e.At, &e.NetworkID, &e.IP, &e.Type, &e.Severity, &e.Message, &details, &e.JobID, &e.Baseline); err != nil {
			return nil, err
		}
		e.Details = []byte(details)
		out = append(out, e)
	}
	return out, rows.Err()
}

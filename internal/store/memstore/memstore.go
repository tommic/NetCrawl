// Package memstore is an in-memory store.Store for tests and local
// experiments. All data is lost when the process exits.
package memstore

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"netcrawler/internal/store"
)

type nonceKey struct{ crawler, nonce string }

type session struct {
	adminID int64
	expires time.Time
}

// Store is an in-memory store.Store. The zero value is not usable; use New.
type Store struct {
	mu       sync.Mutex
	admins   map[string]store.Admin
	nextID   int64
	sessions map[string]session
	crawlers map[string]store.Crawler
	nonces   map[nonceKey]time.Time
	jobs     map[string]store.Job
	results  map[string]store.Result
	audit    []store.AuditEntry
	networks map[int64]store.Network
	nextNet  int64
	hosts    map[int64]map[string]store.Host
	events   []store.Event
	enrolls  map[string]store.Enrollment
	notify   store.NotificationSettings
	notified map[int64]time.Time
}

// New returns an empty store.
func New() *Store {
	return &Store{
		admins:   map[string]store.Admin{},
		sessions: map[string]session{},
		crawlers: map[string]store.Crawler{},
		nonces:   map[nonceKey]time.Time{},
		jobs:     map[string]store.Job{},
		results:  map[string]store.Result{},
		networks: map[int64]store.Network{},
		hosts:    map[int64]map[string]store.Host{},
		enrolls:  map[string]store.Enrollment{},
		notified: map[int64]time.Time{},
	}
}

var _ store.Store = (*Store)(nil)

func (s *Store) Close() {}

func (s *Store) SetAdmin(_ context.Context, username, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[username]
	if !ok {
		s.nextID++
		a = store.Admin{ID: s.nextID, Username: username}
	}
	a.PasswordHash = hash
	s.admins[username] = a
	return nil
}

func (s *Store) AdminByUsername(_ context.Context, username string) (store.Admin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.admins[username]
	if !ok {
		return store.Admin{}, store.ErrNotFound
	}
	return a, nil
}

func (s *Store) CreateSession(_ context.Context, tokenHash []byte, adminID int64, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[string(tokenHash)] = session{adminID, expires}
	return nil
}

func (s *Store) SessionAdmin(_ context.Context, tokenHash []byte, now time.Time) (store.Admin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[string(tokenHash)]
	if !ok || !now.Before(sess.expires) {
		return store.Admin{}, store.ErrNotFound
	}
	for _, a := range s.admins {
		if a.ID == sess.adminID {
			return a, nil
		}
	}
	return store.Admin{}, store.ErrNotFound
}

func (s *Store) DeleteSession(_ context.Context, tokenHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, string(tokenHash))
	return nil
}

func (s *Store) CreateCrawler(_ context.Context, c store.Crawler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.crawlers[c.ID]; ok {
		return store.ErrExists
	}
	c.Secret = slices.Clone(c.Secret)
	c.Allow = slices.Clone(c.Allow)
	s.crawlers[c.ID] = c
	return nil
}

func (s *Store) Crawler(_ context.Context, id string) (store.Crawler, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.crawlers[id]
	if !ok {
		return store.Crawler{}, store.ErrNotFound
	}
	return c, nil
}

func (s *Store) ListCrawlers(_ context.Context) ([]store.Crawler, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.Crawler, 0, len(s.crawlers))
	for _, c := range s.crawlers {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) SetCrawlerEnabled(_ context.Context, id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.crawlers[id]
	if !ok {
		return store.ErrNotFound
	}
	c.Enabled = enabled
	s.crawlers[id] = c
	return nil
}

func (s *Store) TouchCrawler(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.crawlers[id]
	if !ok {
		return store.ErrNotFound
	}
	t := now
	c.LastSeenAt = &t
	s.crawlers[id] = c
	return nil
}

func (s *Store) UseNonce(_ context.Context, crawlerID, nonce string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.useNonceLocked(crawlerID, nonce, now)
}

func (s *Store) useNonceLocked(crawlerID, nonce string, now time.Time) error {
	k := nonceKey{crawlerID, nonce}
	if _, ok := s.nonces[k]; ok {
		return store.ErrReplay
	}
	s.nonces[k] = now
	return nil
}

func (s *Store) PurgeNonces(_ context.Context, before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, seen := range s.nonces {
		if seen.Before(before) {
			delete(s.nonces, k)
		}
	}
	return nil
}

func (s *Store) CreateJob(_ context.Context, j store.Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[j.ID]; ok {
		return store.ErrExists
	}
	if _, ok := s.crawlers[j.CrawlerID]; !ok {
		return store.ErrNotFound
	}
	if j.NetworkID != nil {
		if _, ok := s.networks[*j.NetworkID]; !ok {
			return store.ErrNotFound
		}
		id := *j.NetworkID
		j.NetworkID = &id
	}
	if j.Kind == "" {
		j.Kind = "ports"
	}
	j.Targets = slices.Clone(j.Targets)
	j.Deny = slices.Clone(j.Deny)
	j.Ports = slices.Clone(j.Ports)
	j.ResultToken = slices.Clone(j.ResultToken)
	s.jobs[j.ID] = j
	return nil
}

func (s *Store) Job(_ context.Context, id string) (store.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return store.Job{}, store.ErrNotFound
	}
	return j, nil
}

func (s *Store) ListJobs(_ context.Context, limit int) ([]store.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		out = append(out, j)
	}
	sort.Slice(out, func(i, k int) bool {
		if !out[i].CreatedAt.Equal(out[k].CreatedAt) {
			return out[i].CreatedAt.After(out[k].CreatedAt)
		}
		return out[i].ID > out[k].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) NextJob(_ context.Context, crawlerID string, now time.Time) (store.Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best *store.Job
	for _, j := range s.jobs {
		if j.CrawlerID != crawlerID || j.Status != store.JobPending || !now.Before(j.ExpiresAt) {
			continue
		}
		if best == nil || j.CreatedAt.Before(best.CreatedAt) || (j.CreatedAt.Equal(best.CreatedAt) && j.ID < best.ID) {
			jj := j
			best = &jj
		}
	}
	if best == nil {
		return store.Job{}, false, nil
	}
	t := now
	best.Status = store.JobDelivered
	best.DeliveredAt = &t
	s.jobs[best.ID] = *best
	return *best, true, nil
}

func (s *Store) SubmitResult(_ context.Context, sub store.Submission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[sub.JobID]
	if !ok {
		return store.ErrUnauthorized
	}
	if j.CrawlerID != sub.CrawlerID || j.Status == store.JobPending {
		return store.ErrForbidden
	}
	if !sub.Verify(j.ResultToken) {
		return store.ErrUnauthorized
	}
	if j.Status == store.JobCompleted {
		return store.ErrReplay
	}
	if _, used := s.nonces[nonceKey{sub.CrawlerID, sub.Nonce}]; used {
		return store.ErrReplay
	}
	if !sub.Now.Before(j.ExpiresAt) {
		return store.ErrExpired
	}
	if err := s.useNonceLocked(sub.CrawlerID, sub.Nonce, sub.Now); err != nil {
		return err
	}
	t := sub.Now
	j.Status = store.JobCompleted
	j.CompletedAt = &t
	s.jobs[j.ID] = j
	s.results[j.ID] = store.Result{
		JobID:      j.ID,
		CrawlerID:  j.CrawlerID,
		ReceivedAt: sub.Now,
		BodySHA256: slices.Clone(sub.BodySHA256),
		Body:       json.RawMessage(slices.Clone(sub.Body)),
	}
	return nil
}

func (s *Store) Result(_ context.Context, jobID string) (store.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[jobID]
	if !ok {
		return store.Result{}, store.ErrNotFound
	}
	return r, nil
}

func (s *Store) Audit(_ context.Context, actor, action string, details any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, store.AuditEntry{
		ID:      int64(len(s.audit) + 1),
		At:      time.Now().UTC(),
		Actor:   actor,
		Action:  action,
		Details: store.MarshalDetails(details),
	})
	return nil
}

func (s *Store) ListAudit(_ context.Context, limit int) ([]store.AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.AuditEntry, 0, len(s.audit))
	for i := len(s.audit) - 1; i >= 0; i-- {
		out = append(out, s.audit[i])
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out, nil
}

func cloneNetwork(n store.Network) store.Network {
	n.Targets = slices.Clone(n.Targets)
	n.Deny = slices.Clone(n.Deny)
	n.DiscoveryPorts = slices.Clone(n.DiscoveryPorts)
	n.ScanPorts = slices.Clone(n.ScanPorts)
	n.LastDiscoveryAt = cloneTime(n.LastDiscoveryAt)
	n.LastPortscanAt = cloneTime(n.LastPortscanAt)
	n.DiscoveryDoneAt = cloneTime(n.DiscoveryDoneAt)
	n.PortscanDoneAt = cloneTime(n.PortscanDoneAt)
	return n
}

func cloneHost(h store.Host) store.Host {
	h.Ports = slices.Clone(h.Ports)
	h.PortsScannedAt = cloneTime(h.PortsScannedAt)
	return h
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func (s *Store) CreateNetwork(_ context.Context, n store.Network) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.crawlers[n.CrawlerID]; !ok {
		return 0, store.ErrNotFound
	}
	for _, other := range s.networks {
		if other.Name == n.Name {
			return 0, store.ErrExists
		}
	}
	s.nextNet++
	n.ID = s.nextNet
	s.networks[n.ID] = cloneNetwork(n)
	return n.ID, nil
}

func (s *Store) Network(_ context.Context, id int64) (store.Network, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.networks[id]
	if !ok {
		return store.Network{}, store.ErrNotFound
	}
	return cloneNetwork(n), nil
}

func (s *Store) ListNetworks(_ context.Context) ([]store.Network, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.Network, 0, len(s.networks))
	for _, n := range s.networks {
		out = append(out, cloneNetwork(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) UpdateNetworkSettings(_ context.Context, n store.Network) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.networks[n.ID]
	if !ok {
		return store.ErrNotFound
	}
	for _, other := range s.networks {
		if other.ID != n.ID && other.Name == n.Name {
			return store.ErrExists
		}
	}
	cur.Name, cur.Targets, cur.Deny = n.Name, slices.Clone(n.Targets), slices.Clone(n.Deny)
	cur.DiscoveryPorts, cur.ScanPorts = slices.Clone(n.DiscoveryPorts), slices.Clone(n.ScanPorts)
	cur.DiscoveryInterval, cur.PortscanInterval = n.DiscoveryInterval, n.PortscanInterval
	cur.OfflineInfoAfter, cur.OfflineWarnAfter = n.OfflineInfoAfter, n.OfflineWarnAfter
	cur.ReverseDNS, cur.Enabled = n.ReverseDNS, n.Enabled
	s.networks[n.ID] = cur
	return nil
}

func (s *Store) UpdateNetworkSchedule(_ context.Context, id int64, lastDiscovery, lastPortscan *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.networks[id]
	if !ok {
		return store.ErrNotFound
	}
	n.LastDiscoveryAt, n.LastPortscanAt = cloneTime(lastDiscovery), cloneTime(lastPortscan)
	s.networks[id] = n
	return nil
}

func (s *Store) OpenNetworkJobs(_ context.Context, networkID int64, kind string, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, j := range s.jobs {
		if j.NetworkID != nil && *j.NetworkID == networkID && j.Kind == kind &&
			j.Status != store.JobCompleted && now.Before(j.ExpiresAt) {
			n++
		}
	}
	return n, nil
}

func (s *Store) UpdateInventory(_ context.Context, networkID int64, fn store.InventoryUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.networks[networkID]
	if !ok {
		return store.ErrNotFound
	}
	work := cloneNetwork(n)
	hosts := map[string]*store.Host{}
	for ip, h := range s.hosts[networkID] {
		c := cloneHost(h)
		hosts[ip] = &c
	}
	changed, events, err := fn(&work, hosts)
	if err != nil {
		return err
	}
	if s.hosts[networkID] == nil {
		s.hosts[networkID] = map[string]store.Host{}
	}
	for _, ip := range changed {
		h, ok := hosts[ip]
		if !ok {
			continue
		}
		c := cloneHost(*h)
		c.NetworkID, c.IP = networkID, ip
		sort.Slice(c.Ports, func(i, j int) bool { return c.Ports[i].Port < c.Ports[j].Port })
		s.hosts[networkID][ip] = c
	}
	for _, e := range events {
		e.ID = int64(len(s.events) + 1)
		e.NetworkID = networkID
		if e.Details == nil {
			e.Details = json.RawMessage("null")
		}
		s.events = append(s.events, e)
	}
	n.DiscoveryDoneAt = cloneTime(work.DiscoveryDoneAt)
	n.PortscanDoneAt = cloneTime(work.PortscanDoneAt)
	n.BaselineDone = work.BaselineDone
	s.networks[networkID] = n
	return nil
}

func (s *Store) Hosts(_ context.Context, networkID int64) ([]store.Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.Host
	for nid, hosts := range s.hosts {
		if networkID != 0 && nid != networkID {
			continue
		}
		for _, h := range hosts {
			out = append(out, cloneHost(h))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NetworkID != out[j].NetworkID {
			return out[i].NetworkID < out[j].NetworkID
		}
		return netip.MustParseAddr(out[i].IP).Less(netip.MustParseAddr(out[j].IP))
	})
	return out, nil
}

func (s *Store) SetHostImportant(_ context.Context, networkID int64, ip string, important bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[networkID][ip]
	if !ok {
		return store.ErrNotFound
	}
	h.Important = important
	s.hosts[networkID][ip] = h
	return nil
}

func (s *Store) ListEvents(_ context.Context, f store.EventFilter) ([]store.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.Event
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if (f.NetworkID != 0 && e.NetworkID != f.NetworkID) || (f.IP != "" && e.IP != f.IP) || (e.Baseline && !f.IncludeBaseline) {
			continue
		}
		out = append(out, e)
		if f.Limit > 0 && len(out) == f.Limit {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out, nil
}

func (s *Store) CreateEnrollment(_ context.Context, e store.Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.crawlers[e.CrawlerID]; !ok {
		return store.ErrNotFound
	}
	for k, old := range s.enrolls {
		if old.CrawlerID == e.CrawlerID && old.UsedAt == nil {
			delete(s.enrolls, k)
		}
	}
	e.TokenHash = slices.Clone(e.TokenHash)
	s.enrolls[string(e.TokenHash)] = e
	return nil
}

func (s *Store) Enrollment(_ context.Context, tokenHash []byte, now time.Time) (store.Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.enrolls[string(tokenHash)]
	if !ok || e.UsedAt != nil || !now.Before(e.ExpiresAt) {
		return store.Enrollment{}, store.ErrNotFound
	}
	return e, nil
}

func (s *Store) RedeemEnrollment(_ context.Context, tokenHash, newSecret []byte, now time.Time) (store.Crawler, store.Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.enrolls[string(tokenHash)]
	if !ok || e.UsedAt != nil || !now.Before(e.ExpiresAt) {
		return store.Crawler{}, store.Enrollment{}, store.ErrNotFound
	}
	c, ok := s.crawlers[e.CrawlerID]
	if !ok {
		return store.Crawler{}, store.Enrollment{}, store.ErrNotFound
	}
	if !c.Enabled {
		return store.Crawler{}, store.Enrollment{}, store.ErrForbidden
	}
	t := now
	e.UsedAt = &t
	s.enrolls[string(tokenHash)] = e
	c.Secret = slices.Clone(newSecret)
	s.crawlers[c.ID] = c
	return c, e, nil
}

func (s *Store) NotificationSettings(context.Context) (store.NotificationSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.notify, nil
}

func (s *Store) SaveNotificationSettings(_ context.Context, n store.NotificationSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n.LastSentAt, n.LastError = s.notify.LastSentAt, s.notify.LastError
	s.notify = n
	return nil
}

func (s *Store) RecordNotification(_ context.Context, sentAt *time.Time, lastError string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.notify.UpdatedAt.IsZero() {
		return nil
	}
	if sentAt != nil {
		t := *sentAt
		s.notify.LastSentAt = &t
	}
	s.notify.LastError = lastError
	return nil
}

func (s *Store) PendingEvents(_ context.Context, since time.Time, severities []string, limit int) ([]store.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	var out []store.Event
	for _, e := range s.events {
		if _, done := s.notified[e.ID]; done || e.Baseline || e.At.Before(since) || !slices.Contains(severities, e.Severity) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) MarkEventsNotified(_ context.Context, ids []int64, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		if _, ok := s.notified[id]; !ok {
			s.notified[id] = at
		}
	}
	return nil
}

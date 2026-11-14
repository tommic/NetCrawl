// Package memstore is an in-memory store.Store for tests and local
// experiments. All data is lost when the process exits.
package memstore

import (
	"context"
	"encoding/json"
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
	j.Targets = slices.Clone(j.Targets)
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

package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"netcrawler/internal/iprange"
	"netcrawler/internal/protocol"
	"netcrawler/internal/scope"
	"netcrawler/internal/store"
)

// Job limits enforced by the server.
const (
	DefaultJobTTL       = 5 * time.Minute
	MinJobTTL           = time.Minute
	MaxJobTTL           = time.Hour
	DefaultJobTimeoutMs = 500
	MaxJobTimeoutMs     = 10000
)

// ValidationError is a client error (HTTP 400).
type ValidationError struct{ Err error }

func (e ValidationError) Error() string { return e.Err.Error() }
func (e ValidationError) Unwrap() error { return e.Err }

func invalid(format string, args ...any) error {
	return ValidationError{fmt.Errorf(format, args...)}
}

// IsValidation reports whether err is a ValidationError.
func IsValidation(err error) bool {
	var v ValidationError
	return errors.As(err, &v)
}

// CrawlerRequest describes a new crawler.
type CrawlerRequest struct {
	ID       string   `json:"id"`
	Allow    []string `json:"allow"`
	MaxHosts int      `json:"max_hosts"`
}

// CreateCrawler registers a crawler and returns its secret. The secret is
// shown exactly once; the agent needs it in its secret file.
func CreateCrawler(ctx context.Context, st store.Store, actor string, req CrawlerRequest, now time.Time) (store.Crawler, string, error) {
	if !protocol.ValidCrawlerID(req.ID) {
		return store.Crawler{}, "", invalid("invalid crawler id %q (1-64 characters a-z, 0-9, '.', '_', '-', starting with a letter or digit)", req.ID)
	}
	if _, err := scope.ParseAllowlist(req.Allow); err != nil {
		return store.Crawler{}, "", invalid("allow: %v", err)
	}
	if req.MaxHosts < 1 {
		return store.Crawler{}, "", invalid("max_hosts must be at least 1")
	}
	if err := scope.CheckRelease(req.Allow, req.MaxHosts, false); err != nil {
		return store.Crawler{}, "", invalid("%v", err)
	}
	secret, err := protocol.NewKey()
	if err != nil {
		return store.Crawler{}, "", err
	}
	c := store.Crawler{ID: req.ID, Secret: secret, Allow: req.Allow, MaxHosts: req.MaxHosts, Enabled: true, CreatedAt: now.UTC()}
	if err := st.CreateCrawler(ctx, c); err != nil {
		if errors.Is(err, store.ErrExists) {
			return store.Crawler{}, "", invalid("crawler %q already exists", req.ID)
		}
		return store.Crawler{}, "", err
	}
	_ = st.Audit(ctx, actor, "crawler.create", map[string]any{"id": c.ID, "allow": c.Allow, "max_hosts": c.MaxHosts})
	return c, protocol.EncodeKey(secret), nil
}

// SetCrawlerEnabled enables or disables a crawler. A disabled crawler
// gets no jobs, its results are rejected and it cannot be installed.
func SetCrawlerEnabled(ctx context.Context, st store.Store, actor, id string, enabled bool) error {
	if err := st.SetCrawlerEnabled(ctx, id, enabled); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return invalid("unknown crawler %q", id)
		}
		return err
	}
	action := "crawler.disable"
	if enabled {
		action = "crawler.enable"
	}
	_ = st.Audit(ctx, actor, action, map[string]any{"id": id})
	return nil
}

// JobRequest describes a new job. Zero values get defaults: MaxHosts =
// the crawler's limit, TimeoutMs = 500, TTL = 5 minutes.
type JobRequest struct {
	CrawlerID  string   `json:"crawler_id"`
	Targets    []string `json:"targets"`
	Deny       []string `json:"deny"`
	Ports      []int    `json:"ports"`
	MaxHosts   int      `json:"max_hosts"`
	TimeoutMs  int      `json:"timeout_ms"`
	TTLSeconds int      `json:"ttl_seconds"`
	// Kind is "ports" (default) or "discovery".
	Kind       string `json:"kind"`
	ReverseDNS bool   `json:"reverse_dns"`
	// NetworkID links scheduler jobs to their network (not settable via API).
	NetworkID *int64 `json:"-"`
}

// CreateJob validates a job against the crawler's server-side allowlist and
// host limit and stores it.
func CreateJob(ctx context.Context, st store.Store, actor string, req JobRequest, now time.Time) (store.Job, error) {
	c, err := st.Crawler(ctx, req.CrawlerID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Job{}, invalid("unknown crawler %q", req.CrawlerID)
	}
	if err != nil {
		return store.Job{}, err
	}
	if !c.Enabled {
		return store.Job{}, invalid("crawler %q is disabled", c.ID)
	}
	if req.MaxHosts == 0 {
		req.MaxHosts = c.MaxHosts
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = DefaultJobTimeoutMs
	}
	if req.TimeoutMs < 1 || req.TimeoutMs > MaxJobTimeoutMs {
		return store.Job{}, invalid("timeout_ms must be between 1 and %d", MaxJobTimeoutMs)
	}
	ttl := DefaultJobTTL
	if req.TTLSeconds != 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl < MinJobTTL || ttl > MaxJobTTL {
		return store.Job{}, invalid("ttl must be between %s and %s", MinJobTTL, MaxJobTTL)
	}
	allow, err := scope.ParseAllowlist(c.Allow)
	if err != nil {
		return store.Job{}, err
	}
	if _, err := scope.Check(scope.Request{Targets: req.Targets, MaxHosts: req.MaxHosts, Ports: req.Ports}, allow, c.MaxHosts); err != nil {
		return store.Job{}, invalid("%v", err)
	}
	switch req.Kind {
	case "":
		req.Kind = protocol.JobKindPorts
	case protocol.JobKindPorts, protocol.JobKindDiscovery:
	default:
		return store.Job{}, invalid("kind must be %q or %q", protocol.JobKindPorts, protocol.JobKindDiscovery)
	}
	for _, d := range req.Deny {
		if _, err := iprange.Parse(d); err != nil {
			return store.Job{}, invalid("deny: %v", err)
		}
	}

	id, err := protocol.NewID()
	if err != nil {
		return store.Job{}, err
	}
	token, err := protocol.NewKey()
	if err != nil {
		return store.Job{}, err
	}
	now = now.UTC()
	j := store.Job{
		ID: id, CrawlerID: c.ID, Targets: req.Targets, Deny: req.Deny, Ports: req.Ports, MaxHosts: req.MaxHosts,
		Kind: req.Kind, ReverseDNS: req.ReverseDNS, NetworkID: req.NetworkID,
		TimeoutMs: req.TimeoutMs, ResultToken: token, Status: store.JobPending, CreatedBy: actor,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	if err := st.CreateJob(ctx, j); err != nil {
		return store.Job{}, err
	}
	_ = st.Audit(ctx, actor, "job.create", map[string]any{
		"job_id": j.ID, "crawler_id": j.CrawlerID, "kind": j.Kind, "targets": j.Targets, "deny": j.Deny, "ports": j.Ports,
		"max_hosts": j.MaxHosts, "expires_at": j.ExpiresAt,
	})
	return j, nil
}

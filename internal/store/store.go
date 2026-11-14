// Package store defines the persistence interface of netcrawl-server.
// pgstore implements it with PostgreSQL; memstore keeps everything in
// memory for tests. Both must behave identically; storetest holds the
// shared conformance tests.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Errors returned by Store implementations.
var (
	ErrNotFound     = errors.New("not found")
	ErrExists       = errors.New("already exists")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrReplay       = errors.New("replay")
	ErrExpired      = errors.New("expired")
)

// Admin is a user of the admin API.
type Admin struct {
	ID           int64
	Username     string
	PasswordHash string
}

// Crawler is a registered agent.
type Crawler struct {
	ID string
	// Secret is the HMAC key for job polls.
	Secret []byte
	// Allow is the server-side allowlist for jobs of this crawler.
	Allow      []string
	MaxHosts   int
	Enabled    bool
	CreatedAt  time.Time
	LastSeenAt *time.Time
}

// Job states.
const (
	JobPending   = "pending"
	JobDelivered = "delivered"
	JobCompleted = "completed"
)

// Job is a scan order for one crawler.
type Job struct {
	ID          string
	CrawlerID   string
	Targets     []string
	Ports       []int
	MaxHosts    int
	TimeoutMs   int
	ResultToken []byte
	Status      string
	CreatedBy   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	DeliveredAt *time.Time
	CompletedAt *time.Time
}

// Result is an accepted job result.
type Result struct {
	JobID      string
	CrawlerID  string
	ReceivedAt time.Time
	BodySHA256 []byte
	Body       json.RawMessage
}

// Submission is a signed result submission. Store.SubmitResult checks and
// records it atomically.
type Submission struct {
	CrawlerID string
	JobID     string
	Nonce     string
	Now       time.Time
	// Verify reports whether the request signature is valid for the job's
	// result token.
	Verify     func(resultToken []byte) bool
	Body       []byte
	BodySHA256 []byte
}

// AuditEntry records an administrative or security-relevant action.
type AuditEntry struct {
	ID      int64
	At      time.Time
	Actor   string
	Action  string
	Details json.RawMessage
}

// Store is the persistence interface of the server.
type Store interface {
	// SetAdmin creates the admin or replaces its password hash.
	SetAdmin(ctx context.Context, username, passwordHash string) error
	AdminByUsername(ctx context.Context, username string) (Admin, error)
	CreateSession(ctx context.Context, tokenHash []byte, adminID int64, expires time.Time) error
	// SessionAdmin returns the admin of an unexpired session.
	SessionAdmin(ctx context.Context, tokenHash []byte, now time.Time) (Admin, error)
	DeleteSession(ctx context.Context, tokenHash []byte) error

	CreateCrawler(ctx context.Context, c Crawler) error
	Crawler(ctx context.Context, id string) (Crawler, error)
	ListCrawlers(ctx context.Context) ([]Crawler, error)
	TouchCrawler(ctx context.Context, id string, now time.Time) error

	// UseNonce records a nonce; ErrReplay if the crawler used it before.
	UseNonce(ctx context.Context, crawlerID, nonce string, now time.Time) error
	// PurgeNonces deletes nonces seen before the given time.
	PurgeNonces(ctx context.Context, before time.Time) error

	CreateJob(ctx context.Context, j Job) error
	Job(ctx context.Context, id string) (Job, error)
	ListJobs(ctx context.Context, limit int) ([]Job, error)
	// NextJob hands out the oldest pending, unexpired job of a crawler and
	// marks it delivered. ok is false if there is none.
	NextJob(ctx context.Context, crawlerID string, now time.Time) (j Job, ok bool, err error)

	// SubmitResult atomically checks a submission and stores the result.
	// Checks, in order: job exists (else ErrUnauthorized), belongs to the
	// crawler and was delivered (else ErrForbidden), signature valid
	// (ErrUnauthorized), no result yet and nonce unused (ErrReplay), job
	// not expired (ErrExpired).
	SubmitResult(ctx context.Context, s Submission) error
	Result(ctx context.Context, jobID string) (Result, error)

	Audit(ctx context.Context, actor, action string, details any) error
	ListAudit(ctx context.Context, limit int) ([]AuditEntry, error)

	Close()
}

// MarshalDetails encodes audit details, falling back to null.
func MarshalDetails(details any) json.RawMessage {
	if details == nil {
		return json.RawMessage("null")
	}
	b, err := json.Marshal(details)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

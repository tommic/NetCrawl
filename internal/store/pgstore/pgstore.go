// Package pgstore implements store.Store with PostgreSQL.
package pgstore

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"netcrawler/internal/store"
)

//go:embed migrations/*.sql
var migrations embed.FS

// migrationLockID serializes concurrent migrations (pg_advisory_xact_lock).
const migrationLockID = 0x6e6574637277 // "netcrw"

// Store is a PostgreSQL-backed store.Store.
type Store struct {
	pool *pgxpool.Pool
}

var _ store.Store = (*Store)(nil)

// Open connects to PostgreSQL. It does not run migrations; call Migrate.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect database: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Migrate applies all pending migrations, each in its own transaction.
// It returns the versions applied.
func (s *Store) Migrate(ctx context.Context) ([]int, error) {
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return nil, err
	}
	type migration struct {
		version int
		name    string
	}
	var all []migration
	for _, e := range entries {
		prefix, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(prefix)
		if !ok || err != nil {
			return nil, fmt.Errorf("invalid migration file name %q", e.Name())
		}
		all = append(all, migration{v, e.Name()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].version < all[j].version })

	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}
	var applied []int
	for _, m := range all {
		done, err := s.applyMigration(ctx, m.version, m.name)
		if err != nil {
			return applied, err
		}
		if done {
			applied = append(applied, m.version)
		}
	}
	return applied, nil
}

func (s *Store) applyMigration(ctx context.Context, version int, name string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
		return false, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	sql, err := migrations.ReadFile("migrations/" + name)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, string(sql)); err != nil {
		return false, fmt.Errorf("migration %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) SetAdmin(ctx context.Context, username, hash string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)
		ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`, username, hash)
	return err
}

func (s *Store) AdminByUsername(ctx context.Context, username string) (store.Admin, error) {
	var a store.Admin
	err := s.pool.QueryRow(ctx, `SELECT id, username, password_hash FROM admin_users WHERE username = $1`, username).
		Scan(&a.ID, &a.Username, &a.PasswordHash)
	return a, notFound(err)
}

func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, adminID int64, expires time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO admin_sessions (token_hash, admin_id, expires_at) VALUES ($1, $2, $3)`,
		tokenHash, adminID, expires)
	return err
}

func (s *Store) SessionAdmin(ctx context.Context, tokenHash []byte, now time.Time) (store.Admin, error) {
	var a store.Admin
	err := s.pool.QueryRow(ctx, `SELECT u.id, u.username, u.password_hash
		FROM admin_sessions s JOIN admin_users u ON u.id = s.admin_id
		WHERE s.token_hash = $1 AND s.expires_at > $2`, tokenHash, now).
		Scan(&a.ID, &a.Username, &a.PasswordHash)
	return a, notFound(err)
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (s *Store) CreateCrawler(ctx context.Context, c store.Crawler) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO crawlers (id, secret, allow, max_hosts, enabled, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, c.ID, c.Secret, c.Allow, c.MaxHosts, c.Enabled, c.CreatedAt)
	if isUniqueViolation(err) {
		return store.ErrExists
	}
	return err
}

const crawlerColumns = `id, secret, allow, max_hosts, enabled, created_at, last_seen_at`

func scanCrawler(row pgx.Row) (store.Crawler, error) {
	var c store.Crawler
	err := row.Scan(&c.ID, &c.Secret, &c.Allow, &c.MaxHosts, &c.Enabled, &c.CreatedAt, &c.LastSeenAt)
	return c, err
}

func (s *Store) Crawler(ctx context.Context, id string) (store.Crawler, error) {
	c, err := scanCrawler(s.pool.QueryRow(ctx, `SELECT `+crawlerColumns+` FROM crawlers WHERE id = $1`, id))
	return c, notFound(err)
}

func (s *Store) ListCrawlers(ctx context.Context) ([]store.Crawler, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+crawlerColumns+` FROM crawlers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Crawler
	for rows.Next() {
		c, err := scanCrawler(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) SetCrawlerEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE crawlers SET enabled = $2 WHERE id = $1`, id, enabled)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) TouchCrawler(ctx context.Context, id string, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE crawlers SET last_seen_at = $2 WHERE id = $1`, id, now)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func useNonce(ctx context.Context, db execer, crawlerID, nonce string, now time.Time) error {
	_, err := db.Exec(ctx, `INSERT INTO crawler_nonces (crawler_id, nonce, seen_at) VALUES ($1, $2, $3)`, crawlerID, nonce, now)
	if isUniqueViolation(err) {
		return store.ErrReplay
	}
	if isForeignKeyViolation(err) {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) UseNonce(ctx context.Context, crawlerID, nonce string, now time.Time) error {
	return useNonce(ctx, s.pool, crawlerID, nonce, now)
}

func (s *Store) PurgeNonces(ctx context.Context, before time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM crawler_nonces WHERE seen_at < $1`, before)
	return err
}

func (s *Store) CreateJob(ctx context.Context, j store.Job) error {
	if j.Kind == "" {
		j.Kind = "ports"
	}
	if j.Deny == nil {
		j.Deny = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO jobs
		(id, crawler_id, targets, ports, max_hosts, timeout_ms, result_token, status, created_by, created_at, expires_at,
		 network_id, kind, deny, reverse_dns)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		j.ID, j.CrawlerID, j.Targets, j.Ports, j.MaxHosts, j.TimeoutMs, j.ResultToken, j.Status, j.CreatedBy, j.CreatedAt, j.ExpiresAt,
		j.NetworkID, j.Kind, j.Deny, j.ReverseDNS)
	switch {
	case isUniqueViolation(err):
		return store.ErrExists
	case isForeignKeyViolation(err):
		return store.ErrNotFound
	}
	return err
}

const jobColumns = `id::text, crawler_id, targets, ports, max_hosts, timeout_ms, result_token, status, created_by,
	created_at, expires_at, delivered_at, completed_at, network_id, kind, deny, reverse_dns`

func scanJob(row pgx.Row) (store.Job, error) {
	var j store.Job
	var ports []int32
	err := row.Scan(&j.ID, &j.CrawlerID, &j.Targets, &ports, &j.MaxHosts, &j.TimeoutMs, &j.ResultToken, &j.Status,
		&j.CreatedBy, &j.CreatedAt, &j.ExpiresAt, &j.DeliveredAt, &j.CompletedAt, &j.NetworkID, &j.Kind, &j.Deny, &j.ReverseDNS)
	for _, p := range ports {
		j.Ports = append(j.Ports, int(p))
	}
	return j, err
}

func (s *Store) Job(ctx context.Context, id string) (store.Job, error) {
	j, err := scanJob(s.pool.QueryRow(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id::text = $1`, id))
	return j, notFound(err)
}

func (s *Store) ListJobs(ctx context.Context, limit int) ([]store.Job, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `SELECT `+jobColumns+` FROM jobs ORDER BY created_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) NextJob(ctx context.Context, crawlerID string, now time.Time) (store.Job, bool, error) {
	j, err := scanJob(s.pool.QueryRow(ctx, `UPDATE jobs SET status = 'delivered', delivered_at = $2
		WHERE id = (
			SELECT id FROM jobs
			WHERE crawler_id = $1 AND status = 'pending' AND expires_at > $2
			ORDER BY created_at, id
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+jobColumns, crawlerID, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Job{}, false, nil
	}
	if err != nil {
		return store.Job{}, false, err
	}
	return j, true, nil
}

func (s *Store) SubmitResult(ctx context.Context, sub store.Submission) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	j, err := scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id::text = $1 FOR UPDATE`, sub.JobID))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrUnauthorized
	}
	if err != nil {
		return err
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
	var used bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM crawler_nonces WHERE crawler_id = $1 AND nonce = $2)`,
		sub.CrawlerID, sub.Nonce).Scan(&used); err != nil {
		return err
	}
	if used {
		return store.ErrReplay
	}
	if !sub.Now.Before(j.ExpiresAt) {
		return store.ErrExpired
	}
	if err := useNonce(ctx, tx, sub.CrawlerID, sub.Nonce, sub.Now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status = 'completed', completed_at = $2 WHERE id = $1::uuid`, j.ID, sub.Now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO job_results (job_id, crawler_id, received_at, body_sha256, body)
		VALUES ($1::uuid, $2, $3, $4, $5)`, j.ID, j.CrawlerID, sub.Now, sub.BodySHA256, string(sub.Body)); err != nil {
		if isUniqueViolation(err) {
			return store.ErrReplay
		}
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) Result(ctx context.Context, jobID string) (store.Result, error) {
	var r store.Result
	var body string
	err := s.pool.QueryRow(ctx, `SELECT job_id::text, crawler_id, received_at, body_sha256, body::text
		FROM job_results WHERE job_id::text = $1`, jobID).
		Scan(&r.JobID, &r.CrawlerID, &r.ReceivedAt, &r.BodySHA256, &body)
	r.Body = []byte(body)
	return r, notFound(err)
}

func (s *Store) Audit(ctx context.Context, actor, action string, details any) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_log (actor, action, details) VALUES ($1, $2, $3)`,
		actor, action, string(store.MarshalDetails(details)))
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]store.AuditEntry, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `SELECT id, at, actor, action, details::text FROM audit_log ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.AuditEntry
	for rows.Next() {
		var e store.AuditEntry
		var details string
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &details); err != nil {
			return nil, err
		}
		e.Details = []byte(details)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Reset drops all data. Only for tests.
func (s *Store) Reset(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `TRUNCATE admin_sessions, admin_users, crawler_nonces, job_results, jobs, crawlers, audit_log,
		events, host_ports, hosts, networks RESTART IDENTITY CASCADE`)
	return err
}

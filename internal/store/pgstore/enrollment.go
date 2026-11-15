package pgstore

import (
	"context"
	"time"

	"netcrawler/internal/store"
)

func (s *Store) CreateEnrollment(ctx context.Context, e store.Enrollment) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM enrollments WHERE crawler_id = $1 AND used_at IS NULL`, e.CrawlerID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO enrollments (token_hash, crawler_id, reverse_dns, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`, e.TokenHash, e.CrawlerID, e.ReverseDNS, e.CreatedAt, e.ExpiresAt)
	if isForeignKeyViolation(err) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const enrollmentColumns = `token_hash, crawler_id, reverse_dns, created_at, expires_at, used_at`

func (s *Store) Enrollment(ctx context.Context, tokenHash []byte, now time.Time) (store.Enrollment, error) {
	var e store.Enrollment
	err := s.pool.QueryRow(ctx, `SELECT `+enrollmentColumns+` FROM enrollments
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2`, tokenHash, now).
		Scan(&e.TokenHash, &e.CrawlerID, &e.ReverseDNS, &e.CreatedAt, &e.ExpiresAt, &e.UsedAt)
	return e, notFound(err)
}

func (s *Store) RedeemEnrollment(ctx context.Context, tokenHash, newSecret []byte, now time.Time) (store.Crawler, store.Enrollment, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.Crawler{}, store.Enrollment{}, err
	}
	defer tx.Rollback(ctx)
	var e store.Enrollment
	err = tx.QueryRow(ctx, `SELECT `+enrollmentColumns+` FROM enrollments
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2 FOR UPDATE`, tokenHash, now).
		Scan(&e.TokenHash, &e.CrawlerID, &e.ReverseDNS, &e.CreatedAt, &e.ExpiresAt, &e.UsedAt)
	if err != nil {
		return store.Crawler{}, store.Enrollment{}, notFound(err)
	}
	c, err := scanCrawler(tx.QueryRow(ctx, `SELECT `+crawlerColumns+` FROM crawlers WHERE id = $1 FOR UPDATE`, e.CrawlerID))
	if err != nil {
		return store.Crawler{}, store.Enrollment{}, notFound(err)
	}
	if !c.Enabled {
		return store.Crawler{}, store.Enrollment{}, store.ErrForbidden
	}
	if _, err := tx.Exec(ctx, `UPDATE enrollments SET used_at = $2 WHERE token_hash = $1`, tokenHash, now); err != nil {
		return store.Crawler{}, store.Enrollment{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE crawlers SET secret = $2, reinstall_required = false WHERE id = $1`, c.ID, newSecret); err != nil {
		return store.Crawler{}, store.Enrollment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.Crawler{}, store.Enrollment{}, err
	}
	t := now
	e.UsedAt = &t
	c.Secret = newSecret
	c.ReinstallRequired = false
	return c, e, nil
}

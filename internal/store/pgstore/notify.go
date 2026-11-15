package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"netcrawler/internal/store"
)

func (s *Store) NotificationSettings(ctx context.Context) (store.NotificationSettings, error) {
	var n store.NotificationSettings
	err := s.pool.QueryRow(ctx, `SELECT discord_url, min_severity, enabled, since, updated_at, last_sent_at, last_error
		FROM notification_settings WHERE id = 1`).
		Scan(&n.DiscordURL, &n.MinSeverity, &n.Enabled, &n.Since, &n.UpdatedAt, &n.LastSentAt, &n.LastError)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.NotificationSettings{}, nil
	}
	return n, err
}

func (s *Store) SaveNotificationSettings(ctx context.Context, n store.NotificationSettings) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO notification_settings (id, discord_url, min_severity, enabled, since, updated_at)
		VALUES (1, $1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE SET discord_url = $1, min_severity = $2, enabled = $3, since = $4, updated_at = $5`,
		n.DiscordURL, n.MinSeverity, n.Enabled, n.Since, n.UpdatedAt)
	return err
}

func (s *Store) RecordNotification(ctx context.Context, sentAt *time.Time, lastError string) error {
	_, err := s.pool.Exec(ctx, `UPDATE notification_settings
		SET last_sent_at = coalesce($1, last_sent_at), last_error = $2 WHERE id = 1`, sentAt, lastError)
	return err
}

func (s *Store) PendingEvents(ctx context.Context, since time.Time, severities []string, limit int) ([]store.Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT id, at, coalesce(network_id, 0), ip, type, severity, message, details::text, job_id, baseline
		FROM events
		WHERE notified_at IS NULL AND NOT baseline AND at >= $1 AND severity = ANY($2)
		ORDER BY at, id LIMIT $3`, since, severities, limit)
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

func (s *Store) MarkEventsNotified(ctx context.Context, ids []int64, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE events SET notified_at = $2 WHERE id = ANY($1) AND notified_at IS NULL`, ids, at)
	return err
}

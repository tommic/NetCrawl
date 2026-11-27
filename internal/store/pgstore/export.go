package pgstore

import (
	"context"
	"time"

	"netcrawler/internal/store"
)

func (s *Store) CreateExportToken(ctx context.Context, t store.ExportToken) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO export_tokens (name, token_hash, created_by, created_at)
		VALUES ($1, $2, $3, $4) RETURNING id`, t.Name, t.TokenHash, t.CreatedBy, t.CreatedAt).Scan(&id)
	if isUniqueViolation(err) {
		return 0, store.ErrExists
	}
	return id, err
}

const exportTokenColumns = `id, name, token_hash, created_by, created_at, last_used_at`

func (s *Store) ListExportTokens(ctx context.Context) ([]store.ExportToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+exportTokenColumns+` FROM export_tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.ExportToken
	for rows.Next() {
		var t store.ExportToken
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenHash, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) UseExportToken(ctx context.Context, tokenHash []byte, now time.Time) (store.ExportToken, error) {
	var t store.ExportToken
	err := s.pool.QueryRow(ctx, `UPDATE export_tokens SET last_used_at = $2 WHERE token_hash = $1
		RETURNING `+exportTokenColumns, tokenHash, now).
		Scan(&t.ID, &t.Name, &t.TokenHash, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt)
	return t, notFound(err)
}

func (s *Store) DeleteExportToken(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM export_tokens WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

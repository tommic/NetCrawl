-- One-time codes for the crawler installer (M3). Only a SHA-256 of the
-- code is stored.
CREATE TABLE enrollments (
    token_hash  BYTEA       PRIMARY KEY,
    crawler_id  TEXT        NOT NULL REFERENCES crawlers (id) ON DELETE CASCADE,
    reverse_dns BOOLEAN     NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ
);
CREATE INDEX enrollments_crawler ON enrollments (crawler_id);

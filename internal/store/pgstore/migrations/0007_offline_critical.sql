-- Important hosts get their own, short threshold for a critical event
-- (before: critical only after the warning threshold, default 7 days).
ALTER TABLE networks ADD COLUMN offline_critical_s INTEGER NOT NULL DEFAULT 3600 CHECK (offline_critical_s > 0);

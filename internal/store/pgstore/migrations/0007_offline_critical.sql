-- Important hosts get their own, short threshold for a critical event
-- (before: critical only after the warning threshold, default 7 days).
ALTER TABLE networks ADD COLUMN offline_critical_s INTEGER NOT NULL DEFAULT 3600 CHECK (offline_critical_s > 0);
-- It must be longer than the discovery interval (one missed run is no alarm).
UPDATE networks SET offline_critical_s = 2 * discovery_interval_s WHERE offline_critical_s <= discovery_interval_s;

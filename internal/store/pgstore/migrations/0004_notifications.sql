-- M4: change notifications (Discord webhook). The events table doubles as
-- outbox: notified_at is set once an event was delivered.
CREATE TABLE notification_settings (
    id           INTEGER     PRIMARY KEY CHECK (id = 1),
    discord_url  TEXT        NOT NULL DEFAULT '',
    min_severity TEXT        NOT NULL DEFAULT 'warning' CHECK (min_severity IN ('info', 'warning', 'critical')),
    enabled      BOOLEAN     NOT NULL DEFAULT false,
    since        TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL,
    last_sent_at TIMESTAMPTZ,
    last_error   TEXT        NOT NULL DEFAULT ''
);

ALTER TABLE events ADD COLUMN notified_at TIMESTAMPTZ;
CREATE INDEX events_pending ON events (at, id) WHERE notified_at IS NULL AND NOT baseline;

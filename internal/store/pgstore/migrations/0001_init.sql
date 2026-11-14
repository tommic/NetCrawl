-- Initial schema for netcrawl-server (M1).

CREATE TABLE admin_users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Only a SHA-256 of the session token is stored.
CREATE TABLE admin_sessions (
    token_hash BYTEA       PRIMARY KEY,
    admin_id   BIGINT      NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE crawlers (
    id           TEXT        PRIMARY KEY,
    secret       BYTEA       NOT NULL,
    allow        TEXT[]      NOT NULL,
    max_hosts    INTEGER     NOT NULL CHECK (max_hosts > 0),
    enabled      BOOLEAN     NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ
);

CREATE TABLE crawler_nonces (
    crawler_id TEXT        NOT NULL REFERENCES crawlers (id) ON DELETE CASCADE,
    nonce      TEXT        NOT NULL,
    seen_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (crawler_id, nonce)
);
CREATE INDEX crawler_nonces_seen_at ON crawler_nonces (seen_at);

CREATE TABLE jobs (
    id           UUID        PRIMARY KEY,
    crawler_id   TEXT        NOT NULL REFERENCES crawlers (id),
    targets      TEXT[]      NOT NULL,
    ports        INTEGER[]   NOT NULL,
    max_hosts    INTEGER     NOT NULL CHECK (max_hosts > 0),
    timeout_ms   INTEGER     NOT NULL CHECK (timeout_ms > 0),
    result_token BYTEA       NOT NULL,
    status       TEXT        NOT NULL CHECK (status IN ('pending', 'delivered', 'completed')),
    created_by   TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);
CREATE INDEX jobs_next ON jobs (crawler_id, status, created_at);

CREATE TABLE job_results (
    job_id      UUID        PRIMARY KEY REFERENCES jobs (id),
    crawler_id  TEXT        NOT NULL REFERENCES crawlers (id),
    received_at TIMESTAMPTZ NOT NULL,
    body_sha256 BYTEA       NOT NULL,
    body        JSONB       NOT NULL
);

CREATE TABLE audit_log (
    id      BIGSERIAL   PRIMARY KEY,
    at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor   TEXT        NOT NULL,
    action  TEXT        NOT NULL,
    details JSONB       NOT NULL DEFAULT 'null'
);

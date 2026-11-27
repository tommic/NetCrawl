-- Read tokens for the inventory export (e.g. for an AI agent).
CREATE TABLE export_tokens (
    id           BIGSERIAL   PRIMARY KEY,
    name         TEXT        NOT NULL,
    token_hash   BYTEA       NOT NULL UNIQUE,
    created_by   TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);

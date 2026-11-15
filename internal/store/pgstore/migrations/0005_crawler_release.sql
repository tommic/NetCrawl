-- Editable crawler release: a changed release needs a reinstall of the
-- crawler (its local limits are fixed at install time).
ALTER TABLE crawlers ADD COLUMN reinstall_required BOOLEAN NOT NULL DEFAULT false;

-- Server settings changed in the web UI (e.g. the public URL).
CREATE TABLE server_settings (
    key        TEXT        PRIMARY KEY,
    value      TEXT        NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

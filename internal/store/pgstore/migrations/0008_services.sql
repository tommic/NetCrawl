-- Service and version behind each open port (OwnDo #207).
ALTER TABLE host_ports
    ADD COLUMN service         TEXT NOT NULL DEFAULT '',
    ADD COLUMN product         TEXT NOT NULL DEFAULT '',
    ADD COLUMN version         TEXT NOT NULL DEFAULT '',
    ADD COLUMN extra           TEXT NOT NULL DEFAULT '',
    ADD COLUMN service_method  TEXT NOT NULL DEFAULT '',
    ADD COLUMN service_seen_at TIMESTAMPTZ;

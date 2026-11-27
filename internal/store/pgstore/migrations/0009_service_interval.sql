-- Service detection runs on its own, longer schedule than the port scan.
ALTER TABLE networks
    ADD COLUMN service_interval_s INTEGER NOT NULL DEFAULT 86400 CHECK (service_interval_s > 0),
    ADD COLUMN last_services_at   TIMESTAMPTZ;
ALTER TABLE jobs ADD COLUMN services BOOLEAN NOT NULL DEFAULT false;

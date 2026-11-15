-- M2: networks, inventory (hosts and open ports) and change events.

CREATE TABLE networks (
    id                   BIGSERIAL   PRIMARY KEY,
    crawler_id           TEXT        NOT NULL REFERENCES crawlers (id),
    name                 TEXT        NOT NULL UNIQUE,
    targets              TEXT[]      NOT NULL,
    deny                 TEXT[]      NOT NULL DEFAULT '{}',
    discovery_ports      INTEGER[]   NOT NULL,
    scan_ports           INTEGER[]   NOT NULL,
    discovery_interval_s INTEGER     NOT NULL CHECK (discovery_interval_s > 0),
    portscan_interval_s  INTEGER     NOT NULL CHECK (portscan_interval_s > 0),
    offline_info_s       INTEGER     NOT NULL CHECK (offline_info_s > 0),
    offline_warn_s       INTEGER     NOT NULL CHECK (offline_warn_s > 0),
    reverse_dns          BOOLEAN     NOT NULL DEFAULT false,
    enabled              BOOLEAN     NOT NULL DEFAULT true,
    created_at           TIMESTAMPTZ NOT NULL,
    -- When the scheduler last created a job of each kind.
    last_discovery_at    TIMESTAMPTZ,
    last_portscan_at     TIMESTAMPTZ,
    -- When a result of each kind was last applied to the inventory.
    discovery_done_at    TIMESTAMPTZ,
    portscan_done_at     TIMESTAMPTZ,
    baseline_done        BOOLEAN     NOT NULL DEFAULT false
);

ALTER TABLE jobs
    ADD COLUMN network_id  BIGINT  REFERENCES networks (id) ON DELETE SET NULL,
    ADD COLUMN kind        TEXT    NOT NULL DEFAULT 'ports' CHECK (kind IN ('ports', 'discovery')),
    ADD COLUMN deny        TEXT[]  NOT NULL DEFAULT '{}',
    ADD COLUMN reverse_dns BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX jobs_network ON jobs (network_id, kind, status);

CREATE TABLE hosts (
    network_id       BIGINT      NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    ip               TEXT        NOT NULL,
    hostname         TEXT        NOT NULL DEFAULT '',
    first_seen       TIMESTAMPTZ NOT NULL,
    last_seen        TIMESTAMPTZ NOT NULL,
    important        BOOLEAN     NOT NULL DEFAULT false,
    offline_level    TEXT        NOT NULL DEFAULT '' CHECK (offline_level IN ('', 'info', 'warning', 'critical')),
    ports_scanned_at TIMESTAMPTZ,
    PRIMARY KEY (network_id, ip)
);

-- Currently open ports (the port baseline). Closed ports are removed and
-- recorded as events.
CREATE TABLE host_ports (
    network_id BIGINT      NOT NULL,
    ip         TEXT        NOT NULL,
    port       INTEGER     NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (network_id, ip, port),
    FOREIGN KEY (network_id, ip) REFERENCES hosts (network_id, ip) ON DELETE CASCADE
);

CREATE TABLE events (
    id         BIGSERIAL   PRIMARY KEY,
    at         TIMESTAMPTZ NOT NULL,
    network_id BIGINT      REFERENCES networks (id) ON DELETE CASCADE,
    ip         TEXT        NOT NULL DEFAULT '',
    type       TEXT        NOT NULL,
    severity   TEXT        NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    message    TEXT        NOT NULL,
    details    JSONB       NOT NULL DEFAULT 'null',
    job_id     TEXT        NOT NULL DEFAULT '',
    baseline   BOOLEAN     NOT NULL DEFAULT false
);
CREATE INDEX events_at ON events (at DESC, id DESC);
CREATE INDEX events_network ON events (network_id, at DESC);

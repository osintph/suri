-- Suri findings store schema, version 1.
-- Applied by migrations.go on first open. All tables use IF NOT EXISTS so
-- the SQL is safe to re-run during tests and forward-migration paths.

CREATE TABLE IF NOT EXISTS scope_snapshots (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    content_hash     TEXT    NOT NULL UNIQUE,  -- hex SHA-256 of TOML bytes
    content          TEXT    NOT NULL,
    engagement_name  TEXT,
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS scans (
    id                  TEXT    PRIMARY KEY,
    start_time          TEXT    NOT NULL,
    end_time            TEXT,                  -- NULL until FinalizeScan is called
    scope_file_path     TEXT    NOT NULL,
    scope_snapshot_id   INTEGER NOT NULL REFERENCES scope_snapshots(id),
    seed_urls           TEXT    NOT NULL,      -- JSON array
    suri_version        TEXT    NOT NULL,
    exit_status         INTEGER,               -- NULL until FinalizeScan is called
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS evidence (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           TEXT    NOT NULL REFERENCES scans(id),
    request_bytes     BLOB,
    response_bytes    BLOB,
    response_status   INTEGER,
    response_headers  TEXT,                    -- JSON object
    response_time_ms  INTEGER,
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_scan_id ON evidence(scan_id);

CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             TEXT    NOT NULL REFERENCES scans(id),
    first_seen_scan_id  TEXT    NOT NULL REFERENCES scans(id),
    check_id            TEXT    NOT NULL,
    severity            TEXT    NOT NULL,
    title               TEXT    NOT NULL,
    description         TEXT,
    url                 TEXT    NOT NULL,
    parameter           TEXT,
    cwe                 TEXT,
    owasp               TEXT,
    confidence          TEXT    NOT NULL,
    evidence_id         INTEGER REFERENCES evidence(id),
    -- SHA-256(check_id | "|" | url | "|" | parameter) computed at insert.
    -- The diff engine uses this to match a finding across scans.
    identity_hash       TEXT    NOT NULL,
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id       ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_identity_hash ON findings(identity_hash);
CREATE INDEX IF NOT EXISTS idx_findings_severity      ON findings(severity);

CREATE TABLE IF NOT EXISTS urls_discovered (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT    NOT NULL REFERENCES scans(id),
    url             TEXT    NOT NULL,
    source          TEXT    NOT NULL,
    depth           INTEGER NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_urls_scan_id ON urls_discovered(scan_id);

CREATE TABLE IF NOT EXISTS forms_discovered (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT    NOT NULL REFERENCES scans(id),
    page_url    TEXT    NOT NULL,
    action      TEXT,
    method      TEXT    NOT NULL,
    fields      TEXT    NOT NULL,  -- JSON array of field name strings
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_forms_scan_id ON forms_discovered(scan_id);

CREATE TABLE IF NOT EXISTS parameters_discovered (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT    NOT NULL REFERENCES scans(id),
    page_url    TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_params_scan_id ON parameters_discovered(scan_id);

CREATE TABLE IF NOT EXISTS js_artifacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT    NOT NULL REFERENCES scans(id),
    source_url  TEXT    NOT NULL,
    type        TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_js_artifacts_scan_id ON js_artifacts(scan_id);

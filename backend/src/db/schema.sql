-- SENTINEL v1 schema
-- Design: a "target" is a host you scan repeatedly over time.
-- A "scan" is one run against a target, made of several "modules"
-- (tls, http, dns, ports). Each module produces "findings".
-- This shape is what lets us show risk-score history per target later.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS targets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname            TEXT NOT NULL UNIQUE,
    label               TEXT,                     -- optional friendly name
    verification_token  TEXT NOT NULL,            -- random token owner must publish via DNS TXT
    verified_at         TIMESTAMPTZ,               -- null until ownership is proven
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type
        WHERE typname = 'scan_status'
    ) THEN
        CREATE TYPE scan_status AS ENUM ('queued', 'running', 'completed', 'failed');
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS scans (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id      UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    status         scan_status NOT NULL DEFAULT 'queued',
    risk_score     SMALLINT,              -- 0-100, filled in when completed
    modules        TEXT[] NOT NULL,       -- which modules were requested: tls, http, dns, ports
    error          TEXT,                  -- populated if status = failed
    queued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id, queued_at DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type
        WHERE typname = 'finding_severity'
    ) THEN
        CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS findings (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id        UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module         TEXT NOT NULL,          -- tls | http | dns | ports
    severity       finding_severity NOT NULL,
    title          TEXT NOT NULL,
    description    TEXT NOT NULL,
    remediation    TEXT,
    raw_evidence   JSONB,                  -- raw scanner output for this finding
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

-- Scan progress events, used to drive the WebSocket live-update feed.
-- Kept separate from findings since these are ephemeral status lines,
-- not part of the final report.
CREATE TABLE IF NOT EXISTS scan_events (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    message     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_events_scan ON scan_events(scan_id, created_at);

-- ==========================================================================
-- SentinelStream: raw telemetry table
--
-- This table is populated exclusively via pure JDBC batch inserts
-- (TelemetryBatchWriter) and is intentionally NOT managed by Hibernate,
-- since it is a high-volume, write-once, append-only table where ORM
-- entity-tracking overhead would work against the throughput goal.
--
-- incident_reports and threat_origins are created automatically by
-- Hibernate (hibernate.hbm2ddl.auto=update in persistence.xml) the first
-- time the application starts, so they are NOT defined here.
-- ==========================================================================

CREATE DATABASE sentinel_stream_db; -- run this line separately, then connect to it before the rest

CREATE TABLE IF NOT EXISTS raw_telemetry (
    id              BIGSERIAL PRIMARY KEY,
    sequence_id     BIGINT NOT NULL,
    event_timestamp TIMESTAMP NOT NULL,
    source_ip       VARCHAR(45) NOT NULL,
    event_type      VARCHAR(64) NOT NULL,
    raw_line        TEXT NOT NULL,
    ingested_at     TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Speeds up the kind of ad-hoc forensic lookups analysts run after an alert fires.
CREATE INDEX IF NOT EXISTS idx_raw_telemetry_source_ip ON raw_telemetry (source_ip);
CREATE INDEX IF NOT EXISTS idx_raw_telemetry_event_type ON raw_telemetry (event_type);
CREATE INDEX IF NOT EXISTS idx_raw_telemetry_timestamp ON raw_telemetry (event_timestamp);

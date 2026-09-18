package com.sentinelstream.model;

import java.time.LocalDateTime;

/**
 * A single normalized unit of telemetry flowing through the pipeline:
 * producers create these from raw log lines, consumers analyze them against
 * the rule engine, and the JDBC batch writer persists them verbatim for
 * forensic replay.
 *
 * Immutable by design: once a record leaves the parser it is shared across
 * threads (placed on the blocking queue and read by whichever consumer
 * thread picks it up), so it must never be mutated after construction.
 */
public final class TelemetryRecord {

    private final long sequenceId;
    private final LocalDateTime timestamp;
    private final String sourceIp;
    private final String eventType;
    private final String rawLine;

    public TelemetryRecord(long sequenceId, LocalDateTime timestamp, String sourceIp,
                            String eventType, String rawLine) {
        this.sequenceId = sequenceId;
        this.timestamp = timestamp;
        this.sourceIp = sourceIp;
        this.eventType = eventType;
        this.rawLine = rawLine;
    }

    public long getSequenceId() {
        return sequenceId;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getEventType() {
        return eventType;
    }

    public String getRawLine() {
        return rawLine;
    }

    @Override
    public String toString() {
        return String.format("TelemetryRecord[#%d ts=%s ip=%s type=%s]",
                sequenceId, timestamp, sourceIp, eventType);
    }
}

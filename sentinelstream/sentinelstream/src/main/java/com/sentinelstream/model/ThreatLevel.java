package com.sentinelstream.model;

/**
 * Standardized severity classification used across the detection engine,
 * the JDBC raw telemetry table and the JPA-managed IncidentReport entity.
 *
 * Ordinal order is intentionally low -> high severity so natural enum
 * comparisons (level.compareTo(other)) behave the way an analyst expects.
 */
public enum ThreatLevel {
    INFO(0, "Informational event, no action required"),
    LOW(1, "Minor anomaly, monitor only"),
    MEDIUM(2, "Suspicious activity, review recommended"),
    HIGH(3, "Likely malicious activity, response advised"),
    CRITICAL(4, "Active compromise indicators, immediate response required");

    private final int weight;
    private final String description;

    ThreatLevel(int weight, String description) {
        this.weight = weight;
        this.description = description;
    }

    public int getWeight() {
        return weight;
    }

    public String getDescription() {
        return description;
    }

    public boolean isAtLeast(ThreatLevel other) {
        return this.weight >= other.weight;
    }
}

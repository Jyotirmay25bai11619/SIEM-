package com.sentinelstream.rules;

import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.model.ThreatLevel;

import java.util.Optional;

/**
 * Base type for every threat detection algorithm in the engine.
 *
 * Each consumer thread holds its own set of rule instances (rules are
 * stateful -- e.g. BruteForceDetector tracks per-IP failure counts -- so
 * they are NOT shared across threads; see RuleLoader for instantiation).
 *
 * Concrete rules only need to implement {@link #inspect(TelemetryRecord)};
 * everything else (name, base severity) is common plumbing living here,
 * which is the polymorphism the syllabus calls for: the consumer loop
 * invokes rule.inspect(record) without caring which concrete subclass it
 * is holding.
 */
public abstract class SecurityRule {

    private final String ruleName;
    private final ThreatLevel baseSeverity;

    protected SecurityRule(String ruleName, ThreatLevel baseSeverity) {
        this.ruleName = ruleName;
        this.baseSeverity = baseSeverity;
    }

    public String getRuleName() {
        return ruleName;
    }

    public ThreatLevel getBaseSeverity() {
        return baseSeverity;
    }

    /**
     * Inspect a single telemetry record in the context of this rule's
     * internal state (e.g. sliding window of recent failures for this IP).
     *
     * @return an Optional describing the finding if this record trips the
     *         rule, or Optional.empty() if the record is benign under this rule.
     */
    public abstract Optional<RuleFinding> inspect(TelemetryRecord record);

    /**
     * Simple immutable result object returned when a rule fires.
     */
    public static final class RuleFinding {
        private final String ruleName;
        private final ThreatLevel severity;
        private final String sourceIp;
        private final String summary;

        public RuleFinding(String ruleName, ThreatLevel severity, String sourceIp, String summary) {
            this.ruleName = ruleName;
            this.severity = severity;
            this.sourceIp = sourceIp;
            this.summary = summary;
        }

        public String getRuleName() {
            return ruleName;
        }

        public ThreatLevel getSeverity() {
            return severity;
        }

        public String getSourceIp() {
            return sourceIp;
        }

        public String getSummary() {
            return summary;
        }

        @Override
        public String toString() {
            return String.format("[%s] %s from %s :: %s", severity, ruleName, sourceIp, summary);
        }
    }
}

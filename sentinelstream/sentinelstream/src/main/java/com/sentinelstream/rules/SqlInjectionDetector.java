package com.sentinelstream.rules;

import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.model.ThreatLevel;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Detects classic SQL injection signatures in the telemetry payload.
 */
public class SqlInjectionDetector extends SecurityRule {

    private static final Pattern SQLI_PATTERN = Pattern.compile(
            "(?i)('.*?OR.*?'.*?=.*?'|UNION\\s+SELECT|;\\s*DROP\\s+TABLE|;\\s*INSERT\\s+INTO)"
    );

    public SqlInjectionDetector() {
        super("SQL_INJECTION", ThreatLevel.CRITICAL);
    }

    @Override
    public Optional<RuleFinding> inspect(TelemetryRecord record) {
        String payload = record.getRawLine();
        if (payload != null && SQLI_PATTERN.matcher(payload).find()) {
            return Optional.of(new RuleFinding(
                    getRuleName(),
                    getBaseSeverity(),
                    record.getSourceIp(),
                    "Detected potential SQL injection payload in request"
            ));
        }
        return Optional.empty();
    }
}

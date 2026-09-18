package com.sentinelstream.rules;

import com.sentinelstream.annotation.CriticalAudit;
import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.model.ThreatLevel;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Stack;

/**
 * Detects distributed / repeated brute-force login attempts.
 *
 * Per source IP, maintains a {@link Stack} of consecutive LOGIN_FAILED
 * timestamps (a Stack is a natural fit here: we only ever care about the
 * most recent run of failures and need to pop off entries that fall
 * outside the sliding window, which is a LIFO access pattern). A
 * LOGIN_SUCCESS clears that IP's stack -- a successful login resets the
 * anomaly streak.
 *
 * Tagged @CriticalAudit because brute-force compromise is one of the two
 * headline scenarios named in the project's problem statement.
 */
@CriticalAudit(reason = "Detects distributed brute-force login attempts", pageOnCall = true)
public class BruteForceDetector extends SecurityRule {

    private static final int FAILURE_THRESHOLD = 5;
    private static final Duration WINDOW = Duration.ofMinutes(2);

    // Not thread-safe by design: each consumer thread owns its own instance (see
    // RuleLoader).
    private final Map<String, Stack<LocalDateTime>> failuresByIp = new HashMap<>();

    public BruteForceDetector() {
        super("BruteForceDetector", ThreatLevel.HIGH);
    }

    @Override
    public Optional<RuleFinding> inspect(TelemetryRecord record) {
        String ip = record.getSourceIp();

        if ("LOGIN_SUCCESS".equals(record.getEventType())) {
            failuresByIp.remove(ip);
            return Optional.empty();
        }

        if (!"LOGIN_FAILED".equals(record.getEventType())) {
            return Optional.empty();
        }

        Stack<LocalDateTime> stack = failuresByIp.computeIfAbsent(ip, k -> new Stack<>());
        stack.push(record.getTimestamp());

        // Evict entries that have aged out of the sliding window from the top down.
        while (!stack.isEmpty() && Duration.between(stack.firstElement(), stack.peek()).compareTo(WINDOW) > 0) {
            stack.remove(0); // drop the oldest (bottom) entry once window is exceeded
        }

        if (stack.size() >= FAILURE_THRESHOLD) {
            ThreatLevel severity = stack.size() >= FAILURE_THRESHOLD * 2 ? ThreatLevel.CRITICAL : getBaseSeverity();
            String summary = String.format("%d failed login attempts within %d minutes",
                    stack.size(), WINDOW.toMinutes());
            // Reset after firing so we don't re-alert on every single subsequent failure.
            stack.clear();
            return Optional.of(new RuleFinding(getRuleName(), severity, ip, summary));
        }

        return Optional.empty();
    }
}

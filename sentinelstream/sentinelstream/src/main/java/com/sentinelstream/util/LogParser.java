package com.sentinelstream.util;

import com.sentinelstream.exception.MalformedTelemetryException;
import com.sentinelstream.model.TelemetryRecord;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses one line of the mock server_traffic.log format into a TelemetryRecord.
 *
 * Expected line format (pipe-delimited, produced by MockDataGenerator):
 * 2024-01-15T10:23:41|192.168.1.45|LOGIN_FAILED|/api/auth|extra free-text
 * detail
 *
 * Uses if/else and switch flow control deliberately (per project syllabus
 * mapping) rather than collapsing everything into a single regex group,
 * so each validation stage is explicit and independently testable.
 */
public class LogParser {

    private static final Pattern LINE_PATTERN = Pattern.compile(
            "^([^|\\r\\n]+)\\|([^|\\r\\n]+)\\|([^|\\r\\n]+)\\|([^|\\r\\n]+)(?:\\|(.*))?$");

    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    // Thread-safe monotonically increasing id shared across all producer threads.
    private final AtomicLong sequenceGenerator = new AtomicLong(0);

    public TelemetryRecord parse(String rawLine, long lineNumber) throws MalformedTelemetryException {
        if (rawLine == null || rawLine.isBlank()) {
            throw new MalformedTelemetryException("Empty or null line", rawLine, lineNumber);
        }

        Matcher matcher = LINE_PATTERN.matcher(rawLine.trim());
        if (!matcher.matches()) {
            throw new MalformedTelemetryException(
                    "Line does not match expected pipe-delimited telemetry format", rawLine, lineNumber);
        }

        String rawTimestamp = matcher.group(1);
        String sourceIp = matcher.group(2);
        String eventType = matcher.group(3);
        // group(4) is the endpoint/path -- currently folded into eventType context
        // downstream.

        LocalDateTime timestamp;
        try {
            timestamp = LocalDateTime.parse(rawTimestamp, TIMESTAMP_FORMAT);
        } catch (Exception e) {
            throw new MalformedTelemetryException("Unparseable timestamp: " + rawTimestamp, rawLine, lineNumber, e);
        }

        if (!isPlausibleIp(sourceIp)) {
            throw new MalformedTelemetryException("Unparseable or invalid source IP: " + sourceIp, rawLine, lineNumber);
        }

        // switch on event type purely for normalization / early flow-control triage
        String normalizedType;
        switch (eventType.toUpperCase()) {
            case "LOGIN_FAILED":
            case "LOGIN_SUCCESS":
            case "PORT_SCAN":
            case "DATA_TRANSFER":
            case "FILE_ACCESS":
                normalizedType = eventType.toUpperCase();
                break;
            default:
                normalizedType = "UNKNOWN";
        }

        return new TelemetryRecord(sequenceGenerator.incrementAndGet(), timestamp, sourceIp, normalizedType, rawLine);
    }

    private boolean isPlausibleIp(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) {
            return false;
        }
        for (String octet : octets) {
            try {
                int value = Integer.parseInt(octet);
                if (value < 0 || value > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }
}

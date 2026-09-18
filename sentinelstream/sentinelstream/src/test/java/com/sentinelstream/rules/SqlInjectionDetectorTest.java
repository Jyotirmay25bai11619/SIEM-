package com.sentinelstream.rules;

import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.rules.SecurityRule.RuleFinding;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SqlInjectionDetectorTest {

    @Test
    public void testSqlInjectionDetected() {
        SqlInjectionDetector detector = new SqlInjectionDetector();
        TelemetryRecord record = new TelemetryRecord(1, LocalDateTime.now(), "10.0.0.1", "HTTP_GET", "GET /login?user=' OR '1'='1 HTTP/1.1");
        
        Optional<RuleFinding> finding = detector.inspect(record);
        
        assertTrue(finding.isPresent());
        assertEquals("SQL_INJECTION", finding.get().getRuleName());
        assertEquals("10.0.0.1", finding.get().getSourceIp());
    }

    @Test
    public void testBenignPayload() {
        SqlInjectionDetector detector = new SqlInjectionDetector();
        TelemetryRecord record = new TelemetryRecord(1, LocalDateTime.now(), "10.0.0.1", "HTTP_GET", "GET /login?user=admin HTTP/1.1");
        
        Optional<RuleFinding> finding = detector.inspect(record);
        
        assertFalse(finding.isPresent());
    }
}

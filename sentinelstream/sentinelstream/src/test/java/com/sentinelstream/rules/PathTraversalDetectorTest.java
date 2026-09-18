package com.sentinelstream.rules;

import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.rules.SecurityRule.RuleFinding;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class PathTraversalDetectorTest {

    @Test
    public void testPathTraversalDetected() {
        PathTraversalDetector detector = new PathTraversalDetector();
        TelemetryRecord record = new TelemetryRecord(1, LocalDateTime.now(), "10.0.0.1", "HTTP_GET", "GET /../../../etc/passwd HTTP/1.1");
        
        Optional<RuleFinding> finding = detector.inspect(record);
        
        assertTrue(finding.isPresent());
        assertEquals("PATH_TRAVERSAL", finding.get().getRuleName());
    }

    @Test
    public void testBenignPath() {
        PathTraversalDetector detector = new PathTraversalDetector();
        TelemetryRecord record = new TelemetryRecord(1, LocalDateTime.now(), "10.0.0.1", "HTTP_GET", "GET /images/logo.png HTTP/1.1");
        
        Optional<RuleFinding> finding = detector.inspect(record);
        
        assertFalse(finding.isPresent());
    }
}

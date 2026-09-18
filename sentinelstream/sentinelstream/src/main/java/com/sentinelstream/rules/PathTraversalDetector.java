package com.sentinelstream.rules;

import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.model.ThreatLevel;

import java.util.Optional;
import java.util.Stack;

/**
 * Detects Path Traversal (Directory Traversal) attacks.
 * Simulates directory navigation using a Stack to determine if the payload attempts
 * to navigate above the web root.
 */
public class PathTraversalDetector extends SecurityRule {

    public PathTraversalDetector() {
        super("PATH_TRAVERSAL", ThreatLevel.HIGH);
    }

    @Override
    public Optional<RuleFinding> inspect(TelemetryRecord record) {
        String payload = record.getRawLine();
        if (payload == null) {
            return Optional.empty();
        }

        // Normalize URL encoded sequences for basic checking
        String normalized = payload.replace("%2e%2e%2f", "../")
                                   .replace("%2e%2e/", "../")
                                   .replace("..%2f", "../")
                                   .replace("%2e%2e%5c", "..\\")
                                   .replace("%2e%2e\\", "..\\")
                                   .replace("..%5c", "..\\");

        // Simple stack-based traversal simulation
        // Extract the path-like segment (e.g. GET /../../../etc/passwd HTTP/1.1)
        int pathStart = normalized.indexOf(" /");
        int pathEnd = normalized.indexOf(" HTTP/");
        
        if (pathStart == -1) {
            pathStart = 0;
            pathEnd = normalized.length();
        } else {
            pathStart += 2;
            if (pathEnd == -1) {
                pathEnd = normalized.length();
            }
        }

        String path = normalized.substring(pathStart, pathEnd);
        
        // Check for common traversal indicators directly
        if (path.contains("../") || path.contains("..\\")) {
            Stack<String> stack = new Stack<>();
            String[] segments = path.split("[/\\\\]");
            for (String segment : segments) {
                if (segment.equals("..")) {
                    if (stack.isEmpty()) {
                        // Attempt to traverse above root
                        return Optional.of(new RuleFinding(
                                getRuleName(),
                                getBaseSeverity(),
                                record.getSourceIp(),
                                "Detected path traversal attempt navigating above root: " + path
                        ));
                    } else {
                        stack.pop();
                    }
                } else if (!segment.isEmpty() && !segment.equals(".")) {
                    stack.push(segment);
                }
            }
            
            // Even if it didn't go above root, excessive traversal might still be an attack,
            // but we'll stick to the stack-underflow definition for now.
        }

        return Optional.empty();
    }
}

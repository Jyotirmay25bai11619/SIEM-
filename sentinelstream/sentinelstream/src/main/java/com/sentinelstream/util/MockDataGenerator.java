package com.sentinelstream.util;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Generates a mock server_traffic.log file simulating normal traffic with
 * embedded "attack" bursts (brute-force login storms and data-exfiltration
 * spikes) so the pipeline has something realistic to detect.
 *
 * Run standalone: {@code java -cp target/classes com.sentinelstream.util.MockDataGenerator}
 * or pass a target size in MB and an output path as args.
 */
public class MockDataGenerator {

    private static final String[] NORMAL_EVENT_TYPES = {
            "LOGIN_SUCCESS", "FILE_ACCESS", "PORT_SCAN", "DATA_TRANSFER"
    };

    private static final String[] ENDPOINTS = {
            "/api/auth", "/api/users", "/api/files", "/api/reports", "/api/admin"
    };

    public static void main(String[] args) {
        double targetMb = args.length > 0 ? Double.parseDouble(args[0]) : 5.0;
        String outputPath = args.length > 1 ? args[1] : "server_traffic.log";
        new MockDataGenerator().generate(outputPath, targetMb);
    }

    public void generate(String outputPath, double targetSizeMb) {
        long targetBytes = (long) (targetSizeMb * 1024 * 1024);
        Random random = ThreadLocalRandom.current();
        LocalDateTime timestamp = LocalDateTime.now().minusDays(1);

        long bytesWritten = 0;
        long linesWritten = 0;
        int linesSinceLastAttack = 0;

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            while (bytesWritten < targetBytes) {
                linesSinceLastAttack++;

                String line;
                // Roughly every ~2000 lines, inject a short attack burst.
                if (linesSinceLastAttack > 2000 && random.nextInt(50) == 0) {
                    line = writeAttackBurst(writer, timestamp, random);
                    linesSinceLastAttack = 0;
                    timestamp = timestamp.plusSeconds(random.nextInt(3) + 1);
                    linesWritten += 25; // approx burst size, tracked precisely inside writeAttackBurst
                    bytesWritten += line == null ? 0 : line.length();
                    continue;
                }

                String ip = randomBenignIp(random);
                String eventType = NORMAL_EVENT_TYPES[random.nextInt(NORMAL_EVENT_TYPES.length)];
                String endpoint = ENDPOINTS[random.nextInt(ENDPOINTS.length)];
                line = formatLine(timestamp, ip, eventType, endpoint, "normal traffic");

                writer.write(line);
                writer.newLine();
                bytesWritten += line.length() + 1;
                linesWritten++;
                timestamp = timestamp.plusSeconds(random.nextInt(5));
            }

            System.out.printf("MockDataGenerator: wrote ~%d lines (%.2f MB) to %s%n",
                    linesWritten, bytesWritten / (1024.0 * 1024.0), outputPath);

        } catch (IOException e) {
            System.err.println("Failed to generate mock telemetry file: " + e.getMessage());
        }
    }

    /** Writes a burst of either brute-force or exfiltration-style lines from one attacking IP. */
    private String writeAttackBurst(BufferedWriter writer, LocalDateTime start, Random random) throws IOException {
        String attackerIp = randomAttackerIp(random);
        boolean bruteForce = random.nextBoolean();
        LocalDateTime ts = start;
        String lastLine = null;

        int burstSize = 8 + random.nextInt(20);
        for (int i = 0; i < burstSize; i++) {
            String eventType = bruteForce ? "LOGIN_FAILED" : "DATA_TRANSFER";
            String endpoint = bruteForce ? "/api/auth" : "/api/files";
            String detail = bruteForce ? "invalid credentials" : "bulk export request";
            String line = formatLine(ts, attackerIp, eventType, endpoint, detail);
            writer.write(line);
            writer.newLine();
            ts = ts.plusSeconds(bruteForce ? 5 : 1);
            lastLine = line;
        }
        return lastLine;
    }

    private String formatLine(LocalDateTime timestamp, String ip, String eventType, String endpoint, String detail) {
        return String.format("%s|%s|%s|%s|%s", timestamp, ip, eventType, endpoint, detail);
    }

    private String randomBenignIp(Random random) {
        return String.format("10.0.%d.%d", random.nextInt(255), random.nextInt(255));
    }

    private String randomAttackerIp(Random random) {
        return String.format("192.168.1.%d", 40 + random.nextInt(20));
    }
}

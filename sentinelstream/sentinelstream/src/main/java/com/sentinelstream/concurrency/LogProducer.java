package com.sentinelstream.concurrency;

import com.sentinelstream.exception.MalformedTelemetryException;
import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.util.LogParser;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Reads the (potentially very large, e.g. 500MB) mock telemetry log file
 * off disk using a character-stream pipeline (FileInputStream wrapped in
 * an InputStreamReader wrapped in a BufferedReader) so the whole file is
 * never loaded into memory at once, and pushes each successfully parsed
 * record onto the SharedLogBuffer for the consumer pool to pick up.
 *
 * On a malformed line the custom checked MalformedTelemetryException is
 * caught locally: the pipeline logs the corrupt line and moves on to the
 * next one rather than crashing the whole run (try...catch...finally is
 * used deliberately here per the syllabus mapping, with finally used to
 * guarantee the corrupt-line counter and the reader are always cleaned up).
 */
public class LogProducer implements Runnable {

    private static final Logger LOGGER = Logger.getLogger(LogProducer.class.getName());

    private final String logFilePath;
    private final SharedLogBuffer buffer;
    private final int consumerCount;
    private final LogParser parser = new LogParser();

    private final AtomicLong linesRead = new AtomicLong(0);
    private final AtomicLong malformedLines = new AtomicLong(0);

    public LogProducer(String logFilePath, SharedLogBuffer buffer, int consumerCount) {
        this.logFilePath = logFilePath;
        this.buffer = buffer;
        this.consumerCount = consumerCount;
    }

    @Override
    public void run() {
        long lineNumber = 0;
        BufferedReader reader = null;

        try {
            reader = new BufferedReader(
                    new InputStreamReader(new FileInputStream(logFilePath), StandardCharsets.UTF_8));

            String line;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                try {
                    TelemetryRecord record = parser.parse(line, lineNumber);
                    buffer.put(record);
                    linesRead.incrementAndGet();

                    if (linesRead.get() % 50_000 == 0) {
                        LOGGER.info(() -> String.format("Producer: ingested %,d lines (buffer size=%d)",
                                linesRead.get(), buffer.size()));
                    }
                } catch (MalformedTelemetryException e) {
                    malformedLines.incrementAndGet();
                    LOGGER.log(Level.WARNING, "Skipping malformed telemetry line: " + e.getMessage());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LOGGER.warning("Producer interrupted while enqueuing record, shutting down early");
                    return;
                }
            }

        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "I/O failure reading telemetry log at " + logFilePath, e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Failed to close log file reader cleanly", e);
                }
            }

            // Send one poison pill per consumer so every consumer thread terminates cleanly.
            for (int i = 0; i < consumerCount; i++) {
                try {
                    buffer.put(SharedLogBuffer.POISON_PILL);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            LOGGER.info(() -> String.format(
                    "Producer finished: %,d lines ingested, %,d malformed lines skipped",
                    linesRead.get(), malformedLines.get()));
        }
    }

    public long getLinesRead() {
        return linesRead.get();
    }

    public long getMalformedLines() {
        return malformedLines.get();
    }
}

package com.sentinelstream;

import com.sentinelstream.concurrency.LogConsumer;
import com.sentinelstream.concurrency.LogProducer;
import com.sentinelstream.concurrency.SharedLogBuffer;
import com.sentinelstream.config.DatabaseConnectionManager;
import com.sentinelstream.persistence.jdbc.TelemetryBatchWriter;
import com.sentinelstream.persistence.jpa.IncidentReportDAO;
import com.sentinelstream.persistence.jpa.JpaUtil;
import com.sentinelstream.util.MockDataGenerator;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Application entry point. Wires together the full pipeline described in
 * the project overview:
 *
 *   log file --(LogProducer, BufferedReader)--> SharedLogBuffer
 *            --(N x LogConsumer threads, polymorphic SecurityRule engine)-->
 *              TelemetryBatchWriter (raw JDBC)  +  IncidentReportDAO (JPA/Hibernate)
 *
 * Run with: java -cp target/sentinel-stream.jar com.sentinelstream.Main
 */
public class Main {

    private static final Logger LOGGER = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        Properties config = loadConfig();

        String logFilePath = config.getProperty("pipeline.log.file", "server_traffic.log");
        int consumerThreads = Integer.parseInt(config.getProperty("pipeline.consumer.threads", "4"));
        int bufferCapacity = Integer.parseInt(config.getProperty("pipeline.buffer.capacity", "10000"));
        double mockSizeMb = Double.parseDouble(config.getProperty("mockdata.target.size.mb", "50"));

        ensureLogFileExists(logFilePath, mockSizeMb);

        LOGGER.info("=== SentinelStream starting ===");
        LOGGER.info(() -> String.format("logFile=%s consumerThreads=%d bufferCapacity=%d",
                logFilePath, consumerThreads, bufferCapacity));

        // Singleton connection pool -- first call constructs it, every later call in
        // this JVM reuses the exact same instance (see DatabaseConnectionManager).
        DatabaseConnectionManager connectionManager = DatabaseConnectionManager.getInstance();
        TelemetryBatchWriter batchWriter = new TelemetryBatchWriter(connectionManager);
        IncidentReportDAO incidentDao = new IncidentReportDAO();

        SharedLogBuffer buffer = new SharedLogBuffer(bufferCapacity);

        // consumerThreads + 1 because the producer runs on its own dedicated thread too.
        ExecutorService executor = Executors.newFixedThreadPool(consumerThreads + 1);

        LogProducer producer = new LogProducer(logFilePath, buffer, consumerThreads);
        executor.submit(producer);

        for (int i = 1; i <= consumerThreads; i++) {
            executor.submit(new LogConsumer(i, buffer, batchWriter, incidentDao));
        }

        long start = System.currentTimeMillis();
        executor.shutdown();
        try {
            if (!executor.awaitTermination(30, TimeUnit.MINUTES)) {
                LOGGER.warning("Pipeline did not finish within the timeout window, forcing shutdown");
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
        long elapsedMs = System.currentTimeMillis() - start;

        LOGGER.info(() -> String.format(
                "=== SentinelStream pipeline complete in %.2fs. %,d lines ingested, %,d malformed lines skipped. ===",
                elapsedMs / 1000.0, producer.getLinesRead(), producer.getMalformedLines()));

        printTopIncidents(incidentDao);

        JpaUtil.shutdown();
    }

    private static void printTopIncidents(IncidentReportDAO incidentDao) {
        List<?> incidents = incidentDao.findAllOrderedBySeverityDescending();
        LOGGER.info(() -> "=== Incident summary (" + incidents.size() + " total, highest severity first) ===");
        incidents.stream().limit(10).forEach(i -> LOGGER.info(i::toString));
    }

    private static void ensureLogFileExists(String logFilePath, double mockSizeMb) {
        Path path = Path.of(logFilePath);
        if (Files.exists(path)) {
            return;
        }
        LOGGER.info(() -> logFilePath + " not found, generating mock telemetry (~" + mockSizeMb + " MB)...");
        new MockDataGenerator().generate(logFilePath, mockSizeMb);
    }

    private static Properties loadConfig() {
        Properties props = new Properties();
        try (InputStream in = Main.class.getClassLoader().getResourceAsStream("application.properties")) {
            if (in != null) {
                props.load(in);
            }
        } catch (IOException e) {
            LOGGER.warning("Could not load application.properties, using built-in defaults: " + e.getMessage());
        }
        return props;
    }
}

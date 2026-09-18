package com.sentinelstream.concurrency;

import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.persistence.jdbc.TelemetryBatchWriter;
import com.sentinelstream.persistence.jpa.IncidentReportDAO;
import com.sentinelstream.rules.RuleLoader;
import com.sentinelstream.rules.SecurityRule;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * One of N consumer threads that drain the SharedLogBuffer.
 *
 * Each consumer:
 *   1. Loads its OWN private set of SecurityRule instances via reflection
 *      (RuleLoader) -- rules carry per-IP state, so sharing instances
 *      across threads would require locking every single inspect() call
 *      and would defeat the purpose of parallelizing detection.
 *   2. Batches raw records into an ArrayList and flushes them to the JDBC
 *      batch writer periodically, trading a little latency for far higher
 *      insert throughput than one-row-at-a-time inserts.
 *   3. Immediately hands any rule match (a "finding") to the JPA DAO,
 *      since incidents are comparatively rare and benefit from the richer
 *      relational modeling (IncidentReport -> ThreatOrigin) that
 *      Hibernate gives us, rather than needing batch throughput.
 *
 * Terminates when it reads the SharedLogBuffer.POISON_PILL sentinel.
 */
public class LogConsumer implements Runnable {

    private static final Logger LOGGER = Logger.getLogger(LogConsumer.class.getName());
    private static final int JDBC_BATCH_SIZE = 500;

    private final int consumerId;
    private final SharedLogBuffer buffer;
    private final TelemetryBatchWriter batchWriter;
    private final IncidentReportDAO incidentDao;
    private final List<SecurityRule> rules;

    private long recordsProcessed = 0;
    private long findingsRaised = 0;

    public LogConsumer(int consumerId, SharedLogBuffer buffer,
                        TelemetryBatchWriter batchWriter, IncidentReportDAO incidentDao) {
        this.consumerId = consumerId;
        this.buffer = buffer;
        this.batchWriter = batchWriter;
        this.incidentDao = incidentDao;
        this.rules = new RuleLoader().loadFreshInstances();
    }

    @Override
    public void run() {
        List<TelemetryRecord> pendingBatch = new ArrayList<>(JDBC_BATCH_SIZE);
        LOGGER.info(() -> "Consumer-" + consumerId + " started with " + rules.size() + " active rules");

        try {
            while (true) {
                TelemetryRecord record = buffer.take();

                if (record == SharedLogBuffer.POISON_PILL) {
                    flushBatch(pendingBatch);
                    LOGGER.info(() -> String.format(
                            "Consumer-%d shutting down: processed=%,d findings=%,d",
                            consumerId, recordsProcessed, findingsRaised));
                    break;
                }

                // Run every polymorphic rule against this record. The consumer never
                // needs to know or care which concrete SecurityRule subclass it holds.
                for (SecurityRule rule : rules) {
                    Optional<SecurityRule.RuleFinding> finding = rule.inspect(record);
                    if (finding.isPresent()) {
                        findingsRaised++;
                        SecurityRule.RuleFinding f = finding.get();
                        LOGGER.warning(() -> String.format("[%s] %s", f.getSeverity(), f));
                        incidentDao.persistIncident(f, record);
                    }
                }

                pendingBatch.add(record);
                recordsProcessed++;

                if (pendingBatch.size() >= JDBC_BATCH_SIZE) {
                    flushBatch(pendingBatch);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warning("Consumer-" + consumerId + " interrupted");
        }
    }

    private void flushBatch(List<TelemetryRecord> batch) {
        if (batch.isEmpty()) {
            return;
        }
        batchWriter.writeBatch(batch);
        batch.clear();
    }

    public long getRecordsProcessed() {
        return recordsProcessed;
    }

    public long getFindingsRaised() {
        return findingsRaised;
    }
}

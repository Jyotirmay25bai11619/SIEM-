package com.sentinelstream.persistence.jdbc;

import com.sentinelstream.config.DatabaseConnectionManager;
import com.sentinelstream.model.TelemetryRecord;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Pure JDBC (no ORM) writer for the raw_telemetry table.
 *
 * This is deliberately the "fast path" of the hybrid persistence strategy
 * described in the project overview: millions of raw rows need to land in
 * the database with minimal per-row overhead, so we use a single
 * PreparedStatement with addBatch()/executeBatch() rather than paying
 * Hibernate's entity-management, dirty-checking and first-level-cache
 * overhead for data that is never updated after insert.
 *
 * Connections are borrowed from the Singleton DatabaseConnectionManager
 * pool and always returned in a finally block.
 */
public class TelemetryBatchWriter {

    private static final Logger LOGGER = Logger.getLogger(TelemetryBatchWriter.class.getName());

    private static final String INSERT_SQL =
            "INSERT INTO raw_telemetry (sequence_id, event_timestamp, source_ip, event_type, raw_line) " +
            "VALUES (?, ?, ?, ?, ?)";

    private final DatabaseConnectionManager connectionManager;

    public TelemetryBatchWriter(DatabaseConnectionManager connectionManager) {
        this.connectionManager = connectionManager;
    }

    /**
     * Writes an entire batch of records in a single round trip. On failure,
     * logs the error and returns rather than propagating -- a persistence
     * hiccup on the raw telemetry table must not take down the ingestion
     * pipeline, per the "resilient" requirement in the problem statement.
     */
    public void writeBatch(List<TelemetryRecord> batch) {
        if (batch.isEmpty()) {
            return;
        }

        Connection connection = null;
        try {
            connection = connectionManager.borrowConnection();
            if (connection == null) {
                LOGGER.warning("Could not borrow connection from pool (timeout), skipping batch of " + batch.size());
                return;
            }
            connection.setAutoCommit(false);

            try (PreparedStatement statement = connection.prepareStatement(INSERT_SQL)) {
                for (TelemetryRecord record : batch) {
                    statement.setLong(1, record.getSequenceId());
                    statement.setTimestamp(2, Timestamp.valueOf(record.getTimestamp()));
                    statement.setString(3, record.getSourceIp());
                    statement.setString(4, record.getEventType());
                    statement.setString(5, record.getRawLine());
                    statement.addBatch();
                }

                int[] results = statement.executeBatch();
                connection.commit();
                LOGGER.fine(() -> "Committed JDBC batch of " + results.length + " raw telemetry rows");
            } catch (SQLException e) {
                connection.rollback();
                LOGGER.log(Level.SEVERE, "Batch insert failed, rolled back " + batch.size() + " rows", e);
            }

        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Connection error while writing telemetry batch", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            if (connection != null) {
                try {
                    connection.setAutoCommit(true);
                } catch (SQLException ignored) {
                    // best-effort reset before returning to the pool
                }
                connectionManager.releaseConnection(connection);
            }
        }
    }
}

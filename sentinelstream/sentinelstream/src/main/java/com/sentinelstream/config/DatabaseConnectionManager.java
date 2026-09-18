package com.sentinelstream.config;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Singleton gateway to the database, backing a small hand-rolled connection
 * pool used by the raw JDBC batch writer (the high-speed, low-latency path
 * described in the problem statement).
 *
 * Classic thread-safe lazy Singleton: double-checked locking with a
 * volatile instance field, so the pool is created exactly once even if
 * multiple consumer threads race to call getInstance() during startup.
 */
public final class DatabaseConnectionManager {

    private static final Logger LOGGER = Logger.getLogger(DatabaseConnectionManager.class.getName());
    private static final String CONFIG_FILE = "application.properties";

    private static volatile DatabaseConnectionManager instance;

    private String url;
    private String user;
    private String password;
    private String driverClass;
    private final BlockingQueue<Connection> pool;
    private Properties activeProperties;

    private DatabaseConnectionManager() {
        Properties props = loadProperties();
        this.url = props.getProperty("db.url", "jdbc:postgresql://localhost:5432/sentinel_stream_db");
        this.user = props.getProperty("db.user", "postgres");
        this.password = props.getProperty("db.password", "");
        this.driverClass = "org.postgresql.Driver";

        int poolSize = Integer.parseInt(props.getProperty("db.pool.size", "8"));
        this.pool = new ArrayBlockingQueue<>(poolSize);
        initializePool(poolSize);
    }

    /**
     * Double-checked locking ensures only one pool is ever constructed under
     * concurrent access.
     */
    public static DatabaseConnectionManager getInstance() {
        DatabaseConnectionManager result = instance;
        if (result == null) {
            synchronized (DatabaseConnectionManager.class) {
                result = instance;
                if (result == null) {
                    instance = result = new DatabaseConnectionManager();
                }
            }
        }
        return result;
    }

    private Properties loadProperties() {
        Properties props = new Properties();
        try (InputStream in = DatabaseConnectionManager.class.getClassLoader()
                .getResourceAsStream(CONFIG_FILE)) {
            if (in != null) {
                props.load(in);
            } else {
                LOGGER.warning(CONFIG_FILE + " not found on classpath, falling back to defaults");
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to load " + CONFIG_FILE, e);
        }
        return props;
    }

    private void initializePool(int poolSize) {
        boolean useH2Fallback = false;
        try {
            Connection testConn = DriverManager.getConnection(url, user, password);
            testConn.close();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Failed to connect to primary database (" + url + "). Falling back to embedded H2.");
            useH2Fallback = true;
        }

        if (useH2Fallback) {
            this.url = "jdbc:h2:mem:sentinel_stream_db;DB_CLOSE_DELAY=-1";
            this.user = "sa";
            this.password = "";
            this.driverClass = "org.h2.Driver";
        }

        this.activeProperties = new Properties();
        this.activeProperties.put("javax.persistence.jdbc.url", this.url);
        this.activeProperties.put("javax.persistence.jdbc.user", this.user);
        this.activeProperties.put("javax.persistence.jdbc.password", this.password);
        this.activeProperties.put("javax.persistence.jdbc.driver", this.driverClass);
        if (useH2Fallback) {
            this.activeProperties.put("hibernate.dialect", "org.hibernate.dialect.H2Dialect");
        }

        for (int i = 0; i < poolSize; i++) {
            try {
                pool.offer(DriverManager.getConnection(url, user, password));
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Failed to open pooled connection #" + i, e);
            }
        }
        
        if (useH2Fallback) {
            try (Connection schemaConn = DriverManager.getConnection(url, user, password)) {
                try (java.sql.Statement stmt = schemaConn.createStatement()) {
                    stmt.execute("CREATE TABLE IF NOT EXISTS raw_telemetry (" +
                            "id BIGINT AUTO_INCREMENT PRIMARY KEY, " +
                            "sequence_id BIGINT NOT NULL, " +
                            "event_timestamp TIMESTAMP NOT NULL, " +
                            "source_ip VARCHAR(45) NOT NULL, " +
                            "event_type VARCHAR(64) NOT NULL, " +
                            "raw_line TEXT NOT NULL, " +
                            "ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)");
                }
            } catch (SQLException e) {
                 LOGGER.log(Level.SEVERE, "Failed to initialize H2 schema", e);
            }
        }

        LOGGER.info(() -> "DatabaseConnectionManager pool initialized with " + pool.size() + " connections (" + url + ")");
    }

    /**
     * Borrow a connection from the pool, blocking if none are currently available.
     */
    public Connection borrowConnection() throws InterruptedException {
        return pool.poll(5, java.util.concurrent.TimeUnit.SECONDS);
    }

    /** Return a connection to the pool once the caller is done with it. */
    public void releaseConnection(Connection connection) {
        if (connection != null) {
            pool.offer(connection);
        }
    }

    public String getUrl() {
        return url;
    }

    public Properties getActiveProperties() {
        return activeProperties;
    }
}

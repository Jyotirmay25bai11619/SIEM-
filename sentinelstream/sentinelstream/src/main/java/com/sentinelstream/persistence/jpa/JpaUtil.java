package com.sentinelstream.persistence.jpa;

import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

/**
 * Holds the single application-wide EntityManagerFactory, built once from
 * META-INF/persistence.xml. EntityManagerFactory itself is thread-safe and
 * expensive to create, so -- unlike EntityManager, which is created fresh
 * per unit of work in IncidentReportDAO -- exactly one instance should
 * exist for the lifetime of the application.
 */
public final class JpaUtil {

    private static final EntityManagerFactory ENTITY_MANAGER_FACTORY = Persistence
            .createEntityManagerFactory("sentinelStreamPU", 
                com.sentinelstream.config.DatabaseConnectionManager.getInstance().getActiveProperties());

    private JpaUtil() {
    }

    public static EntityManagerFactory getEntityManagerFactory() {
        return ENTITY_MANAGER_FACTORY;
    }

    public static void shutdown() {
        if (ENTITY_MANAGER_FACTORY.isOpen()) {
            ENTITY_MANAGER_FACTORY.close();
        }
    }
}

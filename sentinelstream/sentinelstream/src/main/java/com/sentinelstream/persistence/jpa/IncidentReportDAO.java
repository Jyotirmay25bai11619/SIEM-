package com.sentinelstream.persistence.jpa;

import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.rules.SecurityRule;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.TypedQuery;
import java.time.LocalDateTime;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Data-access layer for the JPA/Hibernate side of the hybrid persistence
 * strategy. Each public method opens its own short-lived EntityManager and
 * transaction (the "one EntityManager per unit of work" pattern), which is
 * safe to call concurrently from multiple consumer threads since
 * EntityManagerFactory (see JpaUtil) is thread-safe even though individual
 * EntityManager instances are not.
 */
public class IncidentReportDAO {

    private static final Logger LOGGER = Logger.getLogger(IncidentReportDAO.class.getName());

    /**
     * Persists a rule finding as an IncidentReport, reusing an existing
     * ThreatOrigin row for the source IP if one already exists (first-seen
     * lookup) or creating a new one -- demonstrating a managed
     * many-to-one relationship rather than duplicating IP data per incident.
     */
    public void persistIncident(SecurityRule.RuleFinding finding, TelemetryRecord record) {
        EntityManager em = JpaUtil.getEntityManagerFactory().createEntityManager();
        try {
            em.getTransaction().begin();

            ThreatOrigin origin = findOrCreateOrigin(em, finding.getSourceIp(), record.getTimestamp());

            IncidentReport report = new IncidentReport(
                    finding.getRuleName(),
                    finding.getSeverity(),
                    finding.getSummary(),
                    record.getTimestamp(),
                    record.getSequenceId(),
                    origin);

            em.persist(report);
            em.getTransaction().commit();

        } catch (RuntimeException e) {
            if (em.getTransaction().isActive()) {
                em.getTransaction().rollback();
            }
            LOGGER.log(Level.SEVERE, "Failed to persist incident report via JPA", e);
        } finally {
            em.close();
        }
    }

    private ThreatOrigin findOrCreateOrigin(EntityManager em, String ip, LocalDateTime seenAt) {
        try {
            TypedQuery<ThreatOrigin> query = em.createQuery(
                    "SELECT t FROM ThreatOrigin t WHERE t.ipAddress = :ip", ThreatOrigin.class);
            query.setParameter("ip", ip);
            return query.getSingleResult();
        } catch (NoResultException e) {
            try {
                ThreatOrigin origin = new ThreatOrigin(ip, seenAt.toString());
                em.persist(origin);
                em.flush();
                return origin;
            } catch (javax.persistence.PersistenceException pe) {
                // Another thread inserted the same IP concurrently; re-query
                em.clear();
                TypedQuery<ThreatOrigin> retryQuery = em.createQuery(
                        "SELECT t FROM ThreatOrigin t WHERE t.ipAddress = :ip", ThreatOrigin.class);
                retryQuery.setParameter("ip", ip);
                return retryQuery.getSingleResult();
            }
        }
    }

    /**
     * JPQL triage query: highest-severity incidents first, used to back
     * Step 5 of the README's validation guide (equivalent to
     * "SELECT * FROM incident_reports ORDER BY severity DESC").
     */
    public List<IncidentReport> findAllOrderedBySeverityDescending() {
        EntityManager em = JpaUtil.getEntityManagerFactory().createEntityManager();
        try {
            TypedQuery<IncidentReport> query = em.createQuery(
                    "SELECT i FROM IncidentReport i ORDER BY i.severity DESC, i.detectedAt DESC",
                    IncidentReport.class);
            return query.getResultList();
        } finally {
            em.close();
        }
    }

    /** JPQL query: every incident tied to a specific attacking IP. */
    public List<IncidentReport> findByOriginIp(String ip) {
        EntityManager em = JpaUtil.getEntityManagerFactory().createEntityManager();
        try {
            TypedQuery<IncidentReport> query = em.createQuery(
                    "SELECT i FROM IncidentReport i WHERE i.threatOrigin.ipAddress = :ip " +
                            "ORDER BY i.detectedAt DESC",
                    IncidentReport.class);
            query.setParameter("ip", ip);
            return query.getResultList();
        } finally {
            em.close();
        }
    }
}

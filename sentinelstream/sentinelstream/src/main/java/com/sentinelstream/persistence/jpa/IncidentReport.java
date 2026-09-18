package com.sentinelstream.persistence.jpa;

import com.sentinelstream.model.ThreatLevel;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA-managed entity capturing a finalized security incident for analyst
 * triage. This is the "complex forensic entity management" side of the
 * hybrid persistence strategy: unlike raw_telemetry (write-once, JDBC),
 * incidents are relatively few, get read/joined/queried heavily by
 * security analysts (JPQL in IncidentReportDAO), and benefit from
 * Hibernate managing the IncidentReport <-> ThreatOrigin relationship.
 */
@Entity
@Table(name = "incident_reports")
public class IncidentReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rule_name", nullable = false)
    private String ruleName;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    private ThreatLevel severity;

    @Column(name = "summary", length = 1024)
    private String summary;

    @Column(name = "detected_at", nullable = false)
    private LocalDateTime detectedAt;

    @Column(name = "related_sequence_id")
    private Long relatedSequenceId;

    @ManyToOne(cascade = CascadeType.PERSIST, fetch = FetchType.EAGER)
    @JoinColumn(name = "threat_origin_id")
    private ThreatOrigin threatOrigin;

    protected IncidentReport() {
        // required no-arg constructor for JPA
    }

    public IncidentReport(String ruleName, ThreatLevel severity, String summary,
                           LocalDateTime detectedAt, Long relatedSequenceId, ThreatOrigin threatOrigin) {
        this.ruleName = ruleName;
        this.severity = severity;
        this.summary = summary;
        this.detectedAt = detectedAt;
        this.relatedSequenceId = relatedSequenceId;
        this.threatOrigin = threatOrigin;
    }

    public Long getId() {
        return id;
    }

    public String getRuleName() {
        return ruleName;
    }

    public ThreatLevel getSeverity() {
        return severity;
    }

    public String getSummary() {
        return summary;
    }

    public LocalDateTime getDetectedAt() {
        return detectedAt;
    }

    public Long getRelatedSequenceId() {
        return relatedSequenceId;
    }

    public ThreatOrigin getThreatOrigin() {
        return threatOrigin;
    }

    @Override
    public String toString() {
        return String.format("IncidentReport[id=%d, rule=%s, severity=%s, ip=%s]",
                id, ruleName, severity, threatOrigin != null ? threatOrigin.getIpAddress() : "?");
    }
}

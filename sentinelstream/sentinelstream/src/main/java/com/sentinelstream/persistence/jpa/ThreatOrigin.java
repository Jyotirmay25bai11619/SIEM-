package com.sentinelstream.persistence.jpa;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a distinct attacking source (IP address) that may be
 * responsible for multiple incidents over time. Deduplicating origins this
 * way lets analysts run JPQL queries like "show every incident tied to this
 * IP" or "which origins have the highest incident count" without scanning
 * raw telemetry.
 */
@Entity
@Table(name = "threat_origins")
public class ThreatOrigin {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false, unique = true)
    private String ipAddress;

    @Column(name = "first_seen")
    private String firstSeen;

    @Column(name = "reputation_notes", length = 512)
    private String reputationNotes;

    @OneToMany(mappedBy = "threatOrigin", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<IncidentReport> incidents = new ArrayList<>();

    protected ThreatOrigin() {
        // required no-arg constructor for JPA
    }

    public ThreatOrigin(String ipAddress, String firstSeen) {
        this.ipAddress = ipAddress;
        this.firstSeen = firstSeen;
    }

    public Long getId() {
        return id;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getFirstSeen() {
        return firstSeen;
    }

    public String getReputationNotes() {
        return reputationNotes;
    }

    public void setReputationNotes(String reputationNotes) {
        this.reputationNotes = reputationNotes;
    }

    public List<IncidentReport> getIncidents() {
        return incidents;
    }

    @Override
    public String toString() {
        return String.format("ThreatOrigin[ip=%s, firstSeen=%s, incidents=%d]",
                ipAddress, firstSeen, incidents.size());
    }
}

package com.netsentinel.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Graph vertex representing a network host in the attack graph.
 *
 * <p>Wraps a {@link HostFingerprint} with matched CVE records and
 * a computed aggregate risk score used for graph analysis.</p>
 */
public class HostNode {

    private final String id;
    private final HostFingerprint fingerprint;
    private final List<CveRecord> vulnerabilities;
    private double riskScore;
    private double compromiseProbability;

    public HostNode(String id, HostFingerprint fingerprint) {
        this.id = id;
        this.fingerprint = fingerprint;
        this.vulnerabilities = new ArrayList<>();
        this.riskScore = 0.0;
        this.compromiseProbability = 0.0;
    }

    /**
     * Adds a matched CVE and recomputes the aggregate risk score.
     */
    public void addVulnerability(CveRecord cve) {
        this.vulnerabilities.add(cve);
        recomputeRiskScore();
    }

    /**
     * Aggregate risk = weighted sum of CVSS scores adjusted by asset criticality.
     * Uses the formula: R = criticality * (1 - ∏(1 - cvss_i/10))
     * This models the probability of at least one vulnerability being exploited.
     */
    private void recomputeRiskScore() {
        double survivalProbability = 1.0;
        for (CveRecord cve : vulnerabilities) {
            survivalProbability *= (1.0 - cve.cvssBaseScore() / 10.0);
        }
        this.riskScore = fingerprint.criticality() * (1.0 - survivalProbability);
    }

    // --- Getters ---

    public String getId() { return id; }
    public HostFingerprint getFingerprint() { return fingerprint; }
    public List<CveRecord> getVulnerabilities() { return List.copyOf(vulnerabilities); }
    public double getRiskScore() { return riskScore; }
    public double getCompromiseProbability() { return compromiseProbability; }
    public void setCompromiseProbability(double p) { this.compromiseProbability = p; }

    @Override
    public String toString() {
        return "HostNode{" + fingerprint.displayLabel() +
               ", vulns=" + vulnerabilities.size() +
               ", risk=" + String.format("%.2f", riskScore) + "}";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof HostNode other)) return false;
        return id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}

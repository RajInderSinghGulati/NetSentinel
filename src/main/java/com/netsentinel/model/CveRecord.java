package com.netsentinel.model;

import java.util.List;

/**
 * A Common Vulnerabilities and Exposures (CVE) record enriched
 * with CVSS v3.1 metrics and CWE classification.
 *
 * <p>Sourced from the NVD REST API or a local CVE database cache.</p>
 *
 * @param cveId             CVE identifier (e.g., "CVE-2021-44228")
 * @param description       Human-readable vulnerability description
 * @param cvssBaseScore     CVSS v3.1 base score (0.0 - 10.0)
 * @param attackVector      Attack vector: NETWORK, ADJACENT, LOCAL, PHYSICAL
 * @param attackComplexity  Attack complexity: LOW, HIGH
 * @param privilegesRequired Privileges needed: NONE, LOW, HIGH
 * @param userInteraction   User interaction: NONE, REQUIRED
 * @param cweId             CWE classification (e.g., "CWE-502")
 * @param affectedCpes      List of affected CPE strings
 * @param patchAvailable    Whether an official patch exists
 * @param exploitInWild     Whether active exploitation has been observed
 * @param publishedYear     Year the CVE was published (0 if unknown); used for temporal train/test splits
 * @param vendor            Primary vendor taken from the first affected CPE ("unknown" if none)
 */
public record CveRecord(
        String cveId,
        String description,
        double cvssBaseScore,
        AttackVector attackVector,
        AttackComplexity attackComplexity,
        PrivilegesRequired privilegesRequired,
        UserInteraction userInteraction,
        String cweId,
        List<String> affectedCpes,
        boolean patchAvailable,
        boolean exploitInWild,
        int publishedYear,
        String vendor
) {

    /** Convenience constructor: derives year from the CVE id and vendor from the first CPE. */
    public CveRecord(String cveId, String description, double cvssBaseScore,
                     AttackVector attackVector, AttackComplexity attackComplexity,
                     PrivilegesRequired privilegesRequired, UserInteraction userInteraction,
                     String cweId, List<String> affectedCpes,
                     boolean patchAvailable, boolean exploitInWild) {
        this(cveId, description, cvssBaseScore, attackVector, attackComplexity,
                privilegesRequired, userInteraction, cweId, affectedCpes,
                patchAvailable, exploitInWild,
                yearFromId(cveId), vendorFromCpes(affectedCpes));
    }

    /** Copy with the vendor set to the product actually matched on a host. */
    public CveRecord withVendor(String newVendor) {
        return new CveRecord(cveId, description, cvssBaseScore, attackVector, attackComplexity,
                privilegesRequired, userInteraction, cweId, affectedCpes,
                patchAvailable, exploitInWild, publishedYear, newVendor);
    }

    public static int yearFromId(String cveId) {
        String[] p = cveId == null ? new String[0] : cveId.split("-");
        try {
            return p.length >= 3 ? Integer.parseInt(p[1]) : 0;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    public static String vendorFromCpes(List<String> cpes) {
        if (cpes == null || cpes.isEmpty()) return "unknown";
        // Most frequent vendor (ties: alphabetical) — the first CPE is often a downstream product.
        java.util.Map<String, Integer> counts = new java.util.TreeMap<>();
        for (String cpe : cpes) {
            String[] parts = cpe.split(":");
            if (parts.length > 3 && !parts[3].equals("*")) counts.merge(parts[3], 1, Integer::sum);
        }
        return counts.entrySet().stream()
                .max(java.util.Map.Entry.comparingByValue())
                .map(java.util.Map.Entry::getKey).orElse("unknown");
    }

    public enum AttackVector { NETWORK, ADJACENT, LOCAL, PHYSICAL }
    public enum AttackComplexity { LOW, HIGH }
    public enum PrivilegesRequired { NONE, LOW, HIGH }
    public enum UserInteraction { NONE, REQUIRED }

    /**
     * Computes a normalized exploitability sub-score (0.0 - 1.0)
     * based on CVSS v3.1 components.
     */
    public double exploitabilityScore() {
        double avScore = switch (attackVector) {
            case NETWORK -> 0.85;
            case ADJACENT -> 0.62;
            case LOCAL -> 0.55;
            case PHYSICAL -> 0.20;
        };
        double acScore = switch (attackComplexity) {
            case LOW -> 0.77;
            case HIGH -> 0.44;
        };
        double prScore = switch (privilegesRequired) {
            case NONE -> 0.85;
            case LOW -> 0.62;
            case HIGH -> 0.27;
        };
        double uiScore = switch (userInteraction) {
            case NONE -> 0.85;
            case REQUIRED -> 0.62;
        };
        // Normalized product of CVSS exploitability metrics
        return 8.22 * avScore * acScore * prScore * uiScore / 8.22;
    }

    /**
     * Returns severity label based on CVSS base score.
     */
    public String severity() {
        if (cvssBaseScore >= 9.0) return "CRITICAL";
        if (cvssBaseScore >= 7.0) return "HIGH";
        if (cvssBaseScore >= 4.0) return "MEDIUM";
        if (cvssBaseScore > 0.0) return "LOW";
        return "NONE";
    }
}

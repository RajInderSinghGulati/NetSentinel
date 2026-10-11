package com.netsentinel.ai;

import com.netsentinel.model.CveRecord;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * One remediation action: upgrade a product (identified by its CPE) on one host to a fixed version.
 *
 * <p>Only the CVEs in {@code fixedCveIds} disappear. CVEs that also affect the target version stay
 * (residual), and CVEs that affect the target version but not the current one are added
 * ({@code introduced}).</p>
 *
 * @param index         position in the unit list (stable within one scan)
 * @param hostId        graph node id
 * @param hostname      display name of the host
 * @param cpe           CPE 2.3 string of the installed product
 * @param cves          CVEs currently matched through that CPE
 * @param targetVersion version to upgrade to (null = no fixed release is known)
 * @param targetCpe     the product's CPE at {@code targetVersion} (null = no target)
 * @param targetLabel   human-readable target, e.g. "8.6.3" or "newer than 2.4.50"
 * @param fixedCveIds   ids among {@code cves} that the upgrade removes
 * @param introduced    CVEs that affect the target version but not the installed one
 */
public record PatchUnit(int index, String hostId, String hostname, String cpe, List<CveRecord> cves,
                        String targetVersion, String targetCpe, String targetLabel,
                        Set<String> fixedCveIds, List<CveRecord> introduced) {

    /** Legacy form: an upgrade that fixes every matched CVE and introduces none. */
    public PatchUnit(int index, String hostId, String hostname, String cpe, List<CveRecord> cves) {
        this(index, hostId, hostname, cpe, cves, null, null, "any newer release",
                cves.stream().map(CveRecord::cveId).collect(Collectors.toSet()), List.of());
    }

    public List<CveRecord> fixedCves() {
        return cves.stream().filter(c -> fixedCveIds.contains(c.cveId())).toList();
    }

    public List<CveRecord> residualCves() {
        return cves.stream().filter(c -> !fixedCveIds.contains(c.cveId())).toList();
    }

    /** True if the upgrade removes at least one CVE. */
    public boolean fixesAnything() {
        return !fixedCveIds.isEmpty();
    }

    /** Highest CVSS among all CVEs the unit matches (the naive CVSS-first ranking key). */
    public double maxCvss() {
        return cves.stream().mapToDouble(CveRecord::cvssBaseScore).max().orElse(0.0);
    }

    public double sumCvss() {
        return cves.stream().mapToDouble(CveRecord::cvssBaseScore).sum();
    }

    /** "host : cpe" (parsed by lab/apply_plan.py). */
    public String label() {
        return hostname + " : " + cpe;
    }

    public String product() {
        String[] p = cpe.split(":");
        return p.length > 4 ? p[4] : cpe;
    }

    public String currentVersion() {
        String[] p = cpe.split(":");
        return p.length > 5 ? p[5] : "";
    }

    /** e.g. "app-cache: redis 6.2.6 -> 8.6.3 (fixes 20, 2 remain, 0 new)". */
    public String upgradeSummary() {
        return "%s: %s %s -> %s (fixes %d, %d remain, %d new)".formatted(hostname, product(), currentVersion(),
                targetLabel, fixedCveIds.size(), cves.size() - fixedCveIds.size(), introduced.size());
    }
}

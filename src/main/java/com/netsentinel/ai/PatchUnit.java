package com.netsentinel.ai;

import com.netsentinel.model.CveRecord;

import java.util.List;

/**
 * One remediation action: upgrade a product (identified by its CPE) on one host.
 * Applying it removes every CVE that was matched through that CPE on that host.
 *
 * @param index    position in the unit list (stable within one scan)
 * @param hostId   graph node id (IP)
 * @param hostname display name of the host
 * @param cpe      CPE 2.3 string of the product being upgraded
 * @param cves     CVEs fixed by the upgrade
 */
public record PatchUnit(int index, String hostId, String hostname, String cpe, List<CveRecord> cves) {

    public double maxCvss() {
        return cves.stream().mapToDouble(CveRecord::cvssBaseScore).max().orElse(0.0);
    }

    public double sumCvss() {
        return cves.stream().mapToDouble(CveRecord::cvssBaseScore).sum();
    }

    public String label() {
        return hostname + " : " + cpe;
    }
}

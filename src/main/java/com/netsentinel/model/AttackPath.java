package com.netsentinel.model;

import java.util.List;

/**
 * Represents a single multi-hop attack path through the network,
 * computed by Yen's K-Shortest Paths algorithm.
 *
 * @param pathId            Unique path identifier (1-indexed rank)
 * @param hops              Ordered list of host nodes from entry to target
 * @param edges             Ordered list of exploit edges traversed
 * @param cumulativeRisk    Product of individual edge exploit probabilities
 * @param entryPoint        The DMZ/external entry node
 * @param target            The crown jewel target node
 * @param bottleneckCve     The single most impactful CVE to remediate on this path
 */
public record AttackPath(
        int pathId,
        List<HostNode> hops,
        List<ExploitEdge> edges,
        double cumulativeRisk,
        HostNode entryPoint,
        HostNode target,
        CveRecord bottleneckCve
) {

    /**
     * Returns the number of hops in this attack path.
     */
    public int hopCount() {
        return hops.size() - 1;
    }

    /**
     * Returns a human-readable path description.
     */
    public String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Attack Path #%d (Risk: %.4f, Hops: %d)%n", pathId, cumulativeRisk, hopCount()));
        for (int i = 0; i < hops.size(); i++) {
            sb.append("  ").append(hops.get(i).getFingerprint().displayLabel());
            if (i < edges.size()) {
                ExploitEdge edge = edges.get(i);
                String cveLabel = edge.getExploitedCve() != null
                        ? edge.getExploitedCve().cveId()
                        : "network-flow";
                sb.append(String.format(" --[%s (P=%.2f)]--> ", cveLabel, edge.getExploitProbability()));
            }
        }
        if (bottleneckCve != null) {
            sb.append(String.format("%n  ⚠ Bottleneck: %s (CVSS %.1f) — %s",
                    bottleneckCve.cveId(), bottleneckCve.cvssBaseScore(), bottleneckCve.description()));
        }
        return sb.toString();
    }
}

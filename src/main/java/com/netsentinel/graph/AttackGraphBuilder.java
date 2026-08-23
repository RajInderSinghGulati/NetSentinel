package com.netsentinel.graph;

import com.netsentinel.cve.CveDatabase;
import com.netsentinel.model.*;
import com.netsentinel.model.HostFingerprint.NetworkTier;
import org.jgrapht.graph.DirectedWeightedMultigraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Tier 2: Topological Attack Graph Builder.
 *
 * <p>Constructs a JGraphT {@code DirectedWeightedMultigraph<HostNode, ExploitEdge>}
 * from discovered network hosts. The graph models:</p>
 * <ul>
 *   <li><b>Nodes (V):</b> Network hosts enriched with matched CVE records</li>
 *   <li><b>Edges (E):</b> Network reachability flows weighted by exploitability</li>
 * </ul>
 *
 * <p>Edge creation follows enterprise firewall segmentation rules:</p>
 * <pre>
 *   EXTERNAL → DMZ          (internet-facing services)
 *   DMZ → APPLICATION       (reverse proxy to app servers)
 *   APPLICATION → DATA      (app servers to databases)
 *   APPLICATION → CROWN_JEWEL (lateral movement)
 *   DATA → CROWN_JEWEL      (database links)
 * </pre>
 */
@Component
public class AttackGraphBuilder {

    private static final Logger log = LoggerFactory.getLogger(AttackGraphBuilder.class);

    private final CveDatabase cveDatabase;

    public AttackGraphBuilder(CveDatabase cveDatabase) {
        this.cveDatabase = cveDatabase;
    }

    /**
     * Builds the complete attack graph from discovered hosts.
     *
     * @param fingerprints List of discovered host fingerprints from Tier 1
     * @return The constructed attack graph with CVE-enriched nodes and weighted edges
     */
    public AttackGraphResult buildGraph(List<HostFingerprint> fingerprints) {
        log.info("▶ Building attack graph from {} discovered hosts", fingerprints.size());

        var graph = new DirectedWeightedMultigraph<HostNode, ExploitEdge>(ExploitEdge.class);
        Map<String, HostNode> nodeMap = new LinkedHashMap<>();
        int totalCves = 0;

        // ════════════════════════════════════════
        // Step 1: Create nodes and enrich with CVEs
        // ════════════════════════════════════════
        for (HostFingerprint fp : fingerprints) {
            HostNode node = new HostNode(fp.ip(), fp);

            // Look up CVEs for each CPE string
            for (String cpe : fp.cpeStrings()) {
                List<CveRecord> cves = cveDatabase.findByCpe(cpe);
                for (CveRecord cve : cves) {
                    node.addVulnerability(cve);
                    totalCves++;
                    log.debug("  ⚡ Matched {} → {} (CVSS {})",
                            fp.hostname(), cve.cveId(), cve.cvssBaseScore());
                }
            }

            graph.addVertex(node);
            nodeMap.put(fp.ip(), node);
        }

        // ════════════════════════════════════════
        // Step 2: Create edges based on reachability rules
        // ════════════════════════════════════════
        int edgeCount = 0;
        for (HostNode source : graph.vertexSet()) {
            for (HostNode target : graph.vertexSet()) {
                if (source.equals(target)) continue;

                if (canReach(source.getFingerprint().tier(), target.getFingerprint().tier())) {
                    // Create edges for each vulnerability on the target
                    if (!target.getVulnerabilities().isEmpty()) {
                        for (CveRecord cve : target.getVulnerabilities()) {
                            if (cve.attackVector() == CveRecord.AttackVector.NETWORK) {
                                ExploitEdge edge = new ExploitEdge(
                                        "e-" + (edgeCount++),
                                        cve,
                                        "TCP",
                                        target.getFingerprint().openPorts().isEmpty() ? 0 :
                                                target.getFingerprint().openPorts().get(0),
                                        cve.exploitabilityScore(),
                                        "remote"
                                );
                                graph.addEdge(source, target, edge);
                                // Weight = inverse of exploit probability (lower = easier to exploit)
                                graph.setEdgeWeight(edge, 1.0 - cve.exploitabilityScore() + 0.01);
                            }
                        }
                    } else {
                        // Reachability edge (no known vulnerability)
                        ExploitEdge edge = new ExploitEdge(
                                "e-" + (edgeCount++),
                                null, "TCP",
                                target.getFingerprint().openPorts().isEmpty() ? 0 :
                                        target.getFingerprint().openPorts().get(0),
                                0.1, "network-flow"
                        );
                        graph.addEdge(source, target, edge);
                        graph.setEdgeWeight(edge, 0.9);
                    }
                }
            }
        }

        log.info("✓ Attack graph built: {} nodes, {} edges, {} CVEs matched",
                graph.vertexSet().size(), graph.edgeSet().size(), totalCves);

        return new AttackGraphResult(graph, nodeMap, totalCves);
    }

    /**
     * Determines if network traffic can flow from source tier to target tier.
     * Models enterprise firewall segmentation rules.
     */
    private boolean canReach(NetworkTier source, NetworkTier target) {
        return switch (source) {
            case EXTERNAL -> target == NetworkTier.DMZ;
            case DMZ -> target == NetworkTier.APPLICATION;
            case APPLICATION -> target == NetworkTier.DATA ||
                                target == NetworkTier.CROWN_JEWEL ||
                                target == NetworkTier.APPLICATION;
            case DATA -> target == NetworkTier.CROWN_JEWEL ||
                         target == NetworkTier.DATA;
            case CROWN_JEWEL -> false; // Crown jewels don't initiate outbound
        };
    }

    /**
     * Container for the attack graph build result.
     */
    public record AttackGraphResult(
            DirectedWeightedMultigraph<HostNode, ExploitEdge> graph,
            Map<String, HostNode> nodeMap,
            int totalCvesMatched
    ) {}
}

package com.netsentinel.ai;

import com.netsentinel.model.*;
import com.netsentinel.model.HostFingerprint.NetworkTier;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.YenKShortestPath;
import org.jgrapht.graph.DirectedWeightedMultigraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Tier 3: Multi-Hop Attack Path Analyzer.
 *
 * <p>Runs Yen's K-Shortest Paths algorithm on the attack graph to extract
 * the top K critical compromise vectors from external/DMZ entry points
 * to internal crown jewel servers.</p>
 *
 * <p>Mathematical model:</p>
 * <pre>
 *   Cumulative Risk = ∏ P(exploit_i) for each edge in the path
 *   Path Weight     = Σ (1 - P(exploit_i)) (lower = more dangerous)
 * </pre>
 */
@Component
public class AttackPathAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(AttackPathAnalyzer.class);

    /**
     * Finds the top-K most critical multi-hop attack paths.
     *
     * @param graph The scored attack graph
     * @param nodeMap Map of IP → HostNode for entry/target lookup
     * @param k Number of attack paths to compute
     * @return Ordered list of attack paths ranked by cumulative risk (highest first)
     */
    public List<AttackPath> findTopKAttackPaths(
            DirectedWeightedMultigraph<HostNode, ExploitEdge> graph,
            Map<String, HostNode> nodeMap,
            int k) {

        log.info("▶ Running Yen's K-Shortest Paths (K={})...", k);

        // Attacks start at the EXTERNAL attacker node, so a DMZ host is only on a path if the internet can
        // actually reach it (this keeps the path list consistent with RiskModel). Graphs without an
        // EXTERNAL node fall back to treating DMZ hosts as entry points.
        List<HostNode> entryPoints = graph.vertexSet().stream()
                .filter(n -> n.getFingerprint().tier() == NetworkTier.EXTERNAL)
                .collect(Collectors.toList());
        if (entryPoints.isEmpty()) {
            entryPoints = graph.vertexSet().stream()
                    .filter(n -> n.getFingerprint().tier() == NetworkTier.DMZ)
                    .collect(Collectors.toList());
        }

        List<HostNode> crownJewels = graph.vertexSet().stream()
                .filter(n -> n.getFingerprint().tier() == NetworkTier.CROWN_JEWEL)
                .collect(Collectors.toList());

        if (entryPoints.isEmpty() || crownJewels.isEmpty()) {
            log.warn("  No entry points or crown jewels found in graph");
            return List.of();
        }

        log.debug("  Entry points: {}", entryPoints.stream()
                .map(n -> n.getFingerprint().hostname()).collect(Collectors.joining(", ")));
        log.debug("  Crown jewels: {}", crownJewels.stream()
                .map(n -> n.getFingerprint().hostname()).collect(Collectors.joining(", ")));

        // Run Yen's algorithm for each entry→target pair
        // Yen's cost grows with the edge count, and parallel CVE edges between the same two hosts only
        // differ in probability: search a graph with the single most likely edge per host pair, so the
        // top-K are distinct host routes rather than CVE variants of one route.
        var routeGraph = new org.jgrapht.graph.SimpleDirectedWeightedGraph<HostNode, ExploitEdge>(ExploitEdge.class);
        graph.vertexSet().forEach(routeGraph::addVertex);
        for (ExploitEdge e : graph.edgeSet()) {
            HostNode s = graph.getEdgeSource(e), t = graph.getEdgeTarget(e);
            ExploitEdge best = routeGraph.getEdge(s, t);
            if (best == null || graph.getEdgeWeight(e) < routeGraph.getEdgeWeight(best)) {
                if (best != null) routeGraph.removeEdge(best);
                ExploitEdge copy = new ExploitEdge(e.getEdgeId(), e.getExploitedCve(), e.getProtocol(),
                        e.getTargetPort(), e.getExploitProbability(), e.getAccessLevel());
                routeGraph.addEdge(s, t, copy);
                routeGraph.setEdgeWeight(copy, graph.getEdgeWeight(e));
            }
        }
        YenKShortestPath<HostNode, ExploitEdge> yenAlg = new YenKShortestPath<>(routeGraph);
        List<AttackPath> allPaths = new ArrayList<>();
        int pathCounter = 0;

        for (HostNode entry : entryPoints) {
            for (HostNode target : crownJewels) {
                try {
                    List<GraphPath<HostNode, ExploitEdge>> kPaths =
                            yenAlg.getPaths(entry, target, k);

                    for (GraphPath<HostNode, ExploitEdge> gPath : kPaths) {
                        pathCounter++;
                        AttackPath attackPath = convertPath(pathCounter, gPath);
                        allPaths.add(attackPath);

                        log.debug("  Path #{}: {} hops, risk={:.4f} | {}",
                                pathCounter, attackPath.hopCount(),
                                attackPath.cumulativeRisk(),
                                gPath.getVertexList().stream()
                                        .map(n -> n.getFingerprint().hostname())
                                        .collect(Collectors.joining(" → ")));
                    }
                } catch (Exception e) {
                    log.debug("  No path from {} to {}",
                            entry.getFingerprint().hostname(),
                            target.getFingerprint().hostname());
                }
            }
        }

        // Sort by cumulative risk (highest = most dangerous first)
        allPaths.sort(Comparator.comparingDouble(AttackPath::cumulativeRisk).reversed());

        // Take top K overall
        List<AttackPath> topK = allPaths.stream()
                .limit(k)
                .collect(Collectors.toList());

        // Re-number paths by rank
        List<AttackPath> ranked = new ArrayList<>();
        for (int i = 0; i < topK.size(); i++) {
            AttackPath p = topK.get(i);
            ranked.add(new AttackPath(
                    i + 1, p.hops(), p.edges(), p.cumulativeRisk(),
                    p.entryPoint(), p.target(), p.bottleneckCve()
            ));
        }

        log.info("✓ Found {} attack paths — top {} selected by cumulative risk",
                allPaths.size(), ranked.size());

        for (AttackPath path : ranked) {
            log.info("  Attack Path #{}: Risk={} | {} → {} ({} hops)",
                    path.pathId(),
                    String.format("%.4f", path.cumulativeRisk()),
                    path.entryPoint().getFingerprint().hostname(),
                    path.target().getFingerprint().hostname(),
                    path.hopCount());
        }

        return ranked;
    }

    /**
     * Converts a JGraphT GraphPath into our AttackPath model.
     */
    private AttackPath convertPath(int id, GraphPath<HostNode, ExploitEdge> gPath) {
        List<HostNode> hops = gPath.getVertexList();
        List<ExploitEdge> edges = gPath.getEdgeList();

        // Calculate cumulative risk as product of edge exploit probabilities
        double cumulativeRisk = 1.0;
        CveRecord bottleneck = null;
        double highestEdgeProb = 0.0;

        for (ExploitEdge edge : edges) {
            cumulativeRisk *= edge.getExploitProbability();
            if (edge.getExploitedCve() != null && edge.getExploitProbability() > highestEdgeProb) {
                highestEdgeProb = edge.getExploitProbability();
                bottleneck = edge.getExploitedCve();
            }
        }

        return new AttackPath(
                id,
                hops,
                edges,
                cumulativeRisk,
                hops.get(0),
                hops.get(hops.size() - 1),
                bottleneck
        );
    }
}

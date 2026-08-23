package com.netsentinel.service;

import com.netsentinel.ai.AttackPathAnalyzer;
import com.netsentinel.ai.CompromiseScorer;
import com.netsentinel.ai.RemediationGenerator;
import com.netsentinel.graph.AttackGraphBuilder;
import com.netsentinel.graph.AttackGraphBuilder.AttackGraphResult;
import com.netsentinel.model.*;
import com.netsentinel.scanner.NetworkScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Central orchestrator for the NetSentinel four-tier pipeline.
 *
 * <p>Coordinates execution flow:</p>
 * <pre>
 *   Tier 1 (Scan) → Tier 2 (CVE Match + Graph) → Tier 3 (AI Score + Paths) → Tier 4 (Remediate)
 * </pre>
 *
 * <p>Broadcasts real-time progress events via WebSocket STOMP.</p>
 */
@Service
public class ScanOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestrator.class);

    private final NetworkScanner networkScanner;
    private final AttackGraphBuilder graphBuilder;
    private final CompromiseScorer compromiseScorer;
    private final AttackPathAnalyzer pathAnalyzer;
    private final RemediationGenerator remediationGenerator;
    private final SimpMessagingTemplate messagingTemplate;

    private final Map<String, ScanResult> scans = new ConcurrentHashMap<>();
    private final Map<String, AttackGraphResult> graphResults = new ConcurrentHashMap<>();

    public ScanOrchestrator(NetworkScanner networkScanner,
                            AttackGraphBuilder graphBuilder,
                            CompromiseScorer compromiseScorer,
                            AttackPathAnalyzer pathAnalyzer,
                            RemediationGenerator remediationGenerator,
                            SimpMessagingTemplate messagingTemplate) {
        this.networkScanner = networkScanner;
        this.graphBuilder = graphBuilder;
        this.compromiseScorer = compromiseScorer;
        this.pathAnalyzer = pathAnalyzer;
        this.remediationGenerator = remediationGenerator;
        this.messagingTemplate = messagingTemplate;
    }

    /**
     * Executes the full four-tier pipeline asynchronously.
     */
    public ScanResult executePipeline(ScanTarget target) {
        ScanResult result = new ScanResult(target);
        scans.put(result.getScanId(), result);

        log.info("═══════════════════════════════════════════════════════════");
        log.info("  NetSentinel-AI Pipeline — Scan ID: {}", result.getScanId());
        log.info("  Target: {}", target.cidr());
        log.info("═══════════════════════════════════════════════════════════");

        try {
            // ════════════════════════════════════════
            // TIER 1: Network Discovery
            // ════════════════════════════════════════
            result.setStatus(ScanResult.Status.SCANNING);
            result.setStatusMessage("Tier 1: Scanning subnet with virtual threads...");
            broadcastProgress(result);

            List<HostFingerprint> hosts = networkScanner.scan(target, host -> {
                broadcastEvent("host-discovered", Map.of(
                        "ip", host.ip(),
                        "hostname", host.hostname(),
                        "tier", host.tier().name(),
                        "ports", host.openPorts().size()
                ));
            }).get(); // Block until scan completes

            result.setDiscoveredHosts(hosts);
            log.info("  Tier 1 complete: {} hosts discovered", hosts.size());

            // ════════════════════════════════════════
            // TIER 2: CVE Enrichment & Graph Building
            // ════════════════════════════════════════
            result.setStatus(ScanResult.Status.ENRICHING);
            result.setStatusMessage("Tier 2: Matching CVEs and building attack graph...");
            broadcastProgress(result);

            AttackGraphResult graphResult = graphBuilder.buildGraph(hosts);
            graphResults.put(result.getScanId(), graphResult);

            result.setTotalCvesMatched(graphResult.totalCvesMatched());
            result.setGraphNodeCount(graphResult.graph().vertexSet().size());
            result.setGraphEdgeCount(graphResult.graph().edgeSet().size());

            log.info("  Tier 2 complete: {} nodes, {} edges, {} CVEs",
                    result.getGraphNodeCount(), result.getGraphEdgeCount(), result.getTotalCvesMatched());

            // ════════════════════════════════════════
            // TIER 3: AI Scoring & Path Analysis
            // ════════════════════════════════════════
            result.setStatus(ScanResult.Status.ANALYZING);
            result.setStatusMessage("Tier 3: Running DL4J compromise scorer and Yen's K-SP...");
            broadcastProgress(result);

            // Score edges with MLP
            compromiseScorer.scoreGraphEdges(graphResult.graph());

            // Find attack paths
            List<AttackPath> attackPaths = pathAnalyzer.findTopKAttackPaths(
                    graphResult.graph(), graphResult.nodeMap(), 5);

            result.setAttackPaths(attackPaths);

            for (AttackPath path : attackPaths) {
                broadcastEvent("attack-path-found", Map.of(
                        "pathId", path.pathId(),
                        "risk", String.format("%.4f", path.cumulativeRisk()),
                        "hops", path.hops().stream()
                                .map(h -> h.getFingerprint().hostname())
                                .collect(Collectors.toList()),
                        "bottleneck", path.bottleneckCve() != null ? path.bottleneckCve().cveId() : "none"
                ));
            }

            log.info("  Tier 3 complete: {} attack paths identified", attackPaths.size());

            // ════════════════════════════════════════
            // TIER 4: Remediation Generation
            // ════════════════════════════════════════
            result.setStatusMessage("Tier 4: Generating remediation playbook...");
            broadcastProgress(result);

            String playbook = remediationGenerator.generatePlaybook(attackPaths);
            result.setRemediationPlaybook(playbook);

            // Build graph data for frontend visualization
            result.setGraphData(buildGraphVisualizationData(graphResult, attackPaths));

            // ════════════════════════════════════════
            // COMPLETE
            // ════════════════════════════════════════
            result.setStatus(ScanResult.Status.COMPLETE);
            result.setEndTime(Instant.now());
            result.setStatusMessage("Pipeline complete in %dms".formatted(result.durationMs()));
            broadcastProgress(result);

            log.info("═══════════════════════════════════════════════════════════");
            log.info("  ✓ Pipeline complete — {} ms", result.durationMs());
            log.info("    Hosts: {} | CVEs: {} | Paths: {} | Risk: {}",
                    hosts.size(), result.getTotalCvesMatched(),
                    attackPaths.size(),
                    String.format("%.4f", result.getHighestPathRisk()));
            log.info("═══════════════════════════════════════════════════════════");

        } catch (Exception e) {
            log.error("Pipeline failed: {}", e.getMessage(), e);
            result.setStatus(ScanResult.Status.FAILED);
            result.setStatusMessage("Pipeline failed: " + e.getMessage());
            result.setEndTime(Instant.now());
            broadcastProgress(result);
        }

        return result;
    }

    /**
     * Retrieves a scan result by ID.
     */
    public Optional<ScanResult> getScan(String scanId) {
        return Optional.ofNullable(scans.get(scanId));
    }

    /**
     * Returns all scan results.
     */
    public Collection<ScanResult> getAllScans() {
        return scans.values();
    }

    /**
     * Builds Cytoscape.js-compatible JSON data for the attack graph visualization.
     */
    private Map<String, Object> buildGraphVisualizationData(
            AttackGraphResult graphResult, List<AttackPath> attackPaths) {

        var graph = graphResult.graph();
        List<Map<String, Object>> elements = new ArrayList<>();

        // Collect all edges that are part of attack paths for highlighting
        Set<String> attackPathEdgeIds = new HashSet<>();
        Set<String> attackPathNodeIds = new HashSet<>();
        for (AttackPath path : attackPaths) {
            for (ExploitEdge edge : path.edges()) {
                attackPathEdgeIds.add(edge.getEdgeId());
            }
            for (HostNode node : path.hops()) {
                attackPathNodeIds.add(node.getId());
            }
        }

        // Nodes
        for (HostNode node : graph.vertexSet()) {
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("id", node.getId());
            data.put("label", node.getFingerprint().displayLabel());
            data.put("ip", node.getFingerprint().ip());
            data.put("tier", node.getFingerprint().tier().name());
            data.put("criticality", node.getFingerprint().criticality());
            data.put("riskScore", Math.round(node.getRiskScore() * 100.0) / 100.0);
            data.put("compromiseProb", Math.round(node.getCompromiseProbability() * 1000.0) / 1000.0);
            data.put("vulnCount", node.getVulnerabilities().size());
            data.put("openPorts", node.getFingerprint().openPorts());
            data.put("os", node.getFingerprint().osTag());
            data.put("onAttackPath", attackPathNodeIds.contains(node.getId()));

            List<Map<String, Object>> vulnDetails = node.getVulnerabilities().stream()
                    .map(cve -> {
                        Map<String, Object> v = new LinkedHashMap<>();
                        v.put("cveId", cve.cveId());
                        v.put("cvss", cve.cvssBaseScore());
                        v.put("severity", cve.severity());
                        v.put("description", cve.description());
                        return v;
                    })
                    .collect(Collectors.toList());
            data.put("vulnerabilities", vulnDetails);

            elements.add(Map.of("group", "nodes", "data", data));
        }

        // Edges
        for (ExploitEdge edge : graph.edgeSet()) {
            HostNode source = graph.getEdgeSource(edge);
            HostNode target = graph.getEdgeTarget(edge);

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("id", edge.getEdgeId());
            data.put("source", source.getId());
            data.put("target", target.getId());
            data.put("exploitProb", Math.round(edge.getExploitProbability() * 1000.0) / 1000.0);
            data.put("cve", edge.getExploitedCve() != null ? edge.getExploitedCve().cveId() : null);
            data.put("cvss", edge.getExploitedCve() != null ? edge.getExploitedCve().cvssBaseScore() : 0);
            data.put("protocol", edge.getProtocol());
            data.put("port", edge.getTargetPort());
            data.put("onAttackPath", attackPathEdgeIds.contains(edge.getEdgeId()));

            elements.add(Map.of("group", "edges", "data", data));
        }

        // Attack paths summary
        List<Map<String, Object>> pathSummaries = attackPaths.stream()
                .map(p -> {
                    Map<String, Object> ps = new LinkedHashMap<>();
                    ps.put("pathId", p.pathId());
                    ps.put("risk", Math.round(p.cumulativeRisk() * 10000.0) / 10000.0);
                    ps.put("hopCount", p.hopCount());
                    ps.put("hops", p.hops().stream()
                            .map(h -> h.getFingerprint().hostname())
                            .collect(Collectors.toList()));
                    ps.put("bottleneck", p.bottleneckCve() != null ?
                            Map.of("cveId", p.bottleneckCve().cveId(),
                                   "cvss", p.bottleneckCve().cvssBaseScore(),
                                   "severity", p.bottleneckCve().severity(),
                                   "description", p.bottleneckCve().description()) : null);
                    ps.put("edges", p.edges().stream()
                            .map(ExploitEdge::getEdgeId)
                            .collect(Collectors.toList()));
                    return ps;
                })
                .collect(Collectors.toList());

        return Map.of(
                "elements", elements,
                "attackPaths", pathSummaries
        );
    }

    private void broadcastProgress(ScanResult result) {
        try {
            messagingTemplate.convertAndSend("/topic/scan-progress", Map.of(
                    "scanId", result.getScanId(),
                    "status", result.getStatus().name(),
                    "message", result.getStatusMessage(),
                    "durationMs", result.durationMs()
            ));
        } catch (Exception e) {
            log.debug("WebSocket broadcast skipped: {}", e.getMessage());
        }
    }

    private void broadcastEvent(String eventType, Map<String, Object> payload) {
        try {
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("type", eventType);
            event.putAll(payload);
            messagingTemplate.convertAndSend("/topic/scan-events", event);
        } catch (Exception e) {
            log.debug("WebSocket event broadcast skipped: {}", e.getMessage());
        }
    }
}

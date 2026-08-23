package com.netsentinel.api;

import com.netsentinel.model.ScanResult;
import com.netsentinel.model.ScanTarget;
import com.netsentinel.service.ScanOrchestrator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Tier 4: REST API controller for the NetSentinel Control Plane.
 *
 * <p>Exposes endpoints for initiating scans, querying results,
 * and retrieving attack graphs and remediation playbooks.</p>
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ScanController {

    private static final Logger log = LoggerFactory.getLogger(ScanController.class);
    private final ScanOrchestrator orchestrator;
    private final ExecutorService scanExecutor = Executors.newVirtualThreadPerTaskExecutor();

    public ScanController(ScanOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    /**
     * POST /api/scan — Initiate a new vulnerability scan.
     *
     * Request body: { "cidr": "192.168.10.0/24" }
     */
    @PostMapping("/scan")
    public ResponseEntity<Map<String, Object>> initiateScan(@RequestBody Map<String, String> request) {
        String cidr = request.getOrDefault("cidr", "192.168.10.0/24");
        log.info("API: Scan requested for {}", cidr);

        ScanTarget target = new ScanTarget(cidr);

        // Execute pipeline asynchronously on a virtual thread
        ScanResult[] resultHolder = new ScanResult[1];
        var future = scanExecutor.submit(() -> {
            resultHolder[0] = orchestrator.executePipeline(target);
        });

        // Wait briefly for the scan to start and get its ID
        try { Thread.sleep(100); } catch (InterruptedException ignored) {}

        // Find the latest scan
        ScanResult latestScan = orchestrator.getAllScans().stream()
                .reduce((first, second) -> second)
                .orElse(null);

        String scanId = latestScan != null ? latestScan.getScanId() : "unknown";

        return ResponseEntity.ok(Map.of(
                "scanId", scanId,
                "status", "INITIATED",
                "target", cidr,
                "message", "Scan pipeline started. Monitor via WebSocket /topic/scan-progress"
        ));
    }

    /**
     * POST /api/scan/sync — Initiate a scan and wait for completion.
     */
    @PostMapping("/scan/sync")
    public ResponseEntity<Map<String, Object>> initiateScanSync(@RequestBody Map<String, String> request) {
        String cidr = request.getOrDefault("cidr", "192.168.10.0/24");
        log.info("API: Synchronous scan requested for {}", cidr);

        ScanTarget target = new ScanTarget(cidr);
        ScanResult result = orchestrator.executePipeline(target);

        return ResponseEntity.ok(buildScanResponse(result));
    }

    /**
     * GET /api/scan/{id}/status — Get scan status.
     */
    @GetMapping("/scan/{id}/status")
    public ResponseEntity<?> getScanStatus(@PathVariable String id) {
        return orchestrator.getScan(id)
                .map(scan -> ResponseEntity.ok(Map.of(
                        "scanId", scan.getScanId(),
                        "status", scan.getStatus().name(),
                        "message", scan.getStatusMessage(),
                        "durationMs", scan.durationMs()
                )))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/scan/{id}/graph — Get attack graph visualization data.
     */
    @GetMapping("/scan/{id}/graph")
    public ResponseEntity<?> getGraphData(@PathVariable String id) {
        return orchestrator.getScan(id)
                .filter(scan -> scan.getGraphData() != null)
                .map(scan -> ResponseEntity.ok(scan.getGraphData()))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/scan/{id}/paths — Get top-K attack paths.
     */
    @GetMapping("/scan/{id}/paths")
    public ResponseEntity<?> getAttackPaths(@PathVariable String id) {
        return orchestrator.getScan(id)
                .filter(scan -> scan.getAttackPaths() != null)
                .map(scan -> {
                    List<Map<String, Object>> paths = scan.getAttackPaths().stream()
                            .map(p -> {
                                Map<String, Object> pathMap = new LinkedHashMap<>();
                                pathMap.put("pathId", p.pathId());
                                pathMap.put("cumulativeRisk", p.cumulativeRisk());
                                pathMap.put("hopCount", p.hopCount());
                                pathMap.put("route", p.describe());
                                pathMap.put("bottleneckCve", p.bottleneckCve() != null ?
                                        p.bottleneckCve().cveId() : null);
                                return pathMap;
                            })
                            .toList();
                    return ResponseEntity.ok(Map.of("paths", paths));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/scan/{id}/remediation — Get generated remediation playbook.
     */
    @GetMapping("/scan/{id}/remediation")
    public ResponseEntity<?> getRemediation(@PathVariable String id) {
        return orchestrator.getScan(id)
                .filter(scan -> scan.getRemediationPlaybook() != null)
                .map(scan -> ResponseEntity.ok(Map.of(
                        "scanId", scan.getScanId(),
                        "playbook", scan.getRemediationPlaybook()
                )))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/scans — List all scans.
     */
    @GetMapping("/scans")
    public ResponseEntity<List<Map<String, Object>>> listScans() {
        List<Map<String, Object>> scanList = orchestrator.getAllScans().stream()
                .map(scan -> {
                    Map<String, Object> s = new LinkedHashMap<>();
                    s.put("scanId", scan.getScanId());
                    s.put("target", scan.getTarget().cidr());
                    s.put("status", scan.getStatus().name());
                    s.put("durationMs", scan.durationMs());
                    return s;
                })
                .toList();
        return ResponseEntity.ok(scanList);
    }

    private Map<String, Object> buildScanResponse(ScanResult result) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("scanId", result.getScanId());
        response.put("status", result.getStatus().name());
        response.put("target", result.getTarget().cidr());
        response.put("durationMs", result.durationMs());
        response.put("hostsDiscovered", result.getDiscoveredHosts() != null ? result.getDiscoveredHosts().size() : 0);
        response.put("cvesMatched", result.getTotalCvesMatched());
        response.put("graphNodes", result.getGraphNodeCount());
        response.put("graphEdges", result.getGraphEdgeCount());
        response.put("attackPaths", result.getAttackPaths() != null ? result.getAttackPaths().size() : 0);
        response.put("highestRisk", result.getHighestPathRisk());
        response.put("message", result.getStatusMessage());
        return response;
    }
}

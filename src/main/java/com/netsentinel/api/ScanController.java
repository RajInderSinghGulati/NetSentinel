package com.netsentinel.api;

import com.netsentinel.ai.PatchOptimizer;
import com.netsentinel.ai.PatchUnit;
import com.netsentinel.ai.RemediationGenerator;
import com.netsentinel.ai.RiskModel;
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
    private final RiskModel riskModel;
    private final PatchOptimizer patchOptimizer;
    private final RemediationGenerator remediationGenerator;
    private final ExecutorService scanExecutor = Executors.newVirtualThreadPerTaskExecutor();

    public ScanController(ScanOrchestrator orchestrator, RiskModel riskModel, PatchOptimizer patchOptimizer,
                          RemediationGenerator remediationGenerator) {
        this.orchestrator = orchestrator;
        this.riskModel = riskModel;
        this.patchOptimizer = patchOptimizer;
        this.remediationGenerator = remediationGenerator;
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

        ScanTarget target = new ScanTarget(cidr, request.get("mode"));

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

        ScanTarget target = new ScanTarget(cidr, request.get("mode"));
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
     * GET /api/scan/{id}/remediation: remediation artifacts. Without parameters this is the plan chosen
     * automatically during the scan; with {@code strategy} and {@code budget} the artifacts are generated
     * for that plan instead.
     */
    @GetMapping("/scan/{id}/remediation")
    public ResponseEntity<?> getRemediation(@PathVariable String id,
                                            @RequestParam(required = false) PatchOptimizer.Strategy strategy,
                                            @RequestParam(required = false) Integer budget) {
        return orchestrator.getScan(id)
                .filter(scan -> scan.getRemediation() != null)
                .map(scan -> {
                    PatchOptimizer.Plan plan = scan.getPatchPlan();
                    RemediationGenerator.Remediation r = scan.getRemediation();
                    String playbook = scan.getRemediationPlaybook();
                    if (strategy != null) {
                        var graph = orchestrator.getGraphResult(id).orElse(null);
                        if (graph == null) return ResponseEntity.notFound().build();
                        var compiled = riskModel.compile(graph.graph(), RiskModel.Variant.CORRELATED);
                        int b = Math.max(0, Math.min(budget != null ? budget : plan.budget(), 10));
                        plan = patchOptimizer.plan(compiled, strategy, b, 42L);
                        if (!plan.computed()) return ResponseEntity.unprocessableEntity()
                                .body(Map.of("error", "search space too large for " + strategy));
                        r = remediationGenerator.generate(plan.patches(), plan.strategy().name(),
                                plan.budget(), scan.getCrownJewelRisk(), plan.risk());
                        playbook = r.combined();
                    }
                    Map<String, Object> body = new LinkedHashMap<>();
                    body.put("scanId", scan.getScanId());
                    body.put("playbook", playbook);
                    body.put("ansible", r.ansible());
                    body.put("inventory", r.inventory());
                    body.put("bash", r.bash());
                    body.put("report", r.report());
                    body.put("strategy", plan.strategy().name());
                    body.put("budget", plan.budget());
                    body.put("riskBefore", scan.getCrownJewelRisk());
                    body.put("riskAfter", plan.risk());
                    body.put("patches", plan.patches().stream().map(PatchUnit::label).toList());
                    return ResponseEntity.ok(body);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/scan/{id}/verify?strategy=OPTIMAL&budget=3: apply the plan to the inventory and re-scan.
     */
    @GetMapping("/scan/{id}/verify")
    public ResponseEntity<?> verify(@PathVariable String id,
                                    @RequestParam(defaultValue = "OPTIMAL") PatchOptimizer.Strategy strategy,
                                    @RequestParam(defaultValue = "3") int budget) {
        return orchestrator.verifyPlan(id, strategy, Math.max(0, Math.min(budget, 10)))
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/scan/{id}/optimize?maxBudget=6 — Risk-vs-budget curves for every patching strategy.
     *
     * <p>Risk is the criticality-weighted expected number of compromised crown jewels. A patch is
     * "upgrade product P on host H". OPTIMAL is null where the exhaustive search was too large.
     * With {@code mcTrials > 0}, each plan's risk is also estimated by Monte Carlo sampling
     * ({@code mcRisk}) to validate the analytic model.</p>
     */
    @GetMapping("/scan/{id}/optimize")
    public ResponseEntity<?> optimize(@PathVariable String id,
                                      @RequestParam(defaultValue = "6") int maxBudget,
                                      @RequestParam(defaultValue = "0") int mcTrials) {
        int budget = Math.max(0, Math.min(maxBudget, 10));
        return orchestrator.getGraphResult(id).map(gr -> {
            var compiled = riskModel.compile(gr.graph(), RiskModel.Variant.CORRELATED);
            var curve = patchOptimizer.curve(compiled, budget, 42L);
            double baseline = patchOptimizer.baselineRisk(compiled);

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("scanId", id);
            body.put("baselineRisk", baseline);
            body.put("patchUnits", compiled.units.size());
            List<Map<String, Object>> rows = new ArrayList<>();
            for (int b = 0; b <= budget; b++) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("budget", b);
                for (PatchOptimizer.Strategy s : PatchOptimizer.Strategy.values()) {
                    PatchOptimizer.Plan plan = curve.get(s).get(b);
                    Map<String, Object> cell = new LinkedHashMap<>();
                    cell.put("risk", plan.computed() ? plan.risk() : null);
                    cell.put("reductionPct", plan.computed() && baseline > 0
                            ? 100.0 * (1.0 - plan.risk() / baseline) : null);
                    cell.put("patches", plan.patches().stream().map(PatchUnit::label).toList());
                    if (mcTrials > 0 && plan.computed() && s != PatchOptimizer.Strategy.RANDOM) {
                        boolean[] removed = new boolean[compiled.units.size()];
                        plan.patches().forEach(u -> removed[u.index()] = true);
                        double[] pm = riskModel.monteCarlo(compiled, removed, mcTrials, 7L);
                        cell.put("mcRisk", riskModel.crownJewelRisk(compiled, pm));
                    }
                    row.put(s.name(), cell);
                }
                rows.add(row);
            }
            body.put("curve", rows);
            return ResponseEntity.ok(body);
        }).orElse(ResponseEntity.notFound().build());
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
        response.put("crownJewelRisk", result.getCrownJewelRisk());
        response.put("message", result.getStatusMessage());
        return response;
    }
}

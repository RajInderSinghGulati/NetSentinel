package com.netsentinel.ai;

import com.netsentinel.model.ScanResult;
import com.netsentinel.model.ScanTarget;
import com.netsentinel.service.ScanOrchestrator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Full pipeline on the simulated network: the optimizer's predicted risk must equal the risk obtained
 * by actually removing the patched products from the inventory and rebuilding everything from scratch.
 */
@SpringBootTest(properties = {"netsentinel.nvd.offline-only=true", "netsentinel.scan.simulated-delay-ms=0"})
class RemediationEndToEndTest {

    @Autowired
    ScanOrchestrator orchestrator;

    static ScanResult scan;

    @BeforeAll
    static void noop() {}

    private ScanResult scan() {
        if (scan == null) scan = orchestrator.executePipeline(new ScanTarget("192.168.10.0/24"));
        return scan;
    }

    @Test
    void pipelineProducesAPlanAndWellFormedArtifacts() {
        ScanResult s = scan();
        assertEquals(ScanResult.Status.COMPLETE, s.getStatus());
        assertTrue(s.getCrownJewelRisk() > 0);
        assertNotNull(s.getPatchPlan());
        assertTrue(s.getPatchPlan().patches().size() <= 3);
        assertTrue(s.getPatchPlan().risk() < s.getCrownJewelRisk());
        RemediationGeneratorTest.assertPlaybookWellFormed(s.getRemediation().ansible(), s.getRemediation().inventory());
    }

    @Test
    void rescanAfterApplyingEachStrategyMatchesThePrediction() {
        ScanResult s = scan();
        for (PatchOptimizer.Strategy strat : new PatchOptimizer.Strategy[]{
                PatchOptimizer.Strategy.CVSS_FIRST, PatchOptimizer.Strategy.EXPLOIT_PROB_FIRST,
                PatchOptimizer.Strategy.GREEDY, PatchOptimizer.Strategy.OPTIMAL}) {
            for (int budget : new int[]{1, 2, 3, 5}) {
                var v = orchestrator.verifyPlan(s.getScanId(), strat, budget).orElseThrow();
                assertEquals(v.predictedRisk(), v.rescanRisk(), 1e-9, strat + " budget " + budget);
                assertTrue(v.rescanRisk() <= v.baselineRisk() + 1e-9);
            }
        }
    }

    @Test
    void optimalPlanRemovesAttackPathsOnRescan() {
        ScanResult s = scan();
        var v = orchestrator.verifyPlan(s.getScanId(), PatchOptimizer.Strategy.OPTIMAL, 3).orElseThrow();
        assertTrue(v.pathsBefore() > 0);
        assertEquals(0, v.pathsAfter(), "all attack paths to crown jewels should be gone");
        assertEquals(0.0, v.rescanRisk(), 1e-9);
    }
}

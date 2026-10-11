package com.netsentinel.ai;

import com.netsentinel.model.CveRecord;
import com.netsentinel.model.ExploitEdge;
import com.netsentinel.model.HostFingerprint;
import com.netsentinel.model.HostFingerprint.NetworkTier;
import com.netsentinel.model.HostNode;
import org.jgrapht.graph.DirectedWeightedMultigraph;
import org.junit.jupiter.api.Test;

import com.netsentinel.cve.CveDatabase;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Hand-computable graphs for the risk model and the patch optimizer. */
class RiskModelTest {

    // ------------------------------------------------------------------ builders

    static CveRecord cve(String id, double cvss) {
        return new CveRecord(id, id, cvss, CveRecord.AttackVector.NETWORK, CveRecord.AttackComplexity.LOW,
                CveRecord.PrivilegesRequired.NONE, CveRecord.UserInteraction.NONE, "CWE-1",
                List.of("cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"), true, false);
    }

    static HostNode node(String id, NetworkTier tier, int criticality) {
        return new HostNode(id, new HostFingerprint(id, id, List.of(80), Map.of(), List.of(), "os", tier, criticality));
    }

    static int edgeCounter = 0;

    static void edge(DirectedWeightedMultigraph<HostNode, ExploitEdge> g, HostNode s, HostNode t, CveRecord c, double p) {
        g.addEdge(s, t, new ExploitEdge("e" + (edgeCounter++), c, "TCP", 80, p, "remote"));
    }

    static DirectedWeightedMultigraph<HostNode, ExploitEdge> graph(HostNode... nodes) {
        var g = new DirectedWeightedMultigraph<HostNode, ExploitEdge>(ExploitEdge.class);
        for (HostNode n : nodes) g.addVertex(n);
        return g;
    }

    final RiskModel model = new RiskModel();

    double pOf(RiskModel.Compiled c, double[] p, String id) {
        for (int i = 0; i < c.nodes().size(); i++) if (c.nodes().get(i).getId().equals(id)) return p[i];
        throw new AssertionError(id);
    }

    // ------------------------------------------------------------------ risk model

    @Test
    void chainMultipliesProbabilities() {
        HostNode ext = node("ext", NetworkTier.EXTERNAL, 0), a = node("a", NetworkTier.DMZ, 3), j = node("j", NetworkTier.CROWN_JEWEL, 10);
        var g = graph(ext, a, j);
        edge(g, ext, a, cve("A", 5), 0.5);
        edge(g, a, j, cve("J", 5), 0.4);
        for (var v : RiskModel.Variant.values()) {
            var c = model.compile(g, v);
            double[] p = model.evaluate(c, null);
            assertEquals(0.5, pOf(c, p, "a"), 1e-9);
            assertEquals(0.2, pOf(c, p, "j"), 1e-9);
            assertEquals(0.2, model.crownJewelRisk(c, p), 1e-9); // criticality 10 -> weight 1
        }
    }

    @Test
    void sharedExploitIsOneEventInCorrelatedModelButManyInNoisyOr() {
        HostNode ext = node("ext", NetworkTier.EXTERNAL, 0), a = node("a", NetworkTier.DMZ, 3),
                b = node("b", NetworkTier.DMZ, 3), j = node("j", NetworkTier.CROWN_JEWEL, 10);
        var g = graph(ext, a, b, j);
        edge(g, ext, a, cve("A", 5), 1.0);
        edge(g, ext, b, cve("B", 5), 1.0);
        CveRecord x = cve("X", 5);
        edge(g, a, j, x, 0.5);
        edge(g, b, j, x, 0.5);

        var noisy = model.compile(g, RiskModel.Variant.NOISY_OR);
        var corr = model.compile(g, RiskModel.Variant.CORRELATED);
        assertEquals(0.75, pOf(noisy, model.evaluate(noisy, null), "j"), 1e-9);
        assertEquals(0.50, pOf(corr, model.evaluate(corr, null), "j"), 1e-9);

        // Monte Carlo reproduces both semantics
        assertEquals(0.75, pOf(noisy, model.monteCarlo(noisy, null, 40_000, 1), "j"), 0.01);
        assertEquals(0.50, pOf(corr, model.monteCarlo(corr, null, 40_000, 1), "j"), 0.01);
    }

    @Test
    void diamondMatchesClosedFormAndMonteCarlo() {
        HostNode ext = node("ext", NetworkTier.EXTERNAL, 0), a = node("a", NetworkTier.DMZ, 3),
                b = node("b", NetworkTier.DMZ, 3), j = node("j", NetworkTier.CROWN_JEWEL, 10);
        var g = graph(ext, a, b, j);
        edge(g, ext, a, cve("A", 5), 0.6);
        edge(g, ext, b, cve("B", 5), 0.6);
        CveRecord x = cve("X", 5);
        edge(g, a, j, x, 0.5);
        edge(g, b, j, x, 0.5);
        var c = model.compile(g, RiskModel.Variant.CORRELATED);
        double expected = 0.5 * (1 - 0.4 * 0.4); // X works AND (A or B compromised)
        assertEquals(expected, pOf(c, model.evaluate(c, null), "j"), 1e-9);
        assertEquals(expected, pOf(c, model.monteCarlo(c, null, 60_000, 7), "j"), 0.01);
    }

    /**
     * With a cycle a <-> b the fixed point converges but over-counts self-support: b is only reachable
     * through a, so the true P(j) = 0.5^3 = 0.125, while the analytic equations give 1/7.
     */
    @Test
    void cyclesConvergeAndOverestimateAsDocumented() {
        HostNode ext = node("ext", NetworkTier.EXTERNAL, 0), a = node("a", NetworkTier.APPLICATION, 3),
                b = node("b", NetworkTier.APPLICATION, 3), j = node("j", NetworkTier.CROWN_JEWEL, 10);
        var g = graph(ext, a, b, j);
        edge(g, ext, a, cve("A", 5), 0.5);
        edge(g, a, b, cve("B", 5), 0.5);
        edge(g, b, a, cve("A2", 5), 0.5); // cycle a <-> b
        edge(g, b, j, cve("J", 5), 0.5);
        var c = model.compile(g, RiskModel.Variant.CORRELATED);
        double analytic = pOf(c, model.evaluate(c, null), "j");
        double sampled = pOf(c, model.monteCarlo(c, null, 80_000, 3), "j");
        assertEquals(1.0 / 7.0, analytic, 1e-9);
        assertEquals(0.125, sampled, 0.01);
        assertTrue(analytic > sampled, "analytic fixed point is an upper bound on cyclic graphs");
    }

    @Test
    void patchingRequiresAllUnitsThatCarryTheCve() {
        HostNode ext = node("ext", NetworkTier.EXTERNAL, 0), j = node("j", NetworkTier.CROWN_JEWEL, 10);
        CveRecord x = cve("X", 9);
        j.addVulnerability(x, "cpe:2.3:a:v:one:1:*:*:*:*:*:*:*"); // same CVE reached via two products
        j.addVulnerability(x, "cpe:2.3:a:v:two:1:*:*:*:*:*:*:*");
        var g = graph(ext, j);
        edge(g, ext, j, x, 0.8);
        var c = model.compile(g, RiskModel.Variant.CORRELATED);
        assertEquals(2, c.units.size());
        assertEquals(0.8, model.crownJewelRisk(c, new boolean[]{false, false}), 1e-9);
        assertEquals(0.8, model.crownJewelRisk(c, new boolean[]{true, false}), 1e-9);
        assertEquals(0.0, model.crownJewelRisk(c, new boolean[]{true, true}), 1e-9);
    }

    // ------------------------------------------------------------------ optimizer

    /** ext -> w1(A) , ext -> w2(B), w1 -> j(C), w2 -> j(C). Patching j's product is the chokepoint. */
    private DirectedWeightedMultigraph<HostNode, ExploitEdge> chokepointGraph() {
        HostNode ext = node("ext", NetworkTier.EXTERNAL, 0), w1 = node("a-w1", NetworkTier.DMZ, 3),
                w2 = node("b-w2", NetworkTier.DMZ, 3), j = node("c-j", NetworkTier.CROWN_JEWEL, 10);
        CveRecord a = cve("A", 9.9), b = cve("B", 3.0), cc = cve("C", 4.0);
        w1.addVulnerability(a, "cpe:2.3:a:v:w1:1:*:*:*:*:*:*:*");
        w2.addVulnerability(b, "cpe:2.3:a:v:w2:1:*:*:*:*:*:*:*");
        j.addVulnerability(cc, "cpe:2.3:a:v:j:1:*:*:*:*:*:*:*");
        var g = graph(ext, w1, w2, j);
        edge(g, ext, w1, a, 0.9);
        edge(g, ext, w2, b, 0.9);
        edge(g, w1, j, cc, 0.9);
        edge(g, w2, j, cc, 0.9);
        return g;
    }

    @Test
    void optimizerFindsChokepointWhereCvssFirstDoesNot() {
        var optimizer = new PatchOptimizer(model);
        var c = model.compile(chokepointGraph(), RiskModel.Variant.CORRELATED);
        double base = optimizer.baselineRisk(c);
        assertEquals(0.9 * (1 - 0.1 * 0.1), base, 1e-9);

        var cvss = optimizer.plan(c, PatchOptimizer.Strategy.CVSS_FIRST, 1, 1);
        var greedy = optimizer.plan(c, PatchOptimizer.Strategy.GREEDY, 1, 1);
        var best = optimizer.plan(c, PatchOptimizer.Strategy.OPTIMAL, 1, 1);

        assertEquals("a-w1", cvss.patches().get(0).hostId());      // highest CVSS, wrong place
        assertEquals(0.9 * 0.9, cvss.risk(), 1e-9);                  // other route still open
        assertEquals("c-j", best.patches().get(0).hostId());
        assertEquals(0.0, best.risk(), 1e-12);
        assertEquals(0.0, greedy.risk(), 1e-12);
        assertTrue(base > cvss.risk() && cvss.risk() > best.risk());
    }

    @Test
    void optimalIsNeverWorseThanOtherStrategiesAndMonotoneInBudget() {
        var optimizer = new PatchOptimizer(model);
        var c = model.compile(chokepointGraph(), RiskModel.Variant.CORRELATED);
        double prev = Double.POSITIVE_INFINITY;
        for (int b = 0; b <= 3; b++) {
            double opt = optimizer.plan(c, PatchOptimizer.Strategy.OPTIMAL, b, 1).risk();
            for (var s : PatchOptimizer.Strategy.values()) {
                assertTrue(opt <= optimizer.plan(c, s, b, 1).risk() + 1e-12, s + " at budget " + b);
            }
            assertTrue(opt <= prev + 1e-12);
            prev = opt;
        }
        assertEquals(0.0, optimizer.plan(c, PatchOptimizer.Strategy.OPTIMAL, 3, 1).risk(), 1e-12);
    }

    @Test
    void optimalUsesAtMostBudgetAndPrefersTheSmallestSet() {
        var optimizer = new PatchOptimizer(model);
        var c = model.compile(chokepointGraph(), RiskModel.Variant.CORRELATED);
        var plan = optimizer.plan(c, PatchOptimizer.Strategy.OPTIMAL, 3, 1);
        assertEquals(1, plan.patches().size(), "one patch already reaches zero risk");
        assertEquals("c-j", plan.patches().get(0).hostId());
        assertTrue(optimizer.plan(c, PatchOptimizer.Strategy.OPTIMAL, 0, 1).patches().isEmpty());
    }

    @Test
    void searchSpaceGuard() {
        assertFalse(PatchOptimizer.binomialExceeds(10, 3, 1000));
        assertTrue(PatchOptimizer.binomialExceeds(60, 10, 3_000_000L));
    }

    // ------------------------------------------------------------------ fixed-in semantics

    private CompromiseScorer scorer() {
        CompromiseScorer sc = new CompromiseScorer();
        ReflectionTestUtils.setField(sc, "modelPath", "/model/exploit_model.json");
        ReflectionTestUtils.setField(sc, "knownExploitedProbability", 0.9);
        try {
            sc.initialize();
        } catch (java.io.IOException e) {
            throw new AssertionError(e);
        }
        return sc;
    }

    private static CveRecord rangedCve(String id, String bounds) {
        return new CveRecord(id, id, 9.8, CveRecord.AttackVector.NETWORK, CveRecord.AttackComplexity.LOW,
                CveRecord.PrivilegesRequired.NONE, CveRecord.UserInteraction.NONE, "CWE-78",
                List.of("cpe:2.3:a:acme:srv:*:*:*:*:*:*:*:*#" + bounds), true, false);
    }

    private static CveDatabase dbReturning(Map<String, List<CveRecord>> byTargetVersion) {
        return new CveDatabase() {
            @Override
            public List<CveRecord> findByCpe(String cpe) {
                return byTargetVersion.getOrDefault(cpe.split(":")[5], List.of());
            }

            @Override
            public List<CveRecord> findAll() {
                return List.of();
            }
        };
    }

    private DirectedWeightedMultigraph<HostNode, ExploitEdge> singleHost(CveRecord installed, double p) {
        HostNode ext = node("ext", NetworkTier.EXTERNAL, 0), w = node("w", NetworkTier.CROWN_JEWEL, 10);
        w.addVulnerability(installed, "cpe:2.3:a:acme:srv:1.0:*:*:*:*:*:*:*");
        var g = graph(ext, w);
        edge(g, ext, w, installed, p);
        return g;
    }

    @Test
    void upgradeRemovesFixedCvesAndAddsCvesOfTheNewVersion() {
        CveRecord a = rangedCve("A", "<2.0");          // fixed by upgrading to 2.0
        CveRecord b = rangedCve("B", ">=2.0,<3.0");    // only affects the newer version
        CompromiseScorer sc = scorer();
        var model2 = new RiskModel(dbReturning(Map.of("2.0", List.of(b))), sc);
        var g = singleHost(a, 0.9);

        var c = model2.compile(g, RiskModel.Variant.CORRELATED);
        assertEquals(1, c.units.size());
        PatchUnit u = c.units.get(0);
        assertEquals("2.0", u.targetVersion());
        assertEquals(java.util.Set.of("A"), u.fixedCveIds());
        assertEquals(1, u.introduced().size());

        double before = model2.crownJewelRisk(c, new boolean[]{false});
        double after = model2.crownJewelRisk(c, new boolean[]{true});
        assertEquals(0.9, before, 1e-9);
        assertEquals(sc.scoreEdge(b, 10), after, 1e-9, "after the upgrade only B can be exploited");
        assertTrue(after < before);
    }

    @Test
    void residualCveKeepsRiskAndUnpatchableUnitDoesNothing() {
        CveRecord stays = rangedCve("ALL", "<99.0");    // still affects the next candidate? no: fixed only at 99.0
        CveRecord open = new CveRecord("OPEN", "x", 9.8, CveRecord.AttackVector.NETWORK, CveRecord.AttackComplexity.LOW,
                CveRecord.PrivilegesRequired.NONE, CveRecord.UserInteraction.NONE, "CWE-1",
                List.of("cpe:2.3:a:acme:srv:*:*:*:*:*:*:*:*"), true, false);   // all versions: unfixable
        var m = new RiskModel(dbReturning(Map.of("99.0", List.of(open))), scorer());
        var g = singleHost(open, 0.7);
        var c = m.compile(g, RiskModel.Variant.CORRELATED);
        PatchUnit u = c.units.get(0);
        assertFalse(u.fixesAnything());
        assertNull(u.targetVersion());
        assertEquals(0.7, m.crownJewelRisk(c, new boolean[]{true}), 1e-9, "unfixable CVE keeps the risk");

        // a CVE that is fixed at 99.0 alongside an unfixable one: target 99.0, residual stays
        var g2 = graph(node("ext", NetworkTier.EXTERNAL, 0), node("w", NetworkTier.CROWN_JEWEL, 10));
        HostNode ext = g2.vertexSet().stream().filter(n -> n.getId().equals("ext")).findFirst().orElseThrow();
        HostNode w = g2.vertexSet().stream().filter(n -> n.getId().equals("w")).findFirst().orElseThrow();
        w.addVulnerability(stays, "cpe:2.3:a:acme:srv:1.0:*:*:*:*:*:*:*");
        w.addVulnerability(open, "cpe:2.3:a:acme:srv:1.0:*:*:*:*:*:*:*");
        edge(g2, ext, w, stays, 0.5);
        edge(g2, ext, w, open, 0.4);
        var c2 = m.compile(g2, RiskModel.Variant.CORRELATED);
        PatchUnit u2 = c2.units.get(0);
        assertEquals("99.0", u2.targetVersion());
        assertEquals(java.util.Set.of("ALL"), u2.fixedCveIds());
        double expectedBefore = 1 - (1 - 0.5) * (1 - 0.4);
        assertEquals(expectedBefore, m.crownJewelRisk(c2, new boolean[]{false}), 1e-9);
        assertEquals(0.4, m.crownJewelRisk(c2, new boolean[]{true}), 1e-9, "only the unfixable CVE remains");
    }

    @Test
    void cveMatchedThroughTwoProductsStaysWhileEitherProductStillHasIt() {
        // CVE X affects product A below 2.0 (fixable) and product B in every version (not fixable)
        CveRecord x = new CveRecord("X", "x", 9.8, CveRecord.AttackVector.NETWORK, CveRecord.AttackComplexity.LOW,
                CveRecord.PrivilegesRequired.NONE, CveRecord.UserInteraction.NONE, "CWE-1",
                List.of("cpe:2.3:a:acme:prodA:*:*:*:*:*:*:*:*#<2.0", "cpe:2.3:a:acme:prodB:*:*:*:*:*:*:*:*"), true, false);
        HostNode ext = node("ext", NetworkTier.EXTERNAL, 0), w = node("w", NetworkTier.CROWN_JEWEL, 10);
        w.addVulnerability(x, "cpe:2.3:a:acme:prodA:1.0:*:*:*:*:*:*:*");
        w.addVulnerability(x, "cpe:2.3:a:acme:prodB:1.0:*:*:*:*:*:*:*");
        var g = graph(ext, w);
        edge(g, ext, w, x, 0.6);

        var c = model.compile(g, RiskModel.Variant.CORRELATED);
        assertEquals(2, c.units.size());
        PatchUnit a = c.units.stream().filter(u -> u.cpe().contains("prodA")).findFirst().orElseThrow();
        PatchUnit b = c.units.stream().filter(u -> u.cpe().contains("prodB")).findFirst().orElseThrow();
        assertTrue(a.fixedCveIds().contains("X"));
        assertFalse(b.fixedCveIds().contains("X"));

        boolean[] onlyA = new boolean[2];
        onlyA[a.index()] = true;
        boolean[] both = {true, true};
        assertEquals(0.6, model.crownJewelRisk(c, new boolean[2]), 1e-9);
        assertEquals(0.6, model.crownJewelRisk(c, onlyA), 1e-9, "product B still carries CVE X");
        assertEquals(0.6, model.crownJewelRisk(c, both), 1e-9, "B can never be fixed, so X stays");
    }
}

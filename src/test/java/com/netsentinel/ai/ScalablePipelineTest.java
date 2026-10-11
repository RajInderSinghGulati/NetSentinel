package com.netsentinel.ai;

import com.netsentinel.eval.TopologyFactory;
import com.netsentinel.graph.AttackGraphBuilder;
import com.netsentinel.model.AttackPath;
import com.netsentinel.model.ExploitEdge;
import com.netsentinel.model.HostFingerprint;
import com.netsentinel.model.HostFingerprint.NetworkTier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/** The scalable code paths must give exactly the same answers as the straightforward ones. */
@SpringBootTest(properties = {"netsentinel.nvd.offline-only=true"})
class ScalablePipelineTest {

    @Autowired AttackGraphBuilder builder;
    @Autowired CompromiseScorer scorer;
    @Autowired RiskModel riskModel;
    @Autowired AttackPathAnalyzer analyzer;

    private static List<List<HostFingerprint>> topologies() {
        return List.of(TopologyFactory.lab(), TopologyFactory.ecommerce(),
                TopologyFactory.synthetic(40, 1), TopologyFactory.synthetic(60, 2));
    }

    @Test
    void implicitCompileMatchesExplicitGraphCompile() {
        Random rnd = new Random(7);
        for (var fps : topologies()) {
            var gr = builder.buildGraph(fps);
            scorer.scoreGraphEdges(gr.graph());
            var explicit = riskModel.compile(gr.graph(), RiskModel.Variant.CORRELATED);
            var implicit = riskModel.compileImplicit(builder.buildNodes(fps));

            assertEquals(explicit.units.size(), implicit.units.size());
            for (int i = 0; i < explicit.units.size(); i++) {
                assertEquals(explicit.units.get(i).label(), implicit.units.get(i).label());
                assertEquals(explicit.units.get(i).fixedCveIds(), implicit.units.get(i).fixedCveIds());
            }
            assertEquals(riskModel.crownJewelRisk(explicit, (boolean[]) null),
                    riskModel.crownJewelRisk(implicit, (boolean[]) null), 1e-12, "baseline risk");

            for (int trial = 0; trial < 25; trial++) {
                boolean[] removed = new boolean[explicit.units.size()];
                for (int i = 0; i < removed.length; i++) removed[i] = rnd.nextInt(5) == 0;
                assertEquals(riskModel.crownJewelRisk(explicit, removed),
                        riskModel.crownJewelRisk(implicit, removed), 1e-12, "random patch set " + trial);
            }
        }
    }

    @Test
    void perCveScoringEqualsPerEdgeScoring() {
        var gr = builder.buildGraph(TopologyFactory.synthetic(50, 3));
        scorer.scoreGraphEdges(gr.graph());
        for (ExploitEdge e : gr.graph().edgeSet()) {
            int crit = gr.graph().getEdgeTarget(e).getFingerprint().criticality();
            assertEquals(scorer.scoreEdge(e.getExploitedCve(), crit), e.getExploitProbability(), 0.0);
            assertEquals(-Math.log(e.getExploitProbability()), gr.graph().getEdgeWeight(e), 1e-12);
        }
    }

    @Test
    void topKRoutesAreDistinctRankedAndStartAtTheAttacker() {
        for (var fps : topologies()) {
            var gr = builder.buildGraph(fps);
            scorer.scoreGraphEdges(gr.graph());
            List<AttackPath> paths = analyzer.findTopKAttackPaths(gr.graph(), gr.nodeMap(), 10);
            assertFalse(paths.isEmpty());
            Set<List<String>> routes = new HashSet<>();
            double prev = Double.POSITIVE_INFINITY;
            for (AttackPath p : paths) {
                assertEquals(NetworkTier.EXTERNAL, p.hops().get(0).getFingerprint().tier());
                assertEquals(NetworkTier.CROWN_JEWEL, p.hops().get(p.hops().size() - 1).getFingerprint().tier());
                assertTrue(p.cumulativeRisk() <= prev + 1e-15, "paths must be ranked by risk");
                prev = p.cumulativeRisk();
                assertTrue(routes.add(p.hops().stream().map(h -> h.getId()).toList()), "duplicate host route");
            }
        }
    }

    @Test
    void bestPathRiskIsTheMaximumOverAllHostRoutes() {
        // brute force over host routes (best edge per host pair) on the web-shop topology
        var gr = builder.buildGraph(TopologyFactory.ecommerce());
        scorer.scoreGraphEdges(gr.graph());
        Map<String, Double> bestEdge = new HashMap<>();
        for (ExploitEdge e : gr.graph().edgeSet()) {
            String key = gr.graph().getEdgeSource(e).getId() + ">" + gr.graph().getEdgeTarget(e).getId();
            bestEdge.merge(key, e.getExploitProbability(), Math::max);
        }
        double best = 0;
        for (var start : gr.graph().vertexSet()) {
            if (start.getFingerprint().tier() != NetworkTier.EXTERNAL) continue;
            best = Math.max(best, bestFrom(gr, bestEdge, start, new HashSet<>(), 1.0));
        }
        var top = analyzer.findTopKAttackPaths(gr.graph(), gr.nodeMap(), 3).get(0);
        assertEquals(best, top.cumulativeRisk(), 1e-12);
    }

    private double bestFrom(AttackGraphBuilder.AttackGraphResult gr, Map<String, Double> bestEdge,
                            com.netsentinel.model.HostNode at, Set<String> visited, double risk) {
        if (at.getFingerprint().tier() == NetworkTier.CROWN_JEWEL) return risk;
        visited.add(at.getId());
        double best = 0;
        for (var next : gr.graph().vertexSet()) {
            Double p = bestEdge.get(at.getId() + ">" + next.getId());
            if (p == null || visited.contains(next.getId())) continue;
            best = Math.max(best, bestFrom(gr, bestEdge, next, visited, risk * p));
        }
        visited.remove(at.getId());
        return best;
    }
}

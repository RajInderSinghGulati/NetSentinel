package com.netsentinel.ai;

import com.netsentinel.model.CveRecord;
import com.netsentinel.model.ExploitEdge;
import com.netsentinel.model.HostNode;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Tier 3: Lateral Compromise Scorer.
 *
 * <p>Edge exploitability comes from {@link LearnedExploitModel}, a gradient-boosted tree
 * model trained offline on real labels (CISA KEV exploitation within a year of
 * publication) with a temporal train/test split. See {@code scripts/train.py}.</p>
 *
 * <ul>
 *   <li>CVEs already listed in CISA KEV ({@code exploitInWild}) get at least
 *       {@code netsentinel.ai.known-exploited-probability}: exploitation is observed, the
 *       model's forward-looking estimate would understate it.</li>
 *   <li>Edges without a CVE (pure reachability) get a small constant.</li>
 *   <li>Target-asset criticality does not change exploit likelihood and is no longer a
 *       model input; it belongs in impact weighting (remediation prioritization).</li>
 * </ul>
 *
 * <p>Graph edge weights are {@code -ln(p)}, so a shortest path maximizes the product of
 * edge probabilities.</p>
 */
@Component
public class CompromiseScorer {

    private static final Logger log = LoggerFactory.getLogger(CompromiseScorer.class);
    private static final double REACHABILITY_ONLY = 0.05;
    private static final double MIN_P = 1e-6;
    private static final double MAX_P = 0.999;

    @Value("${netsentinel.ai.model-path:/model/exploit_model.json}")
    private String modelPath;

    @Value("${netsentinel.ai.known-exploited-probability:0.9}")
    private double knownExploitedProbability;

    private LearnedExploitModel model;

    @PostConstruct
    public void initialize() throws IOException {
        model = LearnedExploitModel.fromClasspath(modelPath);
        log.info("✓ Loaded learned exploitability model ({} trees) from {}", model.treeCount(), modelPath);
    }

    /**
     * Probability that an attacker successfully uses this CVE on the target.
     *
     * @param cve         The CVE being exploited (null = reachability-only edge)
     * @param criticality Target host criticality (unused for likelihood; kept for API stability)
     */
    public double scoreEdge(CveRecord cve, int criticality) {
        if (cve == null) return REACHABILITY_ONLY;
        double p = model.predict(cve);
        if (cve.exploitInWild()) p = Math.max(p, knownExploitedProbability);
        return Math.min(MAX_P, Math.max(MIN_P, p));
    }

    /**
     * Scores all edges in the graph and updates exploit probabilities.
     */
    public void scoreGraphEdges(
            org.jgrapht.graph.DirectedWeightedMultigraph<HostNode, ExploitEdge> graph) {

        log.info("▶ Scoring {} edges with learned exploitability model...", graph.edgeSet().size());
        int scored = 0;

        // an edge's probability depends only on its CVE, so score each distinct CVE once
        java.util.Map<String, Double> byCve = new java.util.HashMap<>();
        for (ExploitEdge edge : graph.edgeSet()) {
            HostNode target = graph.getEdgeTarget(edge);
            CveRecord cve = edge.getExploitedCve();
            double probability = cve == null
                    ? scoreEdge(null, 0)
                    : byCve.computeIfAbsent(cve.cveId(), id -> scoreEdge(cve, target.getFingerprint().criticality()));
            edge.setExploitProbability(probability);
            graph.setEdgeWeight(edge, -Math.log(probability));
            scored++;
        }

        // Node compromise probability: strongest incoming edge (noisy-OR comes in Phase C)
        for (HostNode node : graph.vertexSet()) {
            double maxProb = graph.incomingEdgesOf(node).stream()
                    .mapToDouble(ExploitEdge::getExploitProbability)
                    .max().orElse(0.0);
            node.setCompromiseProbability(maxProb);
        }

        log.info("✓ Scored {} edges", scored);
    }
}

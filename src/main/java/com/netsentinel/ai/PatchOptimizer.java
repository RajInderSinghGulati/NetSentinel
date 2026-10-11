package com.netsentinel.ai;

import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Budgeted remediation: pick at most B patch units (upgrade product P on host H) that minimise the
 * criticality-weighted expected number of compromised crown jewels, as computed by {@link RiskModel}.
 *
 * <p>Strategies:</p>
 * <ul>
 *   <li><b>CVSS_FIRST</b>: the common industry baseline; units ranked by highest CVSS score they fix.</li>
 *   <li><b>EXPLOIT_PROB_FIRST</b>: units ranked by the highest learned exploit probability they fix,
 *       ignoring network position.</li>
 *   <li><b>RANDOM</b>: mean over {@value #RANDOM_DRAWS} random draws (reported as a plain baseline).</li>
 *   <li><b>GREEDY</b>: repeatedly apply the unit with the largest marginal risk reduction.</li>
 *   <li><b>OPTIMAL</b>: exhaustive search over all size-B subsets of units that matter; exact for the
 *       model's objective (which is not linear, so an ILP does not apply directly). Skipped when the
 *       search space exceeds {@value #MAX_EVALUATIONS} evaluations.</li>
 * </ul>
 */
@Component
public class PatchOptimizer {

    static final int RANDOM_DRAWS = 200;
    static final long MAX_EVALUATIONS = 3_000_000L;

    public enum Strategy { CVSS_FIRST, EXPLOIT_PROB_FIRST, RANDOM, GREEDY, OPTIMAL }

    /** A chosen patch set and the resulting risk. {@code patches} is empty for RANDOM (a mean). */
    public record Plan(Strategy strategy, int budget, List<PatchUnit> patches, double risk, boolean computed) {}

    private final RiskModel riskModel;

    public PatchOptimizer(RiskModel riskModel) {
        this.riskModel = riskModel;
    }

    public Plan plan(RiskModel.Compiled c, Strategy strategy, int budget, long seed) {
        int b = Math.min(budget, c.units.size());
        return switch (strategy) {
            case CVSS_FIRST -> ranked(c, strategy, b, Comparator
                    .comparingDouble((PatchUnit u) -> -u.maxCvss())
                    .thenComparingDouble(u -> -u.sumCvss()).thenComparingInt(PatchUnit::index));
            case EXPLOIT_PROB_FIRST -> {
                double[] score = new double[c.units.size()];
                for (PatchUnit u : c.units) score[u.index()] = c.maxExploitProbability(u.index());
                yield ranked(c, strategy, b, Comparator
                        .comparingDouble((PatchUnit u) -> -score[u.index()]).thenComparingInt(PatchUnit::index));
            }
            case RANDOM -> random(c, b, seed);
            case GREEDY -> greedy(c, b);
            case OPTIMAL -> optimal(c, b);
        };
    }

    /** Risk after each budget 0..maxBudget for every strategy. */
    public Map<Strategy, List<Plan>> curve(RiskModel.Compiled c, int maxBudget, long seed) {
        Map<Strategy, List<Plan>> out = new EnumMap<>(Strategy.class);
        for (Strategy s : Strategy.values()) {
            List<Plan> plans = new ArrayList<>();
            for (int b = 0; b <= maxBudget; b++) plans.add(plan(c, s, b, seed));
            out.put(s, plans);
        }
        return out;
    }

    public double baselineRisk(RiskModel.Compiled c) {
        return riskModel.crownJewelRisk(c, (boolean[]) null);
    }

    // ------------------------------------------------------------------ strategies

    private Plan ranked(RiskModel.Compiled c, Strategy s, int b, Comparator<PatchUnit> order) {
        List<PatchUnit> sorted = new ArrayList<>(c.units);
        sorted.sort(order);
        List<PatchUnit> chosen = new ArrayList<>(sorted.subList(0, b));
        return new Plan(s, b, chosen, riskAfter(c, chosen), true);
    }

    private Plan random(RiskModel.Compiled c, int b, long seed) {
        Random rnd = new Random(seed);
        double sum = 0;
        for (int d = 0; d < RANDOM_DRAWS; d++) {
            List<PatchUnit> pool = new ArrayList<>(c.units);
            Collections.shuffle(pool, rnd);
            sum += riskAfter(c, pool.subList(0, b));
        }
        return new Plan(Strategy.RANDOM, b, List.of(), sum / RANDOM_DRAWS, true);
    }

    private Plan greedy(RiskModel.Compiled c, int b) {
        boolean[] removed = new boolean[c.units.size()];
        List<PatchUnit> chosen = new ArrayList<>();
        double current = riskModel.crownJewelRisk(c, removed);
        for (int step = 0; step < b; step++) {
            int best = -1;
            double bestRisk = current;
            for (PatchUnit u : c.units) {
                if (removed[u.index()]) continue;
                removed[u.index()] = true;
                double r = riskModel.crownJewelRisk(c, removed);
                removed[u.index()] = false;
                if (r < bestRisk - 1e-15) { bestRisk = r; best = u.index(); }
            }
            if (best < 0) break; // no remaining unit reduces risk
            removed[best] = true;
            chosen.add(c.units.get(best));
            current = bestRisk;
        }
        return new Plan(Strategy.GREEDY, b, chosen, current, true);
    }

    private Plan optimal(RiskModel.Compiled c, int b) {
        // Only units that fix at least one exploit event can change the objective.
        List<PatchUnit> cand = new ArrayList<>();
        for (PatchUnit u : c.units) if (c.maxExploitProbability(u.index()) > 0) cand.add(u);
        int k = Math.min(b, cand.size());
        if (binomialExceeds(cand.size(), k, MAX_EVALUATIONS)) {
            return new Plan(Strategy.OPTIMAL, b, List.of(), Double.NaN, false);
        }
        boolean[] removed = new boolean[c.units.size()];
        int[] pick = new int[k];
        double[] best = {Double.POSITIVE_INFINITY};
        int[] bestPick = new int[k];
        search(c, cand, removed, pick, 0, 0, k, best, bestPick);
        List<PatchUnit> chosen = new ArrayList<>();
        for (int i : bestPick) chosen.add(cand.get(i));
        if (k == 0) best[0] = riskModel.crownJewelRisk(c, removed);
        return new Plan(Strategy.OPTIMAL, b, chosen, best[0], true);
    }

    private void search(RiskModel.Compiled c, List<PatchUnit> cand, boolean[] removed, int[] pick,
                        int depth, int from, int k, double[] best, int[] bestPick) {
        if (depth == k) {
            double r = riskModel.crownJewelRisk(c, removed);
            if (r < best[0] - 1e-15) {
                best[0] = r;
                System.arraycopy(pick, 0, bestPick, 0, k);
            }
            return;
        }
        for (int i = from; i <= cand.size() - (k - depth); i++) {
            pick[depth] = i;
            removed[cand.get(i).index()] = true;
            search(c, cand, removed, pick, depth + 1, i + 1, k, best, bestPick);
            removed[cand.get(i).index()] = false;
        }
    }

    // ------------------------------------------------------------------ helpers

    private double riskAfter(RiskModel.Compiled c, Collection<PatchUnit> patches) {
        boolean[] removed = new boolean[c.units.size()];
        for (PatchUnit u : patches) removed[u.index()] = true;
        return riskModel.crownJewelRisk(c, removed);
    }

    /** True if C(n, k) > limit (computed without overflow). */
    static boolean binomialExceeds(int n, int k, long limit) {
        if (k < 0 || k > n) return false;
        k = Math.min(k, n - k);
        double v = 1;
        for (int i = 1; i <= k; i++) {
            v = v * (n - k + i) / i;
            if (v > limit) return true;
        }
        return false;
    }
}

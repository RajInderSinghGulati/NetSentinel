package com.netsentinel.ai;

import com.netsentinel.model.CveRecord;
import com.netsentinel.model.ExploitEdge;
import com.netsentinel.model.HostFingerprint.NetworkTier;
import com.netsentinel.model.HostNode;
import org.jgrapht.graph.DirectedWeightedMultigraph;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Host compromise probabilities on the attack graph (a Bayesian-attack-graph style model).
 *
 * <p>The attacker starts at the EXTERNAL node(s) with probability 1. A host is compromised if
 * at least one exploit attempt from a compromised neighbour succeeds. Two variants differ in
 * what counts as an independent event:</p>
 * <ul>
 *   <li>{@link Variant#NOISY_OR}: every edge (source host, CVE, target host) is independent:
 *       {@code P(t) = 1 - prod_edges (1 - P(s) p_e)}. Over-counts when many hosts can attack the
 *       same vulnerable service.</li>
 *   <li>{@link Variant#CORRELATED}: "CVE c is exploitable on host t" is ONE event shared by all
 *       sources: {@code P(t) = 1 - prod_c (1 - p_c (1 - prod_s (1 - P(s))))}. An exploit either
 *       works on a given host or it does not, regardless of who launches it.</li>
 * </ul>
 *
 * <p>Both are solved by fixed-point iteration from zero (monotone, converges to the least fixed
 * point, cycles allowed). They treat compromise of different sources as independent, which is an
 * approximation: on graphs with cycles (e.g. lateral movement within a tier) a host can count as
 * support for its own compromise, so the result is an <em>upper bound</em>. {@link #monteCarlo}
 * samples the exact semantics so the error can be measured.</p>
 */
@Component
public class RiskModel {

    public enum Variant { NOISY_OR, CORRELATED }

    /** One probabilistic exploit event that opens a target host to a set of source hosts. */
    static final class Group {
        final int target;
        final int[] sources;
        final double p;
        /** Patch units that fix this event; empty = cannot be patched. Removed once ALL are applied. */
        final int[] units;

        Group(int target, int[] sources, double p, int[] units) {
            this.target = target;
            this.sources = sources;
            this.p = p;
            this.units = units;
        }

        boolean active(boolean[] removed) {
            if (removed == null || units.length == 0) return true;
            for (int u : units) if (!removed[u]) return true;
            return false;
        }
    }

    /** Graph compiled to arrays for fast repeated evaluation under different patch sets. */
    public static final class Compiled {
        final List<HostNode> nodes;
        final boolean[] isSource;
        final Group[][] byTarget;
        final Group[] allGroups;
        final int[] crownJewels;
        final double[] jewelWeight;
        public final List<PatchUnit> units;
        public final Variant variant;

        Compiled(List<HostNode> nodes, boolean[] isSource, Group[][] byTarget, Group[] allGroups,
                 int[] crownJewels, double[] jewelWeight, List<PatchUnit> units, Variant variant) {
            this.nodes = nodes;
            this.isSource = isSource;
            this.byTarget = byTarget;
            this.allGroups = allGroups;
            this.crownJewels = crownJewels;
            this.jewelWeight = jewelWeight;
            this.units = units;
            this.variant = variant;
        }

        public List<HostNode> nodes() { return nodes; }

        /** Highest exploit probability among the exploit events a unit fixes (0 if it fixes no network exploit). */
        public double maxExploitProbability(int unit) {
            double best = 0;
            for (Group g : allGroups) {
                for (int u : g.units) if (u == unit) best = Math.max(best, g.p);
            }
            return best;
        }
    }

    /** Patch units of a graph: one per (host, CPE) with at least one matched CVE, EXTERNAL excluded. */
    public List<PatchUnit> buildUnits(DirectedWeightedMultigraph<HostNode, ExploitEdge> graph) {
        List<HostNode> nodes = sortedNodes(graph);
        List<PatchUnit> units = new ArrayList<>();
        for (HostNode n : nodes) {
            if (n.getFingerprint().tier() == NetworkTier.EXTERNAL) continue;
            for (var e : n.getVulnerabilitiesByCpe().entrySet()) {
                if (e.getValue().isEmpty()) continue;
                units.add(new PatchUnit(units.size(), n.getId(), n.getFingerprint().displayLabel(),
                        e.getKey(), List.copyOf(e.getValue())));
            }
        }
        return units;
    }

    public Compiled compile(DirectedWeightedMultigraph<HostNode, ExploitEdge> graph, Variant variant) {
        List<HostNode> nodes = sortedNodes(graph);
        Map<HostNode, Integer> idx = new HashMap<>();
        for (int i = 0; i < nodes.size(); i++) idx.put(nodes.get(i), i);
        List<PatchUnit> units = buildUnits(graph);

        // (hostId|cveId) -> patch units fixing it
        Map<String, List<Integer>> fixedBy = new HashMap<>();
        for (PatchUnit u : units) {
            for (CveRecord c : u.cves()) {
                fixedBy.computeIfAbsent(u.hostId() + "|" + c.cveId(), k -> new ArrayList<>()).add(u.index());
            }
        }

        int n = nodes.size();
        boolean[] isSource = new boolean[n];
        for (int i = 0; i < n; i++) isSource[i] = nodes.get(i).getFingerprint().tier() == NetworkTier.EXTERNAL;

        // Collect edges per target; CORRELATED merges by (target, cve), NOISY_OR keeps each edge.
        Map<String, List<Integer>> sourcesOf = new LinkedHashMap<>();
        Map<String, Double> pOf = new HashMap<>();
        Map<String, Integer> targetOf = new HashMap<>();
        Map<String, int[]> unitsOf = new HashMap<>();
        for (ExploitEdge e : sortedEdges(graph)) {
            int s = idx.get(graph.getEdgeSource(e));
            int t = idx.get(graph.getEdgeTarget(e));
            CveRecord cve = e.getExploitedCve();
            String key;
            int[] fixing;
            if (cve == null) {
                key = "reach|" + t + "|" + e.getEdgeId();
                fixing = new int[0];
            } else {
                String host = nodes.get(t).getId();
                key = variant == Variant.CORRELATED
                        ? "cve|" + t + "|" + cve.cveId()
                        : "edge|" + t + "|" + cve.cveId() + "|" + s;
                fixing = fixedBy.getOrDefault(host + "|" + cve.cveId(), List.of())
                        .stream().mapToInt(Integer::intValue).toArray();
            }
            sourcesOf.computeIfAbsent(key, k -> new ArrayList<>()).add(s);
            pOf.putIfAbsent(key, e.getExploitProbability());
            targetOf.put(key, t);
            unitsOf.put(key, fixing);
        }

        List<List<Group>> perTarget = new ArrayList<>();
        for (int i = 0; i < n; i++) perTarget.add(new ArrayList<>());
        List<Group> all = new ArrayList<>();
        for (var en : sourcesOf.entrySet()) {
            String k = en.getKey();
            int[] src = en.getValue().stream().distinct().mapToInt(Integer::intValue).toArray();
            Group g = new Group(targetOf.get(k), src, pOf.get(k), unitsOf.get(k));
            perTarget.get(g.target).add(g);
            all.add(g);
        }
        Group[][] byTarget = new Group[n][];
        for (int i = 0; i < n; i++) byTarget[i] = perTarget.get(i).toArray(new Group[0]);

        List<Integer> jewels = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            if (nodes.get(i).getFingerprint().tier() == NetworkTier.CROWN_JEWEL) jewels.add(i);
        }
        int[] jw = jewels.stream().mapToInt(Integer::intValue).toArray();
        double[] w = jewels.stream().mapToDouble(i -> nodes.get(i).getFingerprint().criticality() / 10.0).toArray();

        return new Compiled(nodes, isSource, byTarget, all.toArray(new Group[0]), jw, w, units, variant);
    }

    /**
     * Compromise probability of every node (index order = {@link Compiled#nodes()}).
     *
     * @param removed patch units applied, indexed by unit index; null = nothing patched
     */
    public double[] evaluate(Compiled c, boolean[] removed) {
        int n = c.nodes.size();
        double[] p = new double[n];
        for (int i = 0; i < n; i++) if (c.isSource[i]) p[i] = 1.0;

        for (int iter = 0; iter < 500; iter++) {
            double delta = 0;
            for (int t = 0; t < n; t++) {
                if (c.isSource[t]) continue;
                double survive = 1.0;
                for (Group g : c.byTarget[t]) {
                    if (!g.active(removed)) continue;
                    double noReach = 1.0;
                    for (int s : g.sources) noReach *= 1.0 - p[s];
                    survive *= 1.0 - g.p * (1.0 - noReach);
                }
                double next = 1.0 - survive;
                delta = Math.max(delta, Math.abs(next - p[t]));
                p[t] = next;
            }
            if (delta < 1e-12) break;
        }
        return p;
    }

    /** Expected criticality-weighted number of compromised crown jewels. */
    public double crownJewelRisk(Compiled c, boolean[] removed) {
        return crownJewelRisk(c, evaluate(c, removed));
    }

    public double crownJewelRisk(Compiled c, double[] p) {
        double r = 0;
        for (int k = 0; k < c.crownJewels.length; k++) r += c.jewelWeight[k] * p[c.crownJewels[k]];
        return r;
    }

    /**
     * Monte Carlo estimate with the exact event semantics of the compiled groups (each group is one
     * Bernoulli event per trial; a target falls if a succeeded group has a compromised source).
     */
    public double[] monteCarlo(Compiled c, boolean[] removed, int trials, long seed) {
        int n = c.nodes.size();
        Random rnd = new Random(seed);
        List<Group> active = new ArrayList<>();
        for (Group g : c.allGroups) if (g.active(removed)) active.add(g);
        List<List<Integer>> outGroups = new ArrayList<>();
        for (int i = 0; i < n; i++) outGroups.add(new ArrayList<>());
        for (int gi = 0; gi < active.size(); gi++) {
            for (int s : active.get(gi).sources) outGroups.get(s).add(gi);
        }

        long[] hits = new long[n];
        boolean[] comp = new boolean[n];
        boolean[] ok = new boolean[active.size()];
        ArrayDeque<Integer> queue = new ArrayDeque<>();
        for (int trial = 0; trial < trials; trial++) {
            Arrays.fill(comp, false);
            for (int gi = 0; gi < ok.length; gi++) ok[gi] = rnd.nextDouble() < active.get(gi).p;
            for (int i = 0; i < n; i++) if (c.isSource[i]) { comp[i] = true; queue.add(i); }
            while (!queue.isEmpty()) {
                int s = queue.poll();
                for (int gi : outGroups.get(s)) {
                    int t = active.get(gi).target;
                    if (ok[gi] && !comp[t]) { comp[t] = true; queue.add(t); }
                }
            }
            for (int i = 0; i < n; i++) if (comp[i]) hits[i]++;
        }
        double[] p = new double[n];
        for (int i = 0; i < n; i++) p[i] = hits[i] / (double) trials;
        return p;
    }

    /** Writes node compromise probabilities (CORRELATED unless told otherwise) back onto the graph nodes. */
    public double applyToGraph(DirectedWeightedMultigraph<HostNode, ExploitEdge> graph, Variant variant) {
        Compiled c = compile(graph, variant);
        double[] p = evaluate(c, null);
        for (int i = 0; i < p.length; i++) c.nodes.get(i).setCompromiseProbability(p[i]);
        return crownJewelRisk(c, p);
    }

    private static List<HostNode> sortedNodes(DirectedWeightedMultigraph<HostNode, ExploitEdge> graph) {
        List<HostNode> nodes = new ArrayList<>(graph.vertexSet());
        nodes.sort(Comparator.comparing(HostNode::getId));
        return nodes;
    }

    private static List<ExploitEdge> sortedEdges(DirectedWeightedMultigraph<HostNode, ExploitEdge> graph) {
        List<ExploitEdge> edges = new ArrayList<>(graph.edgeSet());
        edges.sort(Comparator.comparing(ExploitEdge::getEdgeId));
        return edges;
    }
}

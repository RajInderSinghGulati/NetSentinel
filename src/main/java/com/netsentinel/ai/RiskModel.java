package com.netsentinel.ai;

import com.netsentinel.cve.CveDatabase;
import com.netsentinel.cve.UpgradePlanner;
import com.netsentinel.graph.AttackGraphBuilder;
import com.netsentinel.model.CveRecord;
import com.netsentinel.model.ExploitEdge;
import com.netsentinel.model.HostFingerprint.NetworkTier;
import com.netsentinel.model.HostNode;
import org.jgrapht.graph.DirectedWeightedMultigraph;
import org.springframework.beans.factory.annotation.Autowired;
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

    /** Used to look up the CVEs of a target version (null = assume upgrades introduce nothing). */
    private final CveDatabase cveDatabase;
    private final CompromiseScorer scorer;

    @Autowired
    public RiskModel(CveDatabase cveDatabase, CompromiseScorer scorer) {
        this.cveDatabase = cveDatabase;
        this.scorer = scorer;
    }

    /** Model without a CVE database: patches only remove CVEs. Used by unit tests on synthetic graphs. */
    public RiskModel() {
        this(null, null);
    }

    /** One probabilistic exploit event that opens a target host to a set of source hosts. */
    static final class Group {
        final int target;
        final int[] sources;
        final double p;
        /** Patch units that fix this event; empty = cannot be patched. Removed once ALL are applied. */
        final int[] units;
        /** Patch units that must ALL be applied for this event to exist (CVEs introduced by an upgrade). */
        final int[] enabledBy;
        /** Index of this group's source set; groups of one target with equal sources share it. */
        int sid;

        Group(int target, int[] sources, double p, int[] units) {
            this(target, sources, p, units, new int[0]);
        }

        Group(int target, int[] sources, double p, int[] units, int[] enabledBy) {
            this.target = target;
            this.sources = sources;
            this.p = p;
            this.units = units;
            this.enabledBy = enabledBy;
        }

        boolean active(boolean[] removed) {
            if (enabledBy.length > 0) {
                if (removed == null) return false;
                for (int u : enabledBy) if (!removed[u]) return false;
            }
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
        final int numSets;
        final double[] unitMaxP;

        Compiled(List<HostNode> nodes, boolean[] isSource, Group[][] byTarget, Group[] allGroups,
                 int[] crownJewels, double[] jewelWeight, List<PatchUnit> units, Variant variant, int numSets) {
            this.nodes = nodes;
            this.isSource = isSource;
            this.byTarget = byTarget;
            this.allGroups = allGroups;
            this.crownJewels = crownJewels;
            this.jewelWeight = jewelWeight;
            this.units = units;
            this.variant = variant;
            this.numSets = numSets;
            this.unitMaxP = new double[units.size()];
            for (Group g : allGroups) for (int u : g.units) unitMaxP[u] = Math.max(unitMaxP[u], g.p);
        }

        public List<HostNode> nodes() { return nodes; }

        /** Number of distinct exploit events in the compiled model. */
        public int groupCount() { return allGroups.length; }

        /** Highest exploit probability among the exploit events a unit fixes (0 if it fixes no network exploit). */
        public double maxExploitProbability(int unit) {
            return unitMaxP[unit];
        }
    }

    /** Patch units of a graph: one per (host, CPE) with at least one matched CVE, EXTERNAL excluded. */
    public List<PatchUnit> buildUnits(DirectedWeightedMultigraph<HostNode, ExploitEdge> graph) {
        return buildUnits(sortedNodes(graph));
    }

    private List<PatchUnit> buildUnits(List<HostNode> nodes) {
        List<PatchUnit> units = new ArrayList<>();
        // hosts running the same product with the same CVEs share one upgrade plan
        Map<String, UpgradeEntry> memo = new HashMap<>();
        for (HostNode n : nodes) {
            if (n.getFingerprint().tier() == NetworkTier.EXTERNAL) continue;
            for (var e : n.getVulnerabilitiesByCpe().entrySet()) {
                if (e.getValue().isEmpty()) continue;
                units.add(planUnit(units.size(), n, e.getKey(), e.getValue(), memo));
            }
        }
        return units;
    }

    /** Host-independent part of an upgrade plan: the planner result and the CVEs of the target version. */
    private record UpgradeEntry(UpgradePlanner.Upgrade upgrade, Map<String, CveRecord> afterByCve) {}

    /** Chooses the upgrade target for one (host, product) and works out what it fixes, leaves and adds. */
    private PatchUnit planUnit(int index, HostNode host, String cpe, List<CveRecord> matched,
                               Map<String, UpgradeEntry> memo) {
        List<CveRecord> cves = matched.stream().collect(java.util.stream.Collectors.collectingAndThen(
                java.util.stream.Collectors.toMap(CveRecord::cveId, c -> c, (a, b) -> a, java.util.LinkedHashMap::new),
                m -> List.copyOf(m.values())));
        String hostLabel = host.getFingerprint().displayLabel();
        String key = cpe + "#" + cves.stream().map(CveRecord::cveId).sorted().collect(java.util.stream.Collectors.joining(","));
        UpgradeEntry entry = memo.computeIfAbsent(key, k -> {
            UpgradePlanner.Upgrade u = UpgradePlanner.plan(cpe, cves);
            Map<String, CveRecord> after = new LinkedHashMap<>();
            if (u.hasTarget() && cveDatabase != null) {
                // the database is authoritative for what affects the target version
                for (CveRecord c : cveDatabase.findByCpe(u.targetCpe())) after.putIfAbsent(c.cveId(), c);
            }
            return new UpgradeEntry(u, after);
        });
        UpgradePlanner.Upgrade up = entry.upgrade();
        if (!up.hasTarget()) {
            return new PatchUnit(index, host.getId(), hostLabel, cpe, cves, null, null, up.targetLabel(), Set.of(), List.of());
        }
        Set<String> fixed = up.fixedCveIds();
        List<CveRecord> introduced = List.of();
        if (cveDatabase != null) {
            Map<String, CveRecord> after = entry.afterByCve();
            fixed = new LinkedHashSet<>();
            for (CveRecord c : cves) if (!after.containsKey(c.cveId())) fixed.add(c.cveId());
            Set<String> onHost = new HashSet<>();
            host.getVulnerabilities().forEach(c -> onHost.add(c.cveId()));
            introduced = after.values().stream().filter(c -> !onHost.contains(c.cveId())).toList();
        }
        return new PatchUnit(index, host.getId(), hostLabel, cpe, cves, up.targetVersion(), up.targetCpe(),
                up.targetLabel(), fixed, introduced);
    }

    public Compiled compile(DirectedWeightedMultigraph<HostNode, ExploitEdge> graph, Variant variant) {
        List<HostNode> nodes = sortedNodes(graph);
        Map<HostNode, Integer> idx = new HashMap<>();
        for (int i = 0; i < nodes.size(); i++) idx.put(nodes.get(i), i);
        List<PatchUnit> units = buildUnits(graph);

        Map<String, List<Integer>> fixedBy = fixedByIndex(units);

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

        List<Group> base = new ArrayList<>();
        for (var en : sourcesOf.entrySet()) {
            String k = en.getKey();
            int[] src = en.getValue().stream().distinct().mapToInt(Integer::intValue).toArray();
            base.add(new Group(targetOf.get(k), src, pOf.get(k), unitsOf.get(k)));
        }
        return assemble(nodes, units, base, variant);
    }

    /**
     * Same model as {@link #compile} for graphs built by {@link AttackGraphBuilder}, but derived directly from
     * the hosts and the tier reachability rules, without materialising one edge per (source, target, CVE).
     * Memory and time then grow with hosts x CVEs instead of hosts^2 x CVEs. CORRELATED variant only.
     */
    public Compiled compileImplicit(Collection<HostNode> hostNodes) {
        if (scorer == null) throw new IllegalStateException("compileImplicit needs a CompromiseScorer");
        List<HostNode> nodes = new ArrayList<>(hostNodes);
        nodes.sort(Comparator.comparing(HostNode::getId));
        List<PatchUnit> units = buildUnits(nodes);
        Map<String, List<Integer>> fixedBy = fixedByIndex(units);

        int n = nodes.size();
        List<Group> base = new ArrayList<>();
        for (int t = 0; t < n; t++) {
            HostNode host = nodes.get(t);
            NetworkTier tier = host.getFingerprint().tier();
            if (tier == NetworkTier.EXTERNAL) continue;
            int[] srcs = tierSources(nodes, t);
            if (srcs.length == 0) continue;
            Set<String> seen = new HashSet<>();
            for (CveRecord cve : host.getVulnerabilities()) {
                if (cve.attackVector() != CveRecord.AttackVector.NETWORK || !seen.add(cve.cveId())) continue;
                int[] fixing = fixedBy.getOrDefault(host.getId() + "|" + cve.cveId(), List.of())
                        .stream().mapToInt(Integer::intValue).toArray();
                base.add(new Group(t, srcs, scorer.scoreEdge(cve, host.getFingerprint().criticality()), fixing));
            }
        }
        return assemble(nodes, units, base, Variant.CORRELATED);
    }

    private static int[] tierSources(List<HostNode> nodes, int target) {
        NetworkTier tt = nodes.get(target).getFingerprint().tier();
        return java.util.stream.IntStream.range(0, nodes.size())
                .filter(i -> i != target && AttackGraphBuilder.canReach(nodes.get(i).getFingerprint().tier(), tt))
                .toArray();
    }

    /**
     * "host|cve" -> patch units that must all be applied for the CVE to disappear. A CVE can be matched
     * through several products of one host; if any of them cannot fix it, it never disappears, so such keys
     * are left out (the group is then unpatchable).
     */
    private static Map<String, List<Integer>> fixedByIndex(List<PatchUnit> units) {
        Map<String, List<Integer>> fixedBy = new HashMap<>();
        Set<String> unfixable = new HashSet<>();
        for (PatchUnit u : units) {
            for (CveRecord c : u.cves()) {
                String key = u.hostId() + "|" + c.cveId();
                if (u.fixedCveIds().contains(c.cveId())) {
                    fixedBy.computeIfAbsent(key, k -> new ArrayList<>()).add(u.index());
                } else {
                    unfixable.add(key);
                }
            }
        }
        unfixable.forEach(fixedBy::remove);
        return fixedBy;
    }

    /** Adds the CVEs that upgrades introduce, shares equal source sets between a target's groups, and packs arrays. */
    private Compiled assemble(List<HostNode> nodes, List<PatchUnit> units, List<Group> base, Variant variant) {
        int n = nodes.size();
        boolean[] isSource = new boolean[n];
        for (int i = 0; i < n; i++) isSource[i] = nodes.get(i).getFingerprint().tier() == NetworkTier.EXTERNAL;

        Map<Integer, Set<Integer>> incoming = new HashMap<>();   // target -> sources already attacking it
        for (Group g : base) {
            Set<Integer> in = incoming.computeIfAbsent(g.target, k -> new TreeSet<>());
            for (int s : g.sources) in.add(s);
        }

        List<List<Group>> perTarget = new ArrayList<>();
        for (int i = 0; i < n; i++) perTarget.add(new ArrayList<>());
        List<Group> all = new ArrayList<>();
        for (Group g : base) {
            perTarget.get(g.target).add(g);
            all.add(g);
        }

        // CVEs an upgrade introduces: active only once that unit is applied
        for (PatchUnit u : units) {
            if (u.introduced().isEmpty()) continue;
            int t = indexOfId(nodes, u.hostId());
            int crit = nodes.get(t).getFingerprint().criticality();
            // sources: whoever already attacks this host, plus whoever the tier rules allow
            Set<Integer> srcSet = new TreeSet<>(incoming.getOrDefault(t, Set.of()));
            for (int i : tierSources(nodes, t)) srcSet.add(i);
            List<Integer> srcs = new ArrayList<>(srcSet);
            if (srcs.isEmpty()) continue;
            for (CveRecord c : u.introduced()) {
                if (c.attackVector() != CveRecord.AttackVector.NETWORK) continue;
                double p = scorer == null ? 0.0 : scorer.scoreEdge(c, crit);
                if (p <= 0) continue;
                if (variant == Variant.CORRELATED) {
                    Group g = new Group(t, srcs.stream().mapToInt(Integer::intValue).toArray(), p, new int[0], new int[]{u.index()});
                    perTarget.get(t).add(g);
                    all.add(g);
                } else {
                    for (int s : srcs) {
                        Group g = new Group(t, new int[]{s}, p, new int[0], new int[]{u.index()});
                        perTarget.get(t).add(g);
                        all.add(g);
                    }
                }
            }
        }

        // equal source sets share one id so evaluate() computes "does any source reach this target" once
        Map<IntArrayKey, Integer> sets = new HashMap<>();
        for (Group g : all) g.sid = sets.computeIfAbsent(new IntArrayKey(g.sources), k -> sets.size());

        Group[][] byTarget = new Group[n][];
        for (int i = 0; i < n; i++) byTarget[i] = perTarget.get(i).toArray(new Group[0]);

        List<Integer> jewels = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            if (nodes.get(i).getFingerprint().tier() == NetworkTier.CROWN_JEWEL) jewels.add(i);
        }
        int[] jw = jewels.stream().mapToInt(Integer::intValue).toArray();
        double[] w = jewels.stream().mapToDouble(i -> nodes.get(i).getFingerprint().criticality() / 10.0).toArray();

        return new Compiled(nodes, isSource, byTarget, all.toArray(new Group[0]), jw, w, units, variant, sets.size());
    }

    private static final class IntArrayKey {
        private final int[] a;
        private final int hash;

        IntArrayKey(int[] a) {
            this.a = a;
            this.hash = Arrays.hashCode(a);
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof IntArrayKey k && Arrays.equals(a, k.a);
        }

        @Override
        public int hashCode() {
            return hash;
        }
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

        double[] noReachOf = new double[c.numSets];   // per source set, valid while stamp == current target tick
        int[] stamp = new int[c.numSets];
        int tick = 0;
        for (int iter = 0; iter < 500; iter++) {
            double delta = 0;
            for (int t = 0; t < n; t++) {
                if (c.isSource[t]) continue;
                tick++;
                double survive = 1.0;
                for (Group g : c.byTarget[t]) {
                    if (!g.active(removed)) continue;
                    double noReach;
                    if (stamp[g.sid] == tick) {
                        noReach = noReachOf[g.sid];
                    } else {
                        noReach = 1.0;
                        for (int s : g.sources) noReach *= 1.0 - p[s];
                        noReachOf[g.sid] = noReach;
                        stamp[g.sid] = tick;
                    }
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
        return applyTo(compile(graph, variant));
    }

    /** Evaluates an already compiled model, stores each host's probability on its node, returns crown-jewel risk. */
    public double applyTo(Compiled c) {
        double[] p = evaluate(c, null);
        for (int i = 0; i < p.length; i++) c.nodes.get(i).setCompromiseProbability(p[i]);
        return crownJewelRisk(c, p);
    }

    private static int indexOfId(List<HostNode> nodes, String id) {
        for (int i = 0; i < nodes.size(); i++) if (nodes.get(i).getId().equals(id)) return i;
        throw new IllegalStateException("unknown host " + id);
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

package com.netsentinel.eval;

import com.netsentinel.ai.*;
import com.netsentinel.graph.AttackGraphBuilder;
import com.netsentinel.model.AttackPath;
import com.netsentinel.model.HostFingerprint;
import com.netsentinel.model.ScanTarget;
import com.netsentinel.scanner.SimulatedNetworkScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Phase E evaluation harness. Run with, e.g.
 * <pre>
 *   mvn spring-boot:run -Dspring-boot.run.jvmArguments=-Xmx6g -Dspring-boot.run.arguments=
 *     "--netsentinel.eval.run=strategies,scale,scan --netsentinel.nvd.offline-only=true
 *      --logging.level.com.netsentinel=WARN --server.port=0"
 * </pre>
 * Experiments ({@code netsentinel.eval.run}, comma separated):
 * <ul>
 *   <li>{@code strategies}: risk-vs-budget for every patching strategy on three hand-built topologies and
 *       synthetic networks (30 seeds), plus Kendall tau between Yen's top-K ranking, CVSS and the exact
 *       single-patch risk reduction. Writes {@code strategies.csv}, {@code ranking.csv}.</li>
 *   <li>{@code scale}: wall-clock time of each pipeline stage vs. network size. Writes {@code scale.csv}.</li>
 *   <li>{@code scan}: scan concurrency (virtual threads vs fixed pools) with simulated probe latency.
 *       Writes {@code scan.csv}.</li>
 * </ul>
 * Summaries and figures: {@code scripts/summarize_eval.py}.
 */
@Component
@ConditionalOnProperty("netsentinel.eval.run")
public class EvaluationRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(EvaluationRunner.class);

    @Value("${netsentinel.eval.run}") private String run;
    @Value("${netsentinel.eval.out:results/eval}") private String outDir;
    @Value("${netsentinel.eval.reps:30}") private int reps;
    @Value("${netsentinel.eval.sizes:50,200}") private String sizes;
    @Value("${netsentinel.eval.scale-sizes:50,100,200,400}") private String scaleSizes;
    @Value("${netsentinel.eval.big-reps:5}") private int bigReps;
    @Value("${netsentinel.eval.max-budget:10}") private int maxBudget;
    @Value("${netsentinel.eval.max-edges:4000000}") private long maxEdges;
    @Value("${netsentinel.eval.yen-k:10}") private int yenK;
    @Value("${netsentinel.eval.yen-max-hosts:100}") private int yenMaxHosts;
    @Value("${netsentinel.eval.optimal-max-units:25}") private int optimalMaxUnits;
    @Value("${netsentinel.eval.explicit-max:400}") private int explicitMax;

    private final AttackGraphBuilder graphBuilder;
    private final CompromiseScorer scorer;
    private final RiskModel riskModel;
    private final PatchOptimizer optimizer;
    private final AttackPathAnalyzer pathAnalyzer;
    private final SimulatedNetworkScanner simulatedScanner;
    private final ConfigurableApplicationContext context;

    public EvaluationRunner(AttackGraphBuilder graphBuilder, CompromiseScorer scorer, RiskModel riskModel,
                            PatchOptimizer optimizer, AttackPathAnalyzer pathAnalyzer,
                            SimulatedNetworkScanner simulatedScanner, ConfigurableApplicationContext context) {
        this.graphBuilder = graphBuilder;
        this.scorer = scorer;
        this.riskModel = riskModel;
        this.optimizer = optimizer;
        this.pathAnalyzer = pathAnalyzer;
        this.simulatedScanner = simulatedScanner;
        this.context = context;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Files.createDirectories(Path.of(outDir));
        int code = 0;
        try {
            for (String exp : run.split(",")) {
                switch (exp.trim()) {
                    case "strategies" -> strategies();
                    case "scale" -> scale();
                    case "scan" -> scan();
                    default -> log.warn("unknown experiment '{}'", exp);
                }
            }
        } catch (Throwable t) {
            log.error("evaluation failed", t);
            code = 1;
        }
        int exit = SpringApplication.exit(context, () -> 0);
        System.exit(code != 0 ? code : exit);
    }

    // ================================================================== shared pipeline pieces

    private record Prepared(AttackGraphBuilder.AttackGraphResult graph, RiskModel.Compiled compiled,
                            double buildMs, double scoreMs, double compileMs, long edges) {}

    private static double ms(long nanos) {
        return nanos / 1e6;
    }

    private Prepared prepare(List<HostFingerprint> hosts) {
        long t0 = System.nanoTime();
        var gr = graphBuilder.buildGraph(hosts);
        long t1 = System.nanoTime();
        long edges = gr.graph().edgeSet().size();
        scorer.scoreGraphEdges(gr.graph());
        long t2 = System.nanoTime();
        var compiled = riskModel.compile(gr.graph(), RiskModel.Variant.CORRELATED);
        long t3 = System.nanoTime();
        return new Prepared(gr, compiled, ms(t1 - t0), ms(t2 - t1), ms(t3 - t2), edges);
    }

    /** Graph-free pipeline: CVE lookup per host, then the risk model straight from hosts and tier rules. */
    private Prepared prepareImplicit(List<HostFingerprint> hosts) {
        long t0 = System.nanoTime();
        var nodes = graphBuilder.buildNodes(hosts);
        long t1 = System.nanoTime();
        var compiled = riskModel.compileImplicit(nodes);
        long t2 = System.nanoTime();
        return new Prepared(null, compiled, ms(t1 - t0), 0, ms(t2 - t1), compiled.groupCount());
    }

    private double riskOfPrefix(RiskModel.Compiled c, List<PatchUnit> patches, int k) {
        boolean[] removed = new boolean[c.units.size()];
        for (int i = 0; i < Math.min(k, patches.size()); i++) removed[patches.get(i).index()] = true;
        return riskModel.crownJewelRisk(c, removed);
    }

    private static final class Csv implements AutoCloseable {
        private final PrintWriter w;

        Csv(Path file, String header) throws IOException {
            w = new PrintWriter(Files.newBufferedWriter(file, StandardCharsets.UTF_8));
            w.println(header);
        }

        void row(Object... cells) {
            w.println(Arrays.stream(cells).map(c -> c instanceof Double d
                    ? (d.isNaN() ? "" : String.format(Locale.ROOT, "%.8g", d)) : String.valueOf(c))
                    .collect(Collectors.joining(",")));
            w.flush();
        }

        @Override
        public void close() {
            w.close();
        }
    }

    // ================================================================== experiment: strategies + ranking

    private record Topo(String name, long seed, List<HostFingerprint> hosts) {}

    private List<Topo> topologies() throws Exception {
        List<Topo> out = new ArrayList<>();
        out.add(new Topo("enterprise", 0, simulatedScanner.scan(new ScanTarget("192.168.10.0/24"), null).get()));
        out.add(new Topo("lab", 0, TopologyFactory.lab()));
        out.add(new Topo("ecommerce", 0, TopologyFactory.ecommerce()));
        for (String s : sizes.split(",")) {
            int n = Integer.parseInt(s.trim());
            for (int seed = 1; seed <= reps; seed++) out.add(new Topo("synthetic-" + n, seed, TopologyFactory.synthetic(n, seed)));
        }
        return out;
    }

    private void strategies() throws Exception {
        List<Topo> topos = topologies();
        log.warn("strategies: {} topologies, budgets 0..{}", topos.size(), maxBudget);
        try (Csv strat = new Csv(Path.of(outDir, "strategies.csv"),
                "topology,seed,hosts,units,edges,budget,strategy,risk,baseline,reduction_pct");
             Csv rank = new Csv(Path.of(outDir, "ranking.csv"),
                     "topology,seed,hosts,units,tau_yen_vs_marginal,tau_cvss_vs_marginal,tau_prob_vs_marginal,yen_ms")) {
            int done = 0;
            for (Topo t : topos) {
                int hosts = t.hosts().size() - 1;
                Prepared p = hosts > yenMaxHosts ? prepareImplicit(t.hosts()) : prepare(t.hosts());
                RiskModel.Compiled c = p.compiled();
                double base = optimizer.baselineRisk(c);
                int units = c.units.size();

                Map<String, List<PatchUnit>> orders = new LinkedHashMap<>();
                orders.put("CVSS_FIRST", optimizer.plan(c, PatchOptimizer.Strategy.CVSS_FIRST, maxBudget, 1).patches());
                orders.put("EXPLOIT_PROB_FIRST", optimizer.plan(c, PatchOptimizer.Strategy.EXPLOIT_PROB_FIRST, maxBudget, 1).patches());
                orders.put("GREEDY", optimizer.plan(c, PatchOptimizer.Strategy.GREEDY, maxBudget, 1).patches());

                // Yen's top-K: units on the highest-risk paths first (the earlier system's view of "what matters")
                double[] yenScore = new double[units];
                double yenMs = Double.NaN;
                if (p.graph() != null && hosts <= yenMaxHosts) {
                    long t0 = System.nanoTime();
                    List<AttackPath> paths = pathAnalyzer.findTopKAttackPaths(p.graph().graph(), p.graph().nodeMap(), yenK);
                    yenMs = ms(System.nanoTime() - t0);
                    for (AttackPath path : paths) {
                        for (int i = 0; i < path.edges().size(); i++) {
                            var cve = path.edges().get(i).getExploitedCve();
                            String target = path.hops().get(i + 1).getId();
                            if (cve == null) continue;
                            for (PatchUnit u : c.units) {
                                if (u.hostId().equals(target) && u.fixedCveIds().contains(cve.cveId())) {
                                    yenScore[u.index()] += path.cumulativeRisk();
                                }
                            }
                        }
                    }
                    List<PatchUnit> order = new ArrayList<>(c.units);
                    order.sort(Comparator.comparingDouble((PatchUnit u) -> -yenScore[u.index()]).thenComparingInt(PatchUnit::index));
                    orders.put("PATH_FIRST", order.subList(0, Math.min(maxBudget, order.size())));
                }

                for (int b = 0; b <= maxBudget; b++) {
                    for (var e : orders.entrySet()) {
                        double r = riskOfPrefix(c, e.getValue(), b);
                        strat.row(t.name(), t.seed(), hosts, units, p.edges(), b, e.getKey(), r, base, reduction(base, r));
                    }
                    double rnd = optimizer.plan(c, PatchOptimizer.Strategy.RANDOM, b, 1000 + t.seed()).risk();
                    strat.row(t.name(), t.seed(), hosts, units, p.edges(), b, "RANDOM", rnd, base, reduction(base, rnd));
                    if (units <= optimalMaxUnits) {
                        var opt = optimizer.plan(c, PatchOptimizer.Strategy.OPTIMAL, b, 1);
                        double r = opt.computed() ? opt.risk() : Double.NaN;
                        strat.row(t.name(), t.seed(), hosts, units, p.edges(), b, "OPTIMAL", r, base, reduction(base, r));
                    }
                }

                // ranking agreement: exact single-patch marginal risk reduction vs Yen score, CVSS and exploit probability
                double[] marginal = new double[units], cvss = new double[units], prob = new double[units];
                boolean[] removed = new boolean[units];
                for (PatchUnit u : c.units) {
                    removed[u.index()] = true;
                    marginal[u.index()] = base - riskModel.crownJewelRisk(c, removed);
                    removed[u.index()] = false;
                    cvss[u.index()] = u.maxCvss();
                    prob[u.index()] = c.maxExploitProbability(u.index());
                }
                rank.row(t.name(), t.seed(), hosts, units,
                        Double.isNaN(yenMs) ? Double.NaN : Stats.kendallTauB(yenScore, marginal),
                        Stats.kendallTauB(cvss, marginal), Stats.kendallTauB(prob, marginal), yenMs);

                if (++done % 5 == 0 || done == topos.size()) log.warn("strategies: {}/{} topologies", done, topos.size());
            }
        }
    }

    private static double reduction(double base, double risk) {
        return Double.isNaN(risk) || base <= 0 ? Double.NaN : 100.0 * (1.0 - risk / base);
    }

    // ================================================================== experiment: scale

    private void scale() throws Exception {
        try (Csv csv = new Csv(Path.of(outDir, "scale.csv"),
                "mode,hosts,rep,units,edges,build_ms,score_ms,compile_ms,eval_ms,yen_ms,greedy5_ms,status")) {
            // warm up the JIT on a small network so the first measured size is not penalised
            for (int i = 0; i < 3; i++) {
                measureOnce(TopologyFactory.synthetic(50, 900 + i), false);
                measureOnce(TopologyFactory.synthetic(50, 900 + i), true);
            }
            for (String mode : new String[]{"explicit", "implicit"}) {
                boolean implicit = mode.equals("implicit");
                for (String s : scaleSizes.split(",")) {
                    int n = Integer.parseInt(s.trim());
                    if (!implicit && n > explicitMax) continue;
                    int repsHere = n <= 200 ? reps : bigReps;
                    log.warn("scale[{}]: n={} x{}", mode, n, repsHere);
                    for (int rep = 1; rep <= repsHere; rep++) {
                        double[] m;
                        try {
                            m = measureOnce(TopologyFactory.synthetic(n, rep), implicit);
                        } catch (OutOfMemoryError oom) {
                            csv.row(mode, n, rep, "", "", "", "", "", "", "", "", "OOM");
                            System.gc();
                            break;
                        }
                        csv.row(mode, n, rep, (long) m[0], (long) m[1], m[2], m[3], m[4], m[5], m[6], m[7], "ok");
                    }
                }
            }
        }
    }

    /** One end-to-end pass; returns {units, edges, build, score, compile, eval, yen, greedy5} (ms). */
    private double[] measureOnce(List<HostFingerprint> hosts, boolean implicit) {
        Prepared p = implicit ? prepareImplicit(hosts) : prepare(hosts);
        RiskModel.Compiled c = p.compiled();

        long t0 = System.nanoTime();
        riskModel.evaluate(c, null);
        double evalMs = ms(System.nanoTime() - t0);

        double yenMs = Double.NaN;
        if (p.graph() != null) {
            t0 = System.nanoTime();
            pathAnalyzer.findTopKAttackPaths(p.graph().graph(), p.graph().nodeMap(), 5);
            yenMs = ms(System.nanoTime() - t0);
        }

        t0 = System.nanoTime();
        optimizer.plan(c, PatchOptimizer.Strategy.GREEDY, 5, 1);
        double greedyMs = ms(System.nanoTime() - t0);

        return new double[]{c.units.size(), p.edges(), p.buildMs(), p.scoreMs(), p.compileMs(), evalMs, yenMs, greedyMs};
    }

    // ================================================================== experiment: scan concurrency

    private void scan() throws Exception {
        int probesPerHost = 5;
        int latencyMs = 20;
        try (Csv csv = new Csv(Path.of(outDir, "scan.csv"), "hosts,probes_per_host,latency_ms,executor,rep,wall_ms")) {
            for (int hosts : new int[]{50, 200, 1000}) {
                for (String exec : new String[]{"virtual", "fixed-16", "fixed-64", "fixed-256"}) {
                    int repsHere = exec.equals("fixed-16") && hosts == 1000 ? Math.min(reps, 5) : reps;
                    for (int rep = 1; rep <= repsHere; rep++) {
                        csv.row(hosts, probesPerHost, latencyMs, exec, rep, probeAll(hosts, probesPerHost, latencyMs, exec));
                    }
                    log.warn("scan: hosts={} {} done", hosts, exec);
                }
            }
        }
    }

    /** Every host is probed on several ports; each probe blocks for {@code latencyMs} (simulated network I/O). */
    private double probeAll(int hosts, int probes, int latencyMs, String exec) throws Exception {
        ExecutorService ex = exec.equals("virtual")
                ? Executors.newVirtualThreadPerTaskExecutor()
                : Executors.newFixedThreadPool(Integer.parseInt(exec.substring(exec.indexOf('-') + 1)));
        long t0 = System.nanoTime();
        try {
            List<Future<?>> futures = new ArrayList<>(hosts * probes);
            for (int h = 0; h < hosts; h++) {
                for (int p = 0; p < probes; p++) {
                    futures.add(ex.submit(() -> {
                        Thread.sleep(latencyMs);
                        return null;
                    }));
                }
            }
            for (Future<?> f : futures) f.get();
        } finally {
            ex.shutdown();
        }
        return ms(System.nanoTime() - t0);
    }
}

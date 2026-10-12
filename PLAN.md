# NetSentinel — Completion Plan (Research-Paper Oriented)

> [!NOTE]
> The older `remaining_plan.md` describes a different project (K-Sentinel/eBPF). This plan is based on the current Java code in NetSentinel.

## 1. Current state and gaps

| Area | Status | Weakness for a paper |
|---|---|---|
| Scanner | `SimulatedNetworkScanner` only | No real network, no real data |
| CVE | NVD client, hybrid DB, simulated DB | No CPE matching quality evaluation |
| Graph | JGraphT multigraph, Yen's K-paths | Edge weight is `1 - p`, a simple heuristic |
| ML | DL4J MLP | **Trained on a hand-written formula, so it only learns that formula. It has no ground truth and no novelty.** |
| Remediation | Ansible/Bash templates | Not validated, no measured risk reduction |
| Evaluation | None | No baselines, metrics or datasets |

The ML scorer is the biggest problem. A reviewer would reject a model that approximates a formula the authors wrote (see `CompromiseScorer.trainOnSyntheticData`).

## 2. Proposed novel contribution

**Working title:** *Exploit-Aware Attack-Graph Prioritization with Learned Edge Probabilities and Budgeted Remediation Synthesis.*

Contributions, in order of strength:

1. **Learned edge exploitability from real labels.**
   - Labels: CISA KEV (exploited in the wild), Exploit-DB/Metasploit availability, EPSS.
   - Features: CVSS vector components, CWE class, age, vendor.
   - Model: gradient-boosted trees or MLP, against CVSS-only and EPSS-only baselines.
   - Evaluation: temporal split (train up to year N, test on year N+1).
2. **Path-level risk with edge correlation.**
   - Noisy-OR aggregation over parallel paths instead of independent `1-p` weights.
   - Shared-CVE/shared-service correlation penalty.
   - Result: Bayesian-attack-graph style compromise probability per host.
3. **Budgeted remediation optimization.**
   - Choose patches that minimize crown-jewel reachability probability under a patch budget.
   - Greedy vs ILP (e.g. OR-Tools) vs CVSS-first baseline.
   - Report risk reduction per patch.
4. **Reproducible Java-native pipeline.** Virtual-thread scalability benchmark, open dataset, open source release.

> [!TIP]
> Contributions 1 and 3 together make the strongest story: *learned exploitability, then optimal patching, evaluated against CVSS-first patching.*

## 3. Work plan

### Phase A — Real data and scanner (3–4 days)
- [x] Real `NetworkScanner` (`LiveNetworkScanner`: TCP connect + banner grab on virtual threads; inventory or private-range CIDR sweep); simulator kept.
- [x] Docker Compose lab (`lab/`: Apache 2.4.49, nginx 1.18.0, 2x redis 6.2.6, memcached 1.6.9; isolated project, loopback ports).
- [x] Offline NVD snapshot for reproducibility (`scripts/fetch_nvd_snapshot.py`, 497 CVEs for the simulated network and the lab).
- [x] CPE-matching test on a hand-labelled set (33 cases) and banner-to-CPE test (23 labelled banners; 5/5 correct on the live lab).

### Phase B — Learned scorer (4–5 days)
- [x] Dataset build script in `scripts/` (NVD + KEV + EPSS + Exploit-DB); manifest records file hashes.
- [x] Remove synthetic training; offline training job, trained model shipped as JSON (gradient-boosted trees, evaluated in plain Java).
- [x] Baselines: CVSS, point-in-time EPSS (current EPSS is label-leaky), logistic regression, MLP.
- [x] Metrics: AUROC, PR-AUC, Brier (+skill score), ECE, bootstrap CIs, reliability plot, temporal split (`results/`).
- [x] Feature ablation (CVSS, CWE, vendor, affected-CPE count).

### Phase C — Graph risk model (3 days)
- [x] Noisy-OR host compromise probability (`RiskModel`).
- [x] Correlated-edge variant (shared exploit = one event) + Monte Carlo cross-check; analytic model is an upper bound on cyclic graphs.
- [x] Compare with Yen's top-K: Kendall tau against the exact marginal risk reduction (`results/eval/ranking.csv`; about 0 on synthetic networks) and crown-jewel risk of a Yen path-first patching strategy vs greedy (`strategies.csv`).

### Phase D — Remediation optimizer (3–4 days)
- [x] Patch → edge-removal mapping (patch unit = upgrade one product on one host).
- [x] Greedy, exact (exhaustive; the objective is non-linear so an ILP does not apply), CVSS-first, exploit-prob-first, random; risk-vs-budget curve (`/api/scan/{id}/optimize`).
- [ ] Validate Ansible with `ansible-lint` and `--check`: `ansible-lint` (production profile) and `--syntax-check` pass in Docker via `scripts/validate_remediation.py`; `--check` is not applicable to the minimal Alpine lab containers (needs real hosts with Python). Re-scan after patching: done on the simulated inventory (`/api/scan/{id}/verify`) and on the real lab (`lab/apply_plan.py`: redis 6.2.6 -> 8.6.3 gave risk 0.0 and 0 paths, as predicted).

### Phase E — Evaluation (3 days)
- [x] 3 hand-built topologies (enterprise, lab, e-commerce) plus synthetic ones: strategy comparison at 50 and 200 hosts, scalability up to 1000 hosts (`results/eval/`).
- [x] Scalability: stage timings, K-paths latency, baseline vs optimised code, explicit vs graph-free model; scan concurrency with simulated latency (virtual threads vs fixed pools).
- [x] Docker lab end-to-end case study (real scan, plan, real upgrade, re-scan: risk 0.0024 -> 0, paths 5 -> 0).
- [x] 30 runs, mean and 95% CI (30 runs up to 200 hosts; 5 at 400 and 1000 hosts; baseline code 10 and 3).

### Phase F — Engineering polish (2 days)
- [ ] JUnit and Testcontainers tests (JUnit: 45 tests incl. real-socket scanner and end-to-end rescan; Testcontainers not used, the Docker lab covers that).
- [x] UI display of risk-reduction results (Remediate tab: KPIs, patch list, risk-vs-budget chart, re-scan verification).
- [x] README: replaced claims with measured numbers; added Docker quickstart.

### Phase G — Paper (4–5 days)
Sections: Abstract, Introduction, Related Work (MulVAL, Bayesian attack graphs, EPSS, CVSS critiques), Design, Learned Exploitability, Risk Model, Remediation Optimization, Evaluation, Threats to Validity, Conclusion.
- [ ] Figures: architecture, calibration plot, risk-vs-budget curve, scalability plot.
- [ ] Venue: workshop, IEEE/ACM security-adjacent conference, or arXiv first.

## 3b. Deviations from the original plan (as built)

The goals are unchanged (learned exploitability, then budgeted patching, evaluated against CVSS-first). The technical
approach differs from the plan in the following ways. Each one should be explained in the paper's design section.

| Area | Original plan | As built | Why |
|---|---|---|---|
| Label | KEV, Exploit-DB/Metasploit availability, EPSS | KEV: "added to KEV within 365 days of publication" (the reported result). Exploit-DB: "public exploit within 365 days" was also evaluated (`results/label_experiments.md`): AUROC 0.691 vs 0.664 (CVSS) and 0.639 (EPSS at publication), but badly calibrated (predicts 4.1% where the test rate is 0.34%) because Exploit-DB publishes far fewer exploits in recent years (6-8% of 2016-2018 CVEs, under 1% from 2022). 21% of the Exploit-DB training positives were CVE-id mapping errors (exploit dated years before the CVE) and are excluded. Metasploit is not feasible: the modules mirrored in Exploit-DB end in May 2020, so no test-year CVE has one. EPSS is a baseline, not a label. | A fixed horizon avoids right-censoring (recent CVEs have had less time to be exploited). KEV is the better target for calibrated probabilities. A real Metasploit label would need the metasploit-framework repository. |
| EPSS baseline | EPSS-only | Point-in-time EPSS: the first monthly archive snapshot after publication, with CVEs already in KEV at that date dropped from the test set. | Today's EPSS already encodes later exploitation (AUROC 0.976 vs 0.632 at publication time), so it is not a fair baseline. Several EPSS model versions are mixed across the years. |
| Features | CVSS vector, CWE, age, vendor | CVSS vector, CWE, vendor and the number of affected CPEs; no "age" feature. | Absolute age is not meaningful under a temporal split. The CPE count was added and is the second most important feature, but NVD revises it after the fact, so it may leak (ablation: AUROC 0.806 -> 0.768 without it). |
| Training years | Train up to year N, test on N+1 | Train 2016-2021, test 2022-2024 (the reported result). Sensitivity run on 2020-2021 only: gradient-boosted trees AUROC 0.826 (vs 0.806), ECE 0.0015. The shipped model is trained on all eligible years up to 2024. | KEV only started in November 2021, so CVEs published before about 2020 can hardly be positive (0.00% for 2016-2019): left truncation of the label. Retraining the shipped model from 2020 is a candidate improvement; the comparison with CVSS and EPSS holds either way. |
| Model | Gradient-boosted trees or MLP | Gradient-boosted trees (AUROC 0.806) shipped as JSON and evaluated in plain Java; logistic regression (0.775) and MLP (0.719) kept as baselines; DL4J and the formula-trained MLP removed. Training is in Python. | Best of the three on the temporal test set; no ML runtime needed in the Java app; golden vectors check Java against sklearn. |
| Risk model | Noisy-OR plus a shared-CVE/shared-service correlation penalty | Noisy-OR and a correlated variant in which "CVE c works on host h" is one event shared by all attackers. No penalty term, and no correlation across different hosts running the same service. Fixed-point solution is an upper bound on cyclic graphs; Monte Carlo checks it. | An exploit either works on a host or it does not, whoever launches it. Exact inference on cyclic graphs is intractable, so the approximation is measured instead: on optimal and greedy plans analytic and sampled risk agree within about 3% (e.g. 0.0033 vs 0.0034), while one CVSS-first plan was 9% above the sampled value in a run before the fixed-in patch model. |
| Graph semantics | Edge weight `1 - p`; reachability from the zone model | Edge weight `-ln p`; only known network-exploitable CVEs create edges (the hand-set 0.05 "reachability" edge was removed); attack paths start only at the external attacker; criticality no longer enters exploit probability. | `1 - p` is almost constant for small p, so shortest paths became "fewest hops". The 0.05 edge made patching a host's last CVE increase its reachability. Criticality affects impact, not likelihood. |
| Yen baseline | Yen's top-K by `1 - p` | Yen on one edge (the most likely CVE) per host pair, so the top-K are distinct host routes. | Yen's cost grows with edges (113 s at 400 hosts on the full multigraph); parallel CVE edges only repeat a route. Not strictly like-for-like with the earlier output. |
| Patch model | Patch -> edge-removal mapping from CVE records | A patch is "upgrade product P on host H to version T", with T from NVD fixed-in ranges. CVEs with no known fix stay (residual); CVEs that only affect T are added. Re-scan swaps the CPE for the target-version CPE. | "Upgrade removes every CVE" was optimistic: a real upgrade left 2 CVEs and the prediction was off (97% vs 100%). The new model matches real re-scans exactly. |
| Optimizer | Greedy vs ILP (OR-Tools) vs CVSS-first | Greedy, exact exhaustive search, CVSS-first, exploit-probability-first, random, and a Yen path-first baseline. Exact search only runs on topologies with at most 25 patch units. | The objective (probability that a crown jewel falls) is not linear, so an ILP would need a linearisation; exhaustive search is exact for the real objective. Greedy matched the optimum on the lab and web-shop topologies and lost slightly on the enterprise one (99.7% vs 100% at 5 patches). |
| Known exploited CVEs | not specified | CVEs already in KEV get a probability floor of 0.9 (`netsentinel.ai.known-exploited-probability`). | The model predicts future exploitation, which understates observed exploitation. The constant is hand-chosen, not learned. |
| Evaluation | Synthetic networks at 50/200/1000 hosts, 30 runs | Strategy comparison on 3 hand-built topologies and synthetic networks of 50 and 200 hosts (30 seeds); stage timings up to 1000 hosts using a graph-free model that the running app does not use; 5 runs at 400 and 1000 hosts (baseline code: 10 and 3); scan benchmark with simulated 20 ms probe latency. | The explicit attack graph is quadratic (2.5M edges at 400 hosts), so 1000 hosts needed the graph-free model. Larger runs were too slow to repeat 30 times. |
| Lab and scanner | DMZ/App/DB containers; real scanner | Five containers across all tiers (Apache 2.4.49, nginx 1.18.0, 2x redis 6.2.6, memcached 1.6.9); tier and criticality come from a declared inventory; CIDR sweeps are opt-in and private ranges only; the plan is applied by recreating containers on fixed image tags. | A scan cannot know an asset's role; the API is unauthenticated, so sweeps are off by default. `ansible --check` is not applicable to the minimal Alpine containers. |

Added beyond the plan: re-scan verification (`/api/scan/{id}/verify`), `lab/apply_plan.py`, the graph-free risk model,
performance work (20-26x faster scoring), security hardening (loopback binding, opt-in sweeps), a readable dashboard
graph, and the demo scripts and runbook (`docs/DEMO.md`).

## 4. Threats to validity to state honestly
- Lab topologies are small and hand-built.
- KEV and EPSS are proxies for real exploitability.
- Reachability is assumed from the zone model, not measured.
- Banner-based version detection is imprecise.

## 5. If time is short
Do **B → D → E**, then write. These give the novelty and the evidence. A and C are secondary.

## 6. Questions
1. What is your deadline and target venue?
2. Do you have time for the Docker lab, or should evaluation stay simulated?
3. Is a Python training script acceptable for the offline model, or must training stay in Java?

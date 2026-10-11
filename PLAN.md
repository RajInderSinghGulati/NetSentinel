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
- [ ] Real `NetworkScanner` (TCP connect and banner grab); keep the simulator for tests.
- [ ] Docker Compose lab (DMZ/App/DB containers with known vulnerable images).
- [x] Offline NVD snapshot for reproducibility (`scripts/fetch_nvd_snapshot.py`, 492 CVEs for the simulated network).
- [x] CPE-matching test on a hand-labelled set (33 cases, matcher only; banner-to-CPE accuracy still needs the real scanner).

### Phase B — Learned scorer (4–5 days)
- [x] Dataset build script in `scripts/` (NVD + KEV + EPSS + Exploit-DB); manifest records file hashes.
- [x] Remove synthetic training; offline training job, trained model shipped as JSON (gradient-boosted trees, evaluated in plain Java).
- [x] Baselines: CVSS, point-in-time EPSS (current EPSS is label-leaky), logistic regression, MLP.
- [x] Metrics: AUROC, PR-AUC, Brier (+skill score), ECE, bootstrap CIs, reliability plot, temporal split (`results/`).
- [x] Feature ablation (CVSS, CWE, vendor, affected-CPE count).

### Phase C — Graph risk model (3 days)
- [x] Noisy-OR host compromise probability (`RiskModel`).
- [x] Correlated-edge variant (shared exploit = one event) + Monte Carlo cross-check; analytic model is an upper bound on cyclic graphs.
- [ ] Compare with Yen's top-K by `1-p`: Kendall tau and crown-jewel risk difference.

### Phase D — Remediation optimizer (3–4 days)
- [x] Patch → edge-removal mapping (patch unit = upgrade one product on one host).
- [x] Greedy, exact (exhaustive; the objective is non-linear so an ILP does not apply), CVSS-first, exploit-prob-first, random; risk-vs-budget curve (`/api/scan/{id}/optimize`).
- [ ] Validate Ansible with `ansible-lint` and `--check` (`scripts/validate_remediation.py` written; structure check passes, lint needs Docker running; `--check` needs the lab). Re-scan after patching: done on the simulated inventory (`/api/scan/{id}/verify`).

### Phase E — Evaluation (3 days)
- [ ] 3 hand-built topologies plus synthetic ones at 50/200/1000 hosts.
- [ ] Scalability: scan and graph build time (virtual threads vs fixed pool), K-paths latency.
- [ ] Docker lab end-to-end case study.
- [ ] 30 runs, mean and 95% CI.

### Phase F — Engineering polish (2 days)
- [ ] JUnit and Testcontainers tests.
- [x] UI display of risk-reduction results (Remediate tab: KPIs, patch list, risk-vs-budget chart, re-scan verification).
- [ ] README: replace claims with measured numbers; add Docker quickstart.

### Phase G — Paper (4–5 days)
Sections: Abstract, Introduction, Related Work (MulVAL, Bayesian attack graphs, EPSS, CVSS critiques), Design, Learned Exploitability, Risk Model, Remediation Optimization, Evaluation, Threats to Validity, Conclusion.
- [ ] Figures: architecture, calibration plot, risk-vs-budget curve, scalability plot.
- [ ] Venue: workshop, IEEE/ACM security-adjacent conference, or arXiv first.

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

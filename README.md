# NetSentinel-AI

**Exploit-aware attack-graph prioritisation with learned edge probabilities and budgeted remediation, in Java.**

[![Java](https://img.shields.io/badge/Java-21%20LTS-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.5-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![JGraphT](https://img.shields.io/badge/JGraphT-1.5.3-blue.svg)](https://jgrapht.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

NetSentinel scans a network (simulated, or real via TCP connect and banner grabbing), maps the software it finds to
known CVEs, builds an attack graph, estimates how likely each exploit is with a model trained on real exploitation
data, computes how likely each host is to fall, and chooses a small set of upgrades that reduces the risk to the
crown-jewel hosts the most. It then generates Ansible and bash remediation, and can re-scan to check the result.

Everything is deterministic given a pinned NVD snapshot, so results are reproducible.

## Pipeline

```
 scan (simulated | live)  ->  fingerprints (host, ports, banners, CPEs)
        |
        v
 CVE matching (pinned NVD snapshot, range-aware CPE matching)  ->  attack graph (JGraphT)
        |
        v
 learned exploit probability per CVE (gradient-boosted trees, trained offline on CISA KEV)
        |
        v
 host compromise probability (correlated-exploit risk model)  ->  crown-jewel risk
        |
        v
 patch optimizer: "upgrade product P on host H to version T" under a budget  ->  Ansible / bash / report
        |
        v
 verify: apply the plan to the inventory (or the Docker lab) and re-scan
```

Key ideas:

* **Learned exploitability.** `scripts/train.py` trains on CVSS vector, CWE, vendor and affected-product count with
  label "added to CISA KEV within 365 days of publication", using a temporal split (train up to 2021, test 2022-2024).
  The shipped model is exported as JSON and evaluated in plain Java (`LearnedExploitModel`), with no ML runtime.
* **Risk model.** A host falls if some exploit from a compromised neighbour works. "CVE c works on host h" is one
  event shared by every attacker (correlated variant); a noisy-OR variant and a Monte Carlo checker are included.
* **Fixed-in-version patching.** A patch is an upgrade to the version NVD says fixes the host's CVEs. CVEs with no
  known fix stay, and CVEs that only affect the new version are added, so predictions match real re-scans.

## Measured results

All numbers are produced by the scripts in this repo; see `results/` and `results/eval/summary.md`.

| Question | Result |
|---|---|
| Does the learned model beat CVSS at ranking exploited CVEs? | Test AUROC 0.806 (95% CI 0.776-0.835) vs 0.735 for CVSS and 0.632 for EPSS taken at publication time. PR-AUC is low for every model (0.009; base rate 0.2%). Aggregate calibration is good (ECE 0.0006) but Brier skill over the base rate is about zero. |
| How many patches cut crown-jewel risk by 90%? | Hand-built networks: 2 (greedy and exact) vs 6-8 for CVSS-first. 50-host synthetic networks (30 seeds): greedy 5.0 +- 0.4; CVSS-first reaches 0-2% with 10 patches. |
| Does greedy match the exact optimum? | On the lab and web-shop topologies yes; on the enterprise topology greedy loses slightly at 5 patches (99.7% vs 100%). |
| Do predictions match a real re-scan? | Yes on the Docker lab: upgrading redis 6.2.6 to 8.6.3 took risk from 0.0024 to 0 and attack paths from 5 to 0, as predicted. |
| Scalability | The explicit attack graph grows quadratically (2.5M edges at 400 hosts). The graph-free model handles 1,000 hosts (compile 1.6 s, greedy for 5 patches 23 s). Optimisations gave 20-26x faster scoring and 4-16x faster evaluation, path search and greedy selection. |
| Scan concurrency | With simulated 20 ms probes, virtual threads finish 5,000 probes in about 27 ms; a fixed pool of 16 takes 6.4 s. |

Caveats: risk counts known CVEs only; reachability comes from a declared zone model, not measurement; the synthetic
networks and the five-container lab are small; EPSS and KEV are proxies for real exploitation.

## Quickstart

Requirements: JDK 21+, Maven 3.8+ (Python 3.10+ with pandas and scikit-learn only for the ML scripts, Docker for the lab).

```bash
mvn clean test                       # 45 tests, about 30 s
mvn spring-boot:run                  # dashboard at http://localhost:8080 (loopback only)
```

Simulated scan:

```bash
curl -X POST http://localhost:8080/api/scan/sync -H "Content-Type: application/json" \
     -d '{"cidr":"192.168.10.0/24"}'
curl "http://localhost:8080/api/scan/{scanId}/optimize?maxBudget=6&mcTrials=20000"   # risk vs budget, all strategies
curl "http://localhost:8080/api/scan/{scanId}/verify?strategy=OPTIMAL&budget=3"        # apply plan and re-scan
curl "http://localhost:8080/api/scan/{scanId}/remediation"                            # Ansible, inventory, bash, report
```

### Real scan against the Docker lab

`lab/` is an isolated Docker Compose project (own name and networks, containers named `nslab-*`, ports bound to
127.0.0.1) with Apache 2.4.49, nginx 1.18.0, two redis 6.2.6 and memcached 1.6.9. It touches no other Docker project.

```bash
docker compose -f lab/docker-compose.yml up -d
curl -X POST http://localhost:8080/api/scan/sync -H "Content-Type: application/json" \
     -d '{"cidr":"lab","mode":"live"}'
python lab/apply_plan.py --scan-id <scanId> --strategy OPTIMAL --budget 3     # upgrade the planned containers
# re-scan, then restore the vulnerable baseline:
docker compose -f lab/docker-compose.yml up -d --force-recreate
docker compose -f lab/docker-compose.yml down                                  # remove the lab
```

Live scans only probe the hosts declared in `lab/inventory.yml` (a scan cannot know an asset's tier or criticality).
CIDR sweeps of private ranges are off unless `netsentinel.scan.live.allow-cidr-sweep=true`; scan only networks you are
authorised to test.

### Reproduce the data and model

```bash
python scripts/fetch_nvd_snapshot.py          # pinned NVD snapshot for the scanned products
python scripts/build_dataset.py               # NVD + CISA KEV + Exploit-DB + EPSS -> data/cve_features.csv (about 20 min)
python scripts/fetch_epss_history.py          # point-in-time EPSS baseline
python scripts/train.py                       # temporal split, baselines, ablation -> results/
python scripts/export_model.py                # ship the model as JSON for the Java side
```

### Run the evaluation

```bash
powershell -File scripts/run_eval.ps1 -Run strategies,scale,scan -Reps 30
python scripts/summarize_eval.py              # tables and figures in results/eval/
python scripts/validate_remediation.py        # ansible-lint + syntax-check of the generated playbook (needs Docker)
```

## Configuration (application.yml)

| Key | Default | Meaning |
|---|---|---|
| `server.address` | `127.0.0.1` | The REST API has no authentication; keep it on loopback or put it behind auth. |
| `netsentinel.scan.mode` | `simulated` | Default scanner when a request gives no `mode`. |
| `netsentinel.scan.live.inventory` | `lab/inventory.yml` | Declared assets for live scans. |
| `netsentinel.scan.live.allow-cidr-sweep` | `false` | Allow a private-range CIDR as a live scan target. |
| `netsentinel.nvd.offline-only` | `false` | `true` = never call the live NVD API (reproducible runs). |
| `netsentinel.ai.known-exploited-probability` | `0.9` | Probability floor for CVEs already in CISA KEV. |
| `netsentinel.ai.k-paths` | `5` | Attack routes reported per scan. |
| `netsentinel.remediation.budget` | `3` | Patches in the automatic plan. |
| `netsentinel.graph.max-edges` | `3000000` | A scan whose attack graph would be larger fails with a clear message. |

## Code map

| Path | Contents |
|---|---|
| `scanner/` | `LiveNetworkScanner`, `BannerFingerprinter`, `SimulatedNetworkScanner` |
| `cve/` | offline and live NVD sources, range-aware `CpeMatcher`, `UpgradePlanner` |
| `graph/` | `AttackGraphBuilder` (tiered reachability: external -> DMZ -> application -> data -> crown jewel) |
| `ai/` | `LearnedExploitModel`, `CompromiseScorer`, `RiskModel`, `PatchOptimizer`, `RemediationGenerator` |
| `eval/` | evaluation harness (runs only with `netsentinel.eval.run`) |
| `scripts/` | dataset, training, export, evaluation and validation scripts |
| `lab/` | Docker lab and the script that applies a plan to it |

## License
Apache License 2.0 (as stated by the project; no `LICENSE` file has been added to the repository yet).

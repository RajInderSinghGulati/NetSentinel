# NetSentinel evaluation summary

```
date: 2026-10-12T02:34:03
cpu: AMD Ryzen 5 4600H with Radeon Graphics          (6 cores / 12 threads)
ram_gb: 7.4
os: Microsoft Windows 11 Home Single Language
java: java version "24.0.2" 2025-07-15
heap: -Xmx6g
```

## 1. Risk reduction by patching strategy

Crown-jewel risk reduction (%) after applying the first *B* patches chosen by each strategy. Hand-built topologies are single instances; synthetic networks are 30 random topologies (mean ± 95% CI). Optimal is exhaustive and only run on topologies with at most 25 patch units.

**Budget B = 1**

| topology | CVSS-first | Exploit-prob-first | Yen path-first | Random | Greedy | Optimal |
|---|---|---|---|---|---|---|
| enterprise (n=1) | 0.0 ± 0.0 | 0.0 ± 0.0 | 77.5 ± 0.0 | 7.2 ± 0.0 | 77.5 ± 0.0 | 77.5 ± 0.0 |
| lab (n=1) | 100.0 ± 0.0 | 9.7 ± 0.0 | 100.0 ± 0.0 | 41.6 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 |
| ecommerce (n=1) | 0.0 ± 0.0 | 0.0 ± 0.0 | 68.9 ± 0.0 | 8.9 ± 0.0 | 68.9 ± 0.0 | 68.9 ± 0.0 |
| synthetic-50 (n=30) | 0.0 ± 0.0 | 0.0 ± 0.0 | 31.7 ± 7.6 | 1.4 ± 0.2 | 40.9 ± 4.8 | – |
| synthetic-200 (n=30) | 0.0 ± 0.0 | 0.0 ± 0.0 | – | 0.3 ± 0.0 | 14.1 ± 1.3 | – |

**Budget B = 3**

| topology | CVSS-first | Exploit-prob-first | Yen path-first | Random | Greedy | Optimal |
|---|---|---|---|---|---|---|
| enterprise (n=1) | 0.0 ± 0.0 | 0.0 ± 0.0 | 77.5 ± 0.0 | 20.0 ± 0.0 | 99.7 ± 0.0 | 99.7 ± 0.0 |
| lab (n=1) | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 |
| ecommerce (n=1) | 0.0 ± 0.0 | 0.0 ± 0.0 | 68.9 ± 0.0 | 26.1 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 |
| synthetic-50 (n=30) | 0.0 ± 0.0 | 0.0 ± 0.0 | 42.1 ± 5.4 | 4.2 ± 0.4 | 75.6 ± 4.0 | – |
| synthetic-200 (n=30) | 0.0 ± 0.0 | 0.0 ± 0.0 | – | 1.1 ± 0.1 | 39.0 ± 2.3 | – |

**Budget B = 5**

| topology | CVSS-first | Exploit-prob-first | Yen path-first | Random | Greedy | Optimal |
|---|---|---|---|---|---|---|
| enterprise (n=1) | 79.2 ± 0.0 | 97.1 ± 0.0 | 77.5 ± 0.0 | 32.6 ± 0.0 | 99.7 ± 0.0 | 100.0 ± 0.0 |
| lab (n=1) | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 |
| ecommerce (n=1) | 2.3 ± 0.0 | 79.5 ± 0.0 | 69.1 ± 0.0 | 46.2 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 |
| synthetic-50 (n=30) | 0.3 ± 0.5 | 0.0 ± 0.0 | 42.1 ± 5.4 | 7.0 ± 0.4 | 91.7 ± 2.2 | – |
| synthetic-200 (n=30) | 0.0 ± 0.0 | 0.0 ± 0.0 | – | 1.7 ± 0.1 | 58.4 ± 2.1 | – |

**Budget B = 10**

| topology | CVSS-first | Exploit-prob-first | Yen path-first | Random | Greedy | Optimal |
|---|---|---|---|---|---|---|
| enterprise (n=1) | 98.9 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 | 78.2 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 |
| lab (n=1) | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 |
| ecommerce (n=1) | 100.0 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 | 96.9 ± 0.0 | 100.0 ± 0.0 | 100.0 ± 0.0 |
| synthetic-50 (n=30) | 2.3 ± 2.0 | 0.0 ± 0.0 | 43.0 ± 6.0 | 14.2 ± 0.6 | 99.8 ± 0.0 | – |
| synthetic-200 (n=30) | 0.0 ± 0.0 | 0.0 ± 0.0 | – | 3.6 ± 0.2 | 77.9 ± 1.5 | – |

**Reaching a 90% cut in crown-jewel risk within 10 patches.** Each cell: share of topologies that reach it, and the mean number of patches among those that do (mean ± 95% CI; hand-built = single run).

| topology | CVSS-first | Exploit-prob-first | Yen path-first | Random | Greedy | Optimal |
|---|---|---|---|---|---|---|
| enterprise | 1/1: 8 | 1/1: 5 | 1/1: 6 | 0/1 (never) | 1/1: 2 | 1/1: 2 |
| lab | 1/1: 1 | 1/1: 2 | 1/1: 1 | 1/1: 3 | 1/1: 1 | 1/1: 1 |
| ecommerce | 1/1: 6 | 1/1: 6 | 1/1: 6 | 1/1: 9 | 1/1: 2 | 1/1: 2 |
| synthetic-50 | 0/30 (never) | 0/30 (never) | 0/30 (never) | 0/30 (never) | 30/30: 5.0 ± 0.4 | – |
| synthetic-200 | 0/30 (never) | 0/30 (never) | – | 0/30 (never) | 0/30 (never) | – |

## 2. Agreement of patch rankings with the exact single-patch risk reduction

Kendall's tau-b between the ranking of patch units by *exact marginal risk reduction* and the ranking by (a) Yen's top-K path score (K=10), (b) highest CVSS, (c) highest exploit probability. 1 = identical order; 0 = unrelated. Yen is only computed for networks of at most 100 hosts.

| topology | Yen path score | CVSS | Exploit probability |
|---|---|---|---|
| enterprise (n=1) | 0.17 ± 0.00 | 0.21 ± 0.00 | 0.44 ± 0.00 |
| lab (n=1) | 0.71 ± 0.00 | 0.94 ± 0.00 | -0.24 ± 0.00 |
| ecommerce (n=1) | 0.24 ± 0.00 | 0.08 ± 0.00 | 0.10 ± 0.00 |
| synthetic-50 (n=30) | 0.05 ± 0.03 | -0.00 ± 0.03 | 0.10 ± 0.03 |
| synthetic-200 (n=30) | n/a | -0.03 ± 0.02 | 0.11 ± 0.01 |

## 3. Scalability of the analysis pipeline

Wall-clock time per stage on synthetic networks (mean ± 95% CI over repeated runs on different random topologies; JIT warmed up first). *build* = CVE lookup (+ edge construction in explicit mode); *score* = learned-model scoring of edges; *compile* = risk-model compilation; *eval* = one risk evaluation; *Yen K=5* = top-5 attack routes; *greedy B=5* = choosing 5 patches greedily.

| pipeline | hosts | runs | patch units | edges / events | build | score | compile | eval | Yen K=5 | greedy B=5 |
|---|---|---|---|---|---|---|---|---|---|---|
| explicit (baseline code) | 50 | 10 | 67 | 38,916 | 31.0 ± 5.5 ms | 214.9 ± 17.1 ms | 199.3 ± 29.4 ms | 0.3 ± 0.1 ms | 231.8 ± 19.7 ms | 50.7 ± 5.3 ms |
| explicit (baseline code) | 100 | 10 | 133 | 152,681 | 137.3 ± 7.3 ms | 854.5 ± 44.3 ms | 492.5 ± 28.9 ms | 0.9 ± 0.1 ms | 1.72 ± 0.08 s | 507.6 ± 104.0 ms |
| explicit (baseline code) | 200 | 10 | 270 | 633,105 | 662.6 ± 72.3 ms | 3.56 ± 0.12 s | 1.62 ± 0.10 s | 4.4 ± 0.3 ms | 14.09 ± 0.35 s | 6.02 ± 0.83 s |
| explicit (baseline code) | 400 | 3 | 535 | 2,520,452 | 3.30 ± 0.32 s | 13.87 ± 0.61 s | 5.71 ± 0.10 s | 26.8 ± 27.7 ms | 112.60 ± 4.88 s | 41.29 ± 3.19 s |
| explicit (optimized) | 50 | 30 | 68 | 38,930 | 28.6 ± 1.0 ms | 10.5 ± 0.3 ms | 82.0 ± 2.3 ms | 0.0 ± 0.0 ms | 23.5 ± 0.7 ms | 13.8 ± 0.7 ms |
| explicit (optimized) | 100 | 30 | 135 | 156,796 | 134.7 ± 4.5 ms | 36.3 ± 3.3 ms | 265.2 ± 13.7 ms | 0.1 ± 0.0 ms | 140.3 ± 3.8 ms | 90.3 ± 5.4 ms |
| explicit (optimized) | 200 | 30 | 269 | 636,861 | 668.0 ± 30.4 ms | 137.4 ± 13.3 ms | 1.17 ± 0.05 s | 0.4 ± 0.0 ms | 1.04 ± 0.03 s | 429.6 ± 37.9 ms |
| explicit (optimized) | 400 | 5 | 536 | 2,571,236 | 3.07 ± 0.23 s | 619.8 ± 258.0 ms | 4.78 ± 0.28 s | 1.6 ± 0.8 ms | 7.18 ± 0.60 s | 3.53 ± 1.46 s |
| graph-free (optimized) | 50 | 30 | 68 | 1,513 | 0.8 ± 0.1 ms | – | 48.8 ± 4.0 ms | 0.1 ± 0.0 ms | – | 14.3 ± 0.8 ms |
| graph-free (optimized) | 100 | 30 | 135 | 3,030 | 1.2 ± 0.1 ms | – | 64.9 ± 2.3 ms | 0.2 ± 0.0 ms | – | 70.1 ± 2.5 ms |
| graph-free (optimized) | 200 | 30 | 269 | 6,179 | 2.4 ± 0.1 ms | – | 123.0 ± 5.0 ms | 0.5 ± 0.1 ms | – | 336.3 ± 15.9 ms |
| graph-free (optimized) | 400 | 5 | 536 | 12,258 | 4.8 ± 0.5 ms | – | 335.2 ± 45.4 ms | 0.6 ± 0.3 ms | – | 1.38 ± 0.17 s |
| graph-free (optimized) | 1000 | 5 | 1333 | 30,451 | 11.5 ± 0.3 ms | – | 1.62 ± 0.04 s | 3.1 ± 0.7 ms | – | 22.72 ± 0.40 s |

**Speed-up of the optimized pipeline over the baseline code** (same hosts; ratio of mean times)

| hosts | score | eval | Yen K=5 | greedy B=5 |
|---|---|---|---|---|
| 50 | 20.4x | 5.5x | 9.9x | 3.7x |
| 100 | 23.5x | 6.4x | 12.2x | 5.6x |
| 200 | 25.9x | 11.9x | 13.6x | 14.0x |
| 400 | 22.4x | 16.3x | 15.7x | 11.7x |

## 4. Scan concurrency model

Each host is probed on 5 ports; every probe blocks for a simulated 20 ms of network latency (`Thread.sleep`, not real traffic). Wall time to finish all probes (mean ± 95% CI).

| hosts | virtual threads | fixed pool 16 | fixed pool 64 | fixed pool 256 |
|---|---|---|---|---|
| 50 | 21.9 ± 0.3 ms (n=30) | 331.1 ± 0.5 ms (n=30) | 88.0 ± 0.4 ms (n=30) | 47.1 ± 3.1 ms (n=30) |
| 200 | 22.8 ± 0.3 ms (n=30) | 1.29 ± 0.00 s (n=30) | 334.0 ± 0.7 ms (n=30) | 107.3 ± 2.0 ms (n=30) |
| 1000 | 27.4 ± 0.5 ms (n=30) | 6.43 ± 0.00 s (n=5) | 1.63 ± 0.01 s (n=30) | 430.8 ± 1.7 ms (n=30) |

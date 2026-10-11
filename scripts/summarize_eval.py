#!/usr/bin/env python3
"""Summarise the Phase E evaluation CSVs into tables (results/eval/summary.md) and figures.

Inputs  (results/eval/): strategies.csv, ranking.csv, scale.csv, scale_baseline.csv, scan.csv, environment.txt
Outputs (results/eval/): summary.md, fig_risk_vs_budget.png, fig_scalability.png, fig_scan.png

Every "mean ± x" is a mean with a 95% confidence interval half-width (Student t) over independent runs
(random topologies for strategy results, repeated timings for scalability).
"""
import pathlib

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "eval"

STRATEGY_ORDER = ["CVSS_FIRST", "EXPLOIT_PROB_FIRST", "PATH_FIRST", "RANDOM", "GREEDY", "OPTIMAL"]
STRATEGY_LABEL = {"CVSS_FIRST": "CVSS-first", "EXPLOIT_PROB_FIRST": "Exploit-prob-first",
                  "PATH_FIRST": "Yen path-first", "RANDOM": "Random", "GREEDY": "Greedy", "OPTIMAL": "Optimal"}
COLORS = {"CVSS_FIRST": "#f59e0b", "EXPLOIT_PROB_FIRST": "#8b5cf6", "PATH_FIRST": "#ef4444",
          "RANDOM": "#64748b", "GREEDY": "#06b6d4", "OPTIMAL": "#10b981"}


def ci(x):
    x = pd.Series(x).dropna()
    n = len(x)
    if n < 2:
        return 0.0
    return stats.t.ppf(0.975, n - 1) * x.std(ddof=1) / np.sqrt(n)


def fmt(x, digits=1):
    x = pd.Series(x).dropna()
    if x.empty:
        return "n/a"
    return f"{x.mean():.{digits}f} ± {ci(x):.{digits}f}"


def ms_fmt(x):
    x = pd.Series(x).dropna()
    if x.empty:
        return "n/a"
    m = x.mean()
    if m >= 1000:
        return f"{m / 1000:.2f} ± {ci(x) / 1000:.2f} s"
    return f"{m:.1f} ± {ci(x):.1f} ms"


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def strategies_section(md):
    d = pd.read_csv(OUT / "strategies.csv")
    md.append("## 1. Risk reduction by patching strategy\n")
    md.append("Crown-jewel risk reduction (%) after applying the first *B* patches chosen by each strategy. "
              "Hand-built topologies are single instances; synthetic networks are 30 random topologies "
              "(mean ± 95% CI). Optimal is exhaustive and only run on topologies with at most 25 patch units.\n")
    groups = ["enterprise", "lab", "ecommerce", "synthetic-50", "synthetic-200"]
    for budget in (1, 3, 5, 10):
        rows = []
        for g in groups:
            sub = d[(d.topology == g) & (d.budget == budget)]
            if sub.empty:
                continue
            row = [f"{g} (n={sub.seed.nunique() if g.startswith('synthetic') else 1})"]
            for s in STRATEGY_ORDER:
                x = sub[sub.strategy == s].reduction_pct
                row.append(fmt(x) if not x.dropna().empty else "–")
            rows.append(row)
        md.append(f"**Budget B = {budget}**\n")
        md.append(md_table(["topology"] + [STRATEGY_LABEL[s] for s in STRATEGY_ORDER], rows) + "\n")

    # patches needed to reach 90% reduction
    md.append("**Reaching a 90% cut in crown-jewel risk within 10 patches.** Each cell: share of topologies that reach "
              "it, and the mean number of patches among those that do (mean ± 95% CI; hand-built = single run).\n")
    rows = []
    for g in groups:
        sub = d[d.topology == g]
        if sub.empty:
            continue
        row = [g]
        for s in STRATEGY_ORDER:
            runs = list(sub[sub.strategy == s].groupby("seed"))
            if not runs:
                row.append("–")
                continue
            need = []
            for seed, run in runs:
                ok = run[run.reduction_pct >= 90].budget
                if len(ok):
                    need.append(float(ok.min()))
            share = f"{len(need)}/{len(runs)}"
            if not need:
                row.append(f"{share} (never)")
            elif len(runs) == 1:
                row.append(f"{share}: {int(need[0])}")
            else:
                row.append(f"{share}: {pd.Series(need).mean():.1f} ± {ci(need):.1f}")
        rows.append(row)
    md.append(md_table(["topology"] + [STRATEGY_LABEL[s] for s in STRATEGY_ORDER], rows) + "\n")

    # figure
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.2), sharey=True)
    for ax, g in zip(axes, ["enterprise", "ecommerce", "synthetic-50"]):
        sub = d[d.topology == g]
        for s in STRATEGY_ORDER:
            x = sub[sub.strategy == s]
            if x.empty or x.reduction_pct.dropna().empty:
                continue
            agg = x.groupby("budget").reduction_pct.agg(["mean", lambda v: ci(v)])
            agg.columns = ["mean", "ci"]
            ax.plot(agg.index, agg["mean"], marker="o", ms=3, label=STRATEGY_LABEL[s], color=COLORS[s],
                    lw=3 if s == "OPTIMAL" else 1.8)
            if g.startswith("synthetic"):
                ax.fill_between(agg.index, agg["mean"] - agg["ci"], agg["mean"] + agg["ci"], color=COLORS[s], alpha=0.15)
        ax.set_title(g + (" (mean ± 95% CI, 30 seeds)" if g.startswith("synthetic") else ""))
        ax.set_xlabel("patch budget")
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("crown-jewel risk reduction (%)")
    axes[0].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "fig_risk_vs_budget.png", dpi=150)
    plt.close(fig)


def ranking_section(md):
    r = pd.read_csv(OUT / "ranking.csv")
    md.append("## 2. Agreement of patch rankings with the exact single-patch risk reduction\n")
    md.append("Kendall's tau-b between the ranking of patch units by *exact marginal risk reduction* and the ranking by "
              "(a) Yen's top-K path score (K=10), (b) highest CVSS, (c) highest exploit probability. "
              "1 = identical order; 0 = unrelated. Yen is only computed for networks of at most 100 hosts.\n")
    rows = []
    for g, sub in r.groupby("topology", sort=False):
        rows.append([f"{g} (n={len(sub)})", fmt(sub.tau_yen_vs_marginal, 2), fmt(sub.tau_cvss_vs_marginal, 2),
                     fmt(sub.tau_prob_vs_marginal, 2)])
    md.append(md_table(["topology", "Yen path score", "CVSS", "Exploit probability"], rows) + "\n")


def scalability_section(md):
    new = pd.read_csv(OUT / "scale.csv")
    base_file = OUT / "scale_baseline.csv"
    frames = []
    if base_file.exists():
        b = pd.read_csv(base_file)
        b.insert(0, "mode", "explicit (baseline code)")
        frames.append(b)
    new["mode"] = new["mode"].replace({"explicit": "explicit (optimized)", "implicit": "graph-free (optimized)"})
    frames.append(new)
    d = pd.concat(frames, ignore_index=True)
    d = d[d.status == "ok"] if "status" in d else d

    md.append("## 3. Scalability of the analysis pipeline\n")
    md.append("Wall-clock time per stage on synthetic networks (mean ± 95% CI over repeated runs on different random "
              "topologies; JIT warmed up first). *build* = CVE lookup (+ edge construction in explicit mode); "
              "*score* = learned-model scoring of edges; *compile* = risk-model compilation; *eval* = one risk evaluation; "
              "*Yen K=5* = top-5 attack routes; *greedy B=5* = choosing 5 patches greedily.\n")
    rows = []
    for (mode, n), sub in d.groupby(["mode", "hosts"], sort=False):
        rows.append([mode, n, len(sub), f"{sub.units.mean():.0f}", f"{sub.edges.mean():,.0f}",
                     ms_fmt(sub.build_ms), ms_fmt(sub.score_ms) if sub.score_ms.fillna(0).mean() > 0 else "–",
                     ms_fmt(sub.compile_ms), ms_fmt(sub.eval_ms),
                     ms_fmt(sub.yen_ms) if sub.yen_ms.notna().any() else "–", ms_fmt(sub.greedy5_ms)])
    md.append(md_table(["pipeline", "hosts", "runs", "patch units", "edges / events", "build", "score", "compile",
                        "eval", "Yen K=5", "greedy B=5"], rows) + "\n")

    # speedups at the sizes where both exist
    md.append("**Speed-up of the optimized pipeline over the baseline code** (same hosts; ratio of mean times)\n")
    rows = []
    for n in sorted(d.hosts.unique()):
        b = d[(d["mode"] == "explicit (baseline code)") & (d.hosts == n)]
        o = d[(d["mode"] == "explicit (optimized)") & (d.hosts == n)]
        if b.empty or o.empty:
            continue
        def sp(col):
            bm, om = b[col].mean(), o[col].mean()
            return f"{bm / om:.1f}x" if om and not np.isnan(om) and om > 0 else "n/a"
        rows.append([n, sp("score_ms"), sp("eval_ms"), sp("yen_ms"), sp("greedy5_ms")])
    if rows:
        md.append(md_table(["hosts", "score", "eval", "Yen K=5", "greedy B=5"], rows) + "\n")

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.2))
    for ax, (col, title) in zip(axes, [("greedy5_ms", "greedy patch selection (B=5)"), ("yen_ms", "Yen top-5 routes"),
                                       ("eval_ms", "one risk evaluation")]):
        for mode, sub in d.groupby("mode", sort=False):
            agg = sub.groupby("hosts")[col].agg(["mean", ci]).dropna()
            if agg.empty:
                continue
            ax.errorbar(agg.index, agg["mean"], yerr=agg["ci"], marker="o", capsize=3, label=mode)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("hosts")
        ax.set_ylabel("ms")
        ax.set_title(title)
        ax.grid(alpha=0.3, which="both")
    axes[0].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "fig_scalability.png", dpi=150)
    plt.close(fig)


def scan_section(md):
    s = pd.read_csv(OUT / "scan.csv")
    md.append("## 4. Scan concurrency model\n")
    lat = int(s.latency_ms.iloc[0])
    probes = int(s.probes_per_host.iloc[0])
    md.append(f"Each host is probed on {probes} ports; every probe blocks for a simulated {lat} ms of network latency "
              "(`Thread.sleep`, not real traffic). Wall time to finish all probes (mean ± 95% CI).\n")
    rows = []
    for hosts, sub in s.groupby("hosts"):
        row = [hosts]
        for ex in ["virtual", "fixed-16", "fixed-64", "fixed-256"]:
            x = sub[sub.executor == ex].wall_ms
            row.append(ms_fmt(x) + f" (n={len(x)})")
        rows.append(row)
    md.append(md_table(["hosts", "virtual threads", "fixed pool 16", "fixed pool 64", "fixed pool 256"], rows) + "\n")

    fig, ax = plt.subplots(figsize=(6, 4.2))
    for ex in ["virtual", "fixed-16", "fixed-64", "fixed-256"]:
        agg = s[s.executor == ex].groupby("hosts").wall_ms.agg(["mean", ci])
        ax.errorbar(agg.index, agg["mean"], yerr=agg["ci"], marker="o", capsize=3, label=ex)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("hosts")
    ax.set_ylabel("scan wall time (ms)")
    ax.grid(alpha=0.3, which="both")
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUT / "fig_scan.png", dpi=150)
    plt.close(fig)


def main():
    md = ["# NetSentinel evaluation summary\n"]
    env = OUT / "environment.txt"
    if env.exists():
        md.append("```\n" + env.read_text(encoding="utf-8").strip() + "\n```\n")
    for name, fn in [("strategies.csv", strategies_section), ("ranking.csv", ranking_section),
                     ("scale.csv", scalability_section), ("scan.csv", scan_section)]:
        if (OUT / name).exists():
            fn(md)
        else:
            md.append(f"*(missing {name})*\n")
    (OUT / "summary.md").write_text("\n".join(md), encoding="utf-8")
    print(f"wrote {OUT / 'summary.md'}")


if __name__ == "__main__":
    main()

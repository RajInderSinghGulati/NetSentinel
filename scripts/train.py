#!/usr/bin/env python3
"""Train and evaluate exploitability models on data/cve_features.csv.

Label (default `kev365`): the CVE was added to CISA KEV within 365 days of its NVD
publication date. A fixed horizon avoids right-censoring bias (recent CVEs have had
less time to be exploited), so only CVEs published at least 365 days before the KEV
snapshot are used. `--label kev_ever` and `--label exploitdb` are also available.

Split is temporal: train on years <= --train-end, test on --test-start..--test-end.

Models: CVSS-only, EPSS-only (baseline; EPSS is a *current* score so it leaks future
information relative to the test years and is shown only as an upper-reference
baseline), logistic regression, gradient-boosted trees, MLP.

Outputs (results/): metrics.json, ablation.json, calibration.png
"""
import argparse
import json
import pathlib
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import calibration_curve
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

EXPLOIT_LEAD_DAYS = 30   # an exploit may legitimately precede the NVD entry by a few weeks

CVSS_CATS = ["av", "ac", "pr", "ui", "scope", "conf_impact", "integ_impact", "avail_impact"]


def build_label(df, label, horizon_days=365):
    pub = pd.to_datetime(df["published"])
    snapshot = pd.Timestamp(json.loads((ROOT / "data/manifest.json").read_text())["built"])
    if label == "kev365":
        added = pd.to_datetime(df["kev_date_added"], errors="coerce")
        y = ((added - pub).dt.days <= horizon_days) & (added.notna())
        eligible = pub <= snapshot - pd.Timedelta(days=horizon_days)
        # a CVE added to KEV *before* publication-date + horizon is positive; negatives need full horizon
        return y.astype(int), eligible
    if label == "kev_ever":
        return df["kev"].astype(int), pub <= snapshot - pd.Timedelta(days=horizon_days)
    if label == "exploitdb":
        return df["exploitdb"].astype(int), pub <= snapshot - pd.Timedelta(days=horizon_days)
    if label in ("exploitdb365", "msf365"):
        # public exploit (any Exploit-DB entry) or Metasploit module within 365 days of NVD publication
        col = "exploitdb_first_date" if label == "exploitdb365" else "msf_first_date"
        first = pd.to_datetime(df[col], errors="coerce")
        lag = (first - pub).dt.days
        # An exploit dated long BEFORE the CVE existed is a CVE-id mapping error in Exploit-DB (e.g. a 2012
        # exploit listed for a 2024 CVE), not a real label: such CVEs are left out instead of counted as positives.
        y = lag.notna() & (lag <= horizon_days) & (lag >= -EXPLOIT_LEAD_DAYS)
        eligible = (pub <= snapshot - pd.Timedelta(days=horizon_days)) & ~(lag < -EXPLOIT_LEAD_DAYS)
        return y.astype(int), eligible
    raise SystemExit(f"unknown label {label}")


class Features:
    """Fits category vocabularies on the training set only (no test leakage)."""

    def __init__(self, groups, top_cwe=60, top_vendor=60):
        self.groups, self.top_cwe, self.top_vendor = groups, top_cwe, top_vendor

    def fit(self, df):
        self.cwe_vocab = list(df["cwe"].value_counts().head(self.top_cwe).index)
        self.vendor_vocab = list(df["vendor"].value_counts().head(self.top_vendor).index)
        self.cvss_vocab = {c: sorted(df[c].dropna().unique()) for c in CVSS_CATS}
        self.names = self._names()
        return self

    def _names(self):
        n = []
        if "cvss" in self.groups:
            n.append("cvss_base")
            for c in CVSS_CATS:
                n += [f"{c}={v}" for v in self.cvss_vocab[c]]
        if "cwe" in self.groups:
            n += [f"cwe={v}" for v in self.cwe_vocab] + ["cwe=other"]
        if "vendor" in self.groups:
            n += [f"vendor={v}" for v in self.vendor_vocab] + ["vendor=other"]
        if "cpes" in self.groups:
            n.append("log_n_affected_cpes")
        return n

    def transform(self, df):
        cols = []
        if "cvss" in self.groups:
            cols.append(df["cvss_base"].to_numpy(float)[:, None] / 10.0)
            for c in CVSS_CATS:
                cols.append(np.stack([(df[c] == v).to_numpy(float) for v in self.cvss_vocab[c]], 1))
        if "cwe" in self.groups:
            cols.append(np.stack([(df["cwe"] == v).to_numpy(float) for v in self.cwe_vocab], 1))
            cols.append((~df["cwe"].isin(self.cwe_vocab)).to_numpy(float)[:, None])
        if "vendor" in self.groups:
            cols.append(np.stack([(df["vendor"] == v).to_numpy(float) for v in self.vendor_vocab], 1))
            cols.append((~df["vendor"].isin(self.vendor_vocab)).to_numpy(float)[:, None])
        if "cpes" in self.groups:
            cols.append(np.log1p(df["n_affected_cpes"].to_numpy(float))[:, None])
        return np.hstack(cols)


def ece(y, p, bins=10):
    """Expected calibration error with equal-mass bins."""
    order = np.argsort(p)
    err = 0.0
    for chunk in np.array_split(order, bins):
        err += len(chunk) / len(y) * abs(y[chunk].mean() - p[chunk].mean())
    return float(err)


def metrics(y, p, train_prevalence=None):
    b = float(brier_score_loss(y, np.clip(p, 0, 1)))
    out = {"auroc": float(roc_auc_score(y, p)),
           "pr_auc": float(average_precision_score(y, p)),
           "brier": b, "ece": ece(y, p),
           "mean_pred": float(np.mean(p)), "observed_rate": float(np.mean(y))}
    if train_prevalence is not None:
        ref = float(brier_score_loss(y, np.full(len(y), train_prevalence)))
        out["brier_skill_vs_const"] = 1.0 - b / ref  # >0 means better than predicting the base rate
    return out


def bootstrap_ci(y, p, n=200, seed=0):
    rng = np.random.default_rng(seed)
    out = {"auroc": [], "pr_auc": []}
    idx = np.arange(len(y))
    for _ in range(n):
        s = rng.choice(idx, len(idx))
        if y[s].min() == y[s].max():
            continue
        out["auroc"].append(roc_auc_score(y[s], p[s]))
        out["pr_auc"].append(average_precision_score(y[s], p[s]))
    return {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] for k, v in out.items()}


def make_models(seed):
    return {
        "logreg": LogisticRegression(C=1.0, max_iter=2000, class_weight=None),
        "gbt": HistGradientBoostingClassifier(max_depth=4, learning_rate=0.05, max_iter=300,
                                              l2_regularization=1.0, random_state=seed),
        "mlp": MLPClassifier(hidden_layer_sizes=(32, 16), alpha=1e-3, max_iter=300,
                             early_stopping=True, random_state=seed),
    }


def fit_predict(name, model, Xtr, ytr, Xte):
    if name in ("logreg", "mlp"):
        sc = StandardScaler().fit(Xtr)
        model.fit(sc.transform(Xtr), ytr)
        return model.predict_proba(sc.transform(Xte))[:, 1]
    model.fit(Xtr, ytr)
    return model.predict_proba(Xte)[:, 1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="kev365", choices=["kev365", "kev_ever", "exploitdb", "exploitdb365", "msf365"])
    ap.add_argument("--train-start", type=int, default=2016,
                    help="first publication year in the training set (KEV only exists since late 2021, so earlier CVEs can hardly be positive)")
    ap.add_argument("--train-end", type=int, default=2021)
    ap.add_argument("--test-start", type=int, default=2022)
    ap.add_argument("--test-end", type=int, default=2024)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="results", help="output folder (relative to the repo root)")
    a = ap.parse_args()

    df = pd.read_csv(ROOT / "data/cve_features.csv")
    hist = pd.read_csv(ROOT / "data/epss_history.csv")
    df = df.merge(hist, on="cve_id", how="left")
    y_all, eligible = build_label(df, a.label)
    df = df.assign(y=y_all)[eligible].reset_index(drop=True)
    tr = df[(df.year >= a.train_start) & (df.year <= a.train_end)]
    te = df[(df.year >= a.test_start) & (df.year <= a.test_end)]
    # Fair, forward-looking test set: need a point-in-time EPSS score, and drop CVEs that were
    # already in KEV when that EPSS snapshot was taken (EPSS may already encode that fact).
    snap = pd.to_datetime(te["epss_snapshot_date"])
    pos_col = {"exploitdb365": "exploitdb_first_date", "msf365": "msf_first_date"}.get(a.label, "kev_date_added")
    added = pd.to_datetime(te[pos_col], errors="coerce")   # when the label event became known
    keep = te["epss_at_pub"].notna() & ~(added.notna() & (added <= snap))
    print(f"fair test set: kept {int(keep.sum())}/{len(te)} CVEs "
          f"(dropped {int((~keep).sum())}: no EPSS history or already in KEV at snapshot)")
    te = te[keep]
    print(f"label={a.label}  train={len(tr)} (pos {tr.y.sum()})  test={len(te)} (pos {te.y.sum()})")
    if te.y.sum() < 10 or tr.y.sum() < 10:
        sys.exit("too few positives for a meaningful evaluation; widen the year ranges")

    ytr, yte = tr.y.to_numpy(), te.y.to_numpy()
    RESULTS = ROOT / a.out
    RESULTS.mkdir(parents=True, exist_ok=True)
    preds, report = {}, {}

    # baselines that need no training
    preds["cvss_only"] = te["cvss_base"].to_numpy(float) / 10.0
    preds["epss_at_pub"] = te["epss_at_pub"].to_numpy(float)
    preds["epss_current_LEAKY"] = te["epss"].fillna(0).to_numpy(float)

    all_groups = ["cvss", "cwe", "vendor", "cpes"]
    feats = Features(all_groups).fit(tr)
    Xtr, Xte = feats.transform(tr), feats.transform(te)
    for name, model in make_models(a.seed).items():
        preds[name] = fit_predict(name, model, Xtr, ytr, Xte)

    for name, p in preds.items():
        m = metrics(yte, p, ytr.mean())
        m.update({f"{k}_ci95": v for k, v in bootstrap_ci(yte, p).items()})
        report[name] = m
        bss = m.get("brier_skill_vs_const", float("nan"))
        print(f"{name:18s} AUROC {m['auroc']:.3f}  PR-AUC {m['pr_auc']:.3f}  Brier {m['brier']:.5f}  "
              f"BSS {bss:+.3f}  ECE {m['ece']:.5f}  mean_p {m['mean_pred']:.5f} obs {m['observed_rate']:.5f}")

    # feature-group ablation with gradient-boosted trees
    ablation = {}
    for drop in [None] + all_groups:
        groups = [g for g in all_groups if g != drop]
        f = Features(groups).fit(tr)
        p = fit_predict("gbt", make_models(a.seed)["gbt"], f.transform(tr), ytr, f.transform(te))
        ablation[f"without_{drop}" if drop else "all"] = metrics(yte, p)
        print(f"ablation {('-' + drop) if drop else 'all':10s} {ablation[('without_' + drop) if drop else 'all']}")

    # reliability diagram
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 1], [0, 1], "k--", lw=1)
    for name in ("logreg", "gbt", "mlp"):
        frac, mean = calibration_curve(yte, preds[name], n_bins=10, strategy="quantile")
        ax.plot(mean, frac, marker="o", label=name)
    ax.set_xlabel("predicted probability")
    ax.set_ylabel("observed frequency")
    ax.set_title(f"Reliability ({a.label}, test {a.test_start}-{a.test_end})")
    ax.legend()
    fig.tight_layout()
    fig.savefig(RESULTS / "calibration.png", dpi=150)

    out = {"label": a.label, "train_years": f"<= {a.train_end}", "test_years": f"{a.test_start}-{a.test_end}",
           "n_train": len(tr), "n_train_pos": int(ytr.sum()), "n_test": len(te), "n_test_pos": int(yte.sum()),
           "models": report}
    (RESULTS / "metrics.json").write_text(json.dumps(out, indent=2))
    (RESULTS / "ablation.json").write_text(json.dumps(ablation, indent=2))
    print(f"wrote {RESULTS}")


if __name__ == "__main__":
    main()

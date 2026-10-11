#!/usr/bin/env python3
"""Train the shipped gradient-boosted exploitability model and export it for Java.

The shipped model is trained on ALL eligible CVEs (published up to --train-end, default
2024) with the same hyperparameters used in the temporal-split evaluation (train.py),
whose held-out numbers are the ones to report. The model is exported as plain JSON
(tree arrays) so the Java side needs no ML library:

  raw   = baseline + sum_t leaf_t(x)        (leaf values already include the learning rate)
  p     = sigmoid(raw)                      = P(added to CISA KEV within 365 days of publication)

Also writes golden test vectors so the Java implementation can be checked against sklearn.

Outputs:
  src/main/resources/model/exploit_model.json
  src/test/resources/model_golden.json
"""
import argparse
import json
import pathlib
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from train import Features, build_label, make_models, CVSS_CATS  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent


def export_trees(clf):
    trees = []
    for per_iter in clf._predictors:
        nodes = per_iter[0].nodes
        trees.append({
            "feature": [int(x) for x in nodes["feature_idx"]],
            "threshold": [float(x) for x in nodes["num_threshold"]],
            "left": [int(x) for x in nodes["left"]],
            "right": [int(x) for x in nodes["right"]],
            "value": [float(x) for x in nodes["value"]],
            "leaf": [bool(x) for x in nodes["is_leaf"]],
        })
    return trees


def predict_trees(trees, baseline, X):
    """Reference re-implementation of the Java evaluator (used for self-check)."""
    out = np.full(len(X), baseline)
    for t in trees:
        for i, x in enumerate(X):
            n = 0
            while not t["leaf"][n]:
                n = t["left"][n] if x[t["feature"][n]] <= t["threshold"][n] else t["right"][n]
            out[i] += t["value"][n]
    return 1.0 / (1.0 + np.exp(-out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-end", type=int, default=2024)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    df = pd.read_csv(ROOT / "data/cve_features.csv")
    y, eligible = build_label(df, "kev365")
    df = df.assign(y=y)[eligible & (df.year <= a.train_end)].reset_index(drop=True)
    print(f"training on {len(df)} CVEs, {int(df.y.sum())} positives")

    feats = Features(["cvss", "cwe", "vendor", "cpes"]).fit(df)
    X = feats.transform(df)
    clf = make_models(a.seed)["gbt"].fit(X, df.y.to_numpy())
    trees = export_trees(clf)
    baseline = float(clf._baseline_prediction.ravel()[0])

    # self-check: exported-tree evaluation must equal sklearn's predict_proba
    idx = np.random.default_rng(0).choice(len(df), 500, replace=False)
    ref = clf.predict_proba(X[idx])[:, 1]
    mine = predict_trees(trees, baseline, X[idx])
    err = float(np.max(np.abs(ref - mine)))
    print(f"max |sklearn - exported| over 500 rows: {err:.2e}")
    assert err < 1e-9, "tree export does not reproduce sklearn predictions"

    model = {
        "version": 1,
        "type": "gbt",
        "target": "P(added to CISA KEV within 365 days of NVD publication)",
        "trained_on": f"CVEs published <= {a.train_end}, n={len(df)}, positives={int(df.y.sum())}",
        "features": feats.names,
        "baseline": baseline,
        "trees": trees,
    }
    out = ROOT / "src/main/resources/model"
    out.mkdir(parents=True, exist_ok=True)
    (out / "exploit_model.json").write_text(json.dumps(model, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {out / 'exploit_model.json'} ({(out / 'exploit_model.json').stat().st_size / 1024:.0f} KB, "
          f"{len(trees)} trees, {len(feats.names)} features)")

    # golden vectors for the Java test
    rng = np.random.default_rng(1)
    pos = np.flatnonzero(df.y.to_numpy() == 1)
    neg = np.flatnonzero(df.y.to_numpy() == 0)
    pick = np.concatenate([rng.choice(pos, 15, replace=False), rng.choice(neg, 35, replace=False)])
    gold = []
    probs = clf.predict_proba(X[pick])[:, 1]
    for i, p in zip(pick, probs):
        r = df.iloc[i]
        gold.append({
            "cve_id": r["cve_id"], "cvss_base": float(r["cvss_base"]),
            **{c: r[c] for c in CVSS_CATS},
            "cwe": r["cwe"], "vendor": r["vendor"], "n_affected_cpes": int(r["n_affected_cpes"]),
            "expected": float(p),
        })
    gpath = ROOT / "src/test/resources/model_golden.json"
    gpath.write_text(json.dumps(gold, indent=1), encoding="utf-8")
    print(f"wrote {gpath} ({len(gold)} vectors)")


if __name__ == "__main__":
    main()

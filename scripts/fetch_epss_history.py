#!/usr/bin/env python3
"""Build a point-in-time EPSS baseline: for each CVE, the EPSS score from the first
monthly snapshot (1st of the month) after its NVD publication date.

This avoids the leakage in the *current* EPSS score, which already reflects later
exploitation. Snapshots come from the EPSS archive (epss.cyentia.com), available from
2021-04. The EPSS model version changes over time (recorded per snapshot in the output).

Output: data/epss_history.csv  (cve_id, epss_snapshot_date, epss_model_version, epss_at_pub, epss_pct_at_pub)
Usage:  python scripts/fetch_epss_history.py   (requires data/cve_features.csv)
"""
import csv
import datetime as dt
import gzip
import itertools
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from build_dataset import DATA, RAW, http_get, log  # noqa: E402

ARCHIVE = "https://epss.cyentia.com/epss_scores-{}.csv.gz"
FIRST_SNAPSHOT = dt.date(2021, 5, 1)


def snapshot_after(published):
    d = dt.date.fromisoformat(published)
    nxt = dt.date(d.year + (d.month == 12), d.month % 12 + 1, 1)
    return max(nxt, FIRST_SNAPSHOT)


def fetch_snapshot(cache, s):
    """Cached download; if the archive lacks that day, use the next available one (<= 7 days)."""
    for k in range(8):
        d = s + dt.timedelta(days=k)
        p = cache / f"{d}.csv.gz"
        if p.exists():
            return p
        try:
            p.write_bytes(http_get(ARCHIVE.format(d), retries=1))
            return p
        except Exception:
            if p.exists():
                p.unlink()
    raise RuntimeError(f"no EPSS snapshot within 7 days of {s}")


def main():
    today = dt.date.today()
    by_snapshot = {}
    with open(DATA / "cve_features.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            s = snapshot_after(r["published"])
            if s <= today:
                by_snapshot.setdefault(s, []).append(r["cve_id"])

    cache = RAW / "epss_history"
    cache.mkdir(parents=True, exist_ok=True)
    out = DATA / "epss_history.csv"
    n = 0
    with open(out, "w", encoding="utf-8", newline="") as fo:
        w = csv.writer(fo)
        w.writerow(["cve_id", "epss_snapshot_date", "epss_model_version", "epss_at_pub", "epss_pct_at_pub"])
        for i, s in enumerate(sorted(by_snapshot)):
            p = fetch_snapshot(cache, s)
            wanted = set(by_snapshot[s])
            with gzip.open(p, "rt", encoding="utf-8") as g:
                first = g.readline()
                version = ""
                if first.startswith("#"):  # older snapshots have no comment line
                    version = first.split("model_version:")[1].split(",")[0] if "model_version" in first else ""
                    first = g.readline()
                for row in csv.DictReader(itertools.chain([first], g)):
                    if row["cve"] in wanted:
                        w.writerow([row["cve"], p.name.split(".")[0], version, row["epss"], row.get("percentile", "")])
                        n += 1
            log(f"[{i + 1}/{len(by_snapshot)}] {s} ({version}): {len(wanted)} CVEs")
    log(f"wrote {out} ({n} rows)")


if __name__ == "__main__":
    main()

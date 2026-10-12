#!/usr/bin/env python3
"""Build the exploitability dataset used to train NetSentinel's edge scorer.

Sources (all public):
  * NVD API 2.0        - CVE metadata + CVSS v3 vectors, CWE, affected products
  * CISA KEV catalog   - label: exploited in the wild (+ date added)
  * Exploit-DB         - label: public exploit exists
  * EPSS (current)     - baseline score only; never used as a training feature

Output (data/, git-ignored):
  data/raw/nvd/*.json            cached NVD pages (makes the run resumable)
  data/raw/kev.json, exploitdb.csv, epss.csv.gz
  data/cve_features.csv          one row per CVE with a CVSS v3 vector
  data/manifest.json             fetch date, row counts, sha256 of each file

Usage:
  python scripts/build_dataset.py [--api-key KEY] [--start-year 2016] [--skip-nvd]
Without an NVD API key the rate limit is 5 requests / 30 s, so the full pull
takes roughly 15-20 minutes; cached pages are reused on re-runs.
"""
import argparse
import collections
import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import pathlib
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RAW = DATA / "raw"

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
WINDOW_DAYS = 119  # NVD allows at most 120 days per pubStartDate/pubEndDate query


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def http_get(url, headers=None, retries=4):
    """GET bytes. Falls back to curl when Python's CA bundle is stale."""
    headers = headers or {}
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLError):
                cmd = ["curl", "-sS", "-f", "-L", "-m", "180"]
                for k, v in headers.items():
                    cmd += ["-H", f"{k}: {v}"]
                return subprocess.run(cmd + [url], check=True, capture_output=True).stdout
            err = e
        except urllib.error.HTTPError as e:  # pragma: no cover
            err = e
        wait = 10 * (attempt + 1)
        log(f"  retry {attempt + 1}/{retries} after error: {err} (sleep {wait}s)")
        time.sleep(wait)
    raise RuntimeError(f"failed to fetch {url}")


def sha256(path):
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def fetch_cached(url, dest, force=False):
    if dest.exists() and not force:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log(f"downloading {url}")
    dest.write_bytes(http_get(url))
    return dest


# --------------------------------------------------------------------------- NVD

def date_windows(start_year, end):
    d = dt.date(start_year, 1, 1)
    while d < end:
        e = min(d + dt.timedelta(days=WINDOW_DAYS), end)
        yield d, e
        d = e + dt.timedelta(days=1)


def fetch_nvd(start_year, api_key):
    delay = 0.7 if api_key else 6.5
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    today = dt.date.today()
    cache = RAW / "nvd"
    cache.mkdir(parents=True, exist_ok=True)
    wins = list(date_windows(start_year, today))
    for wi, (a, b) in enumerate(wins):
        start_index = 0
        while True:
            page = cache / f"{a}_{start_index}.json"
            if page.exists() and b < today - dt.timedelta(days=WINDOW_DAYS):
                data = json.loads(page.read_text(encoding="utf-8"))
            else:
                q = urllib.parse.urlencode({
                    "pubStartDate": f"{a}T00:00:00.000", "pubEndDate": f"{b}T23:59:59.999",
                    "resultsPerPage": 2000, "startIndex": start_index})
                data = json.loads(http_get(f"{NVD}?{q}", headers))
                page.write_text(json.dumps(data), encoding="utf-8")
                time.sleep(delay)
            total = data.get("totalResults", 0)
            start_index += data.get("resultsPerPage", 0) or 2000
            log(f"[window {wi + 1}/{len(wins)}] {a}..{b} {min(start_index, total)}/{total}")
            if start_index >= total:
                break


def parse_cve(v):
    cve = v["cve"]
    if cve.get("vulnStatus") == "Rejected":
        return None
    metric = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = cve.get("metrics", {}).get(key)
        if arr:
            # prefer the NVD primary score
            metric = next((m for m in arr if m.get("type") == "Primary"), arr[0])["cvssData"]
            break
    if metric is None:
        return None

    cwe = ""
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwe = val
                break
        if cwe:
            break
    if not cwe:
        cwe = "NVD-CWE-noinfo"

    vendors = collections.Counter()
    n_cpe = 0
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", True):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4:
                    vendors[parts[3]] += 1
                    n_cpe += 1
    vendor = vendors.most_common(1)[0][0] if vendors else "unknown"

    return {
        "cve_id": cve["id"],
        "published": cve["published"][:10],
        "year": int(cve["published"][:4]),
        "cvss_base": metric.get("baseScore"),
        "av": metric.get("attackVector"),
        "ac": metric.get("attackComplexity"),
        "pr": metric.get("privilegesRequired"),
        "ui": metric.get("userInteraction"),
        "scope": metric.get("scope"),
        "conf_impact": metric.get("confidentialityImpact"),
        "integ_impact": metric.get("integrityImpact"),
        "avail_impact": metric.get("availabilityImpact"),
        "cwe": cwe,
        "vendor": vendor,
        "n_affected_cpes": n_cpe,
    }


def load_nvd_rows():
    rows, seen, skipped = [], set(), 0
    for page in sorted((RAW / "nvd").glob("*.json")):
        for v in json.loads(page.read_text(encoding="utf-8")).get("vulnerabilities", []):
            r = parse_cve(v)
            if r is None:
                skipped += 1
            elif r["cve_id"] not in seen:
                seen.add(r["cve_id"])
                rows.append(r)
    log(f"NVD: {len(rows)} CVEs with CVSS v3 ({skipped} skipped: no v3 vector or rejected)")
    return rows


# ------------------------------------------------------------------------ labels

def load_kev(force):
    p = fetch_cached(KEV_URL, RAW / "kev.json", force)
    kev = {}
    for v in json.loads(p.read_text(encoding="utf-8"))["vulnerabilities"]:
        kev[v["cveID"]] = v["dateAdded"]
    log(f"KEV: {len(kev)} CVEs")
    return kev


def load_exploitdb(force):
    """CVE -> earliest publication date of (a) any Exploit-DB exploit and (b) a Metasploit module."""
    p = fetch_cached(EDB_URL, RAW / "exploitdb.csv", force)
    first, msf = {}, {}
    with open(p, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            date = (row.get("date_published") or "").strip()
            if not date:
                continue
            is_msf = row.get("author", "").strip().lower() == "metasploit" or "metasploit" in row.get("tags", "").lower()
            for c in re.findall(r"CVE-\d{4}-\d{4,}", row.get("codes", "")):
                if c not in first or date < first[c]:
                    first[c] = date
                if is_msf and (c not in msf or date < msf[c]):
                    msf[c] = date
    log(f"Exploit-DB: {len(first)} distinct CVEs with a public exploit, {len(msf)} with a Metasploit module")
    return first, msf


def load_epss(force):
    p = fetch_cached(EPSS_URL, RAW / "epss.csv.gz", force)
    epss = {}
    with gzip.open(p, "rt", encoding="utf-8") as f:
        first = f.readline()  # "#model_version:...,score_date:..."
        score_date = re.search(r"score_date:([^,\s]+)", first)
        for row in csv.DictReader(f):
            epss[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    log(f"EPSS: {len(epss)} scores (score_date={score_date.group(1) if score_date else '?'})")
    return epss, (score_date.group(1) if score_date else "")


# -------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-key", default="")
    ap.add_argument("--start-year", type=int, default=2016)
    ap.add_argument("--skip-nvd", action="store_true", help="reuse cached NVD pages only")
    ap.add_argument("--refresh-labels", action="store_true", help="re-download KEV/EPSS/Exploit-DB")
    a = ap.parse_args()

    RAW.mkdir(parents=True, exist_ok=True)
    if not a.skip_nvd:
        fetch_nvd(a.start_year, a.api_key)
    rows = load_nvd_rows()
    kev = load_kev(a.refresh_labels)
    edb, msf = load_exploitdb(a.refresh_labels)
    epss, epss_date = load_epss(a.refresh_labels)

    cols = ["cve_id", "published", "year", "cvss_base", "av", "ac", "pr", "ui", "scope",
            "conf_impact", "integ_impact", "avail_impact", "cwe", "vendor", "n_affected_cpes",
            "kev", "kev_date_added", "exploitdb", "exploitdb_first_date", "msf_first_date",
            "epss", "epss_percentile"]
    out = DATA / "cve_features.csv"
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in sorted(rows, key=lambda r: r["cve_id"]):
            cid = r["cve_id"]
            r["kev"] = int(cid in kev)
            r["kev_date_added"] = kev.get(cid, "")
            r["exploitdb"] = int(cid in edb)
            r["exploitdb_first_date"] = edb.get(cid, "")
            r["msf_first_date"] = msf.get(cid, "")
            e = epss.get(cid)
            r["epss"], r["epss_percentile"] = (e if e else ("", ""))
            w.writerow(r)

    by_year = collections.Counter(r["year"] for r in rows)
    kev_by_year = collections.Counter(r["year"] for r in rows if r["kev"])
    built = dt.date.today().isoformat()
    old_manifest = DATA / "manifest.json"
    if a.skip_nvd and not a.refresh_labels and old_manifest.exists():
        built = json.loads(old_manifest.read_text())["built"]   # same snapshot as the earlier run
    manifest = {
        "built": built,
        "epss_score_date": epss_date,
        "rows": len(rows),
        "kev_positive": sum(r["kev"] for r in rows),
        "exploitdb_positive": sum(r["exploitdb"] for r in rows),
        "msf_positive": sum(1 for r in rows if r["msf_first_date"]),
        "per_year": {str(y): {"cves": by_year[y], "kev": kev_by_year[y]} for y in sorted(by_year)},
        "sha256": {p.name: sha256(p) for p in [out, RAW / "kev.json", RAW / "exploitdb.csv", RAW / "epss.csv.gz"]},
    }
    (DATA / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    log(f"wrote {out} ({len(rows)} rows, {manifest['kev_positive']} KEV positives)")


if __name__ == "__main__":
    main()

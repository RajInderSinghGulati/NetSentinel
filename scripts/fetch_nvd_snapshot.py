#!/usr/bin/env python3
"""Fetch a pinned NVD snapshot for the CPEs used by NetSentinel.

Output: src/main/resources/nvd/snapshot.json       ({"vulnerabilities": [...]}, NVD API 2.0 format)
        src/main/resources/nvd/snapshot.meta.json  (fetch date + CPE list, for reproducibility)

Usage: python scripts/fetch_nvd_snapshot.py [--api-key KEY] [--cpe CPE ...]
Without an API key NVD allows 5 requests / 30 s, so requests are spaced 7 s apart.
"""
import argparse
import datetime
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
BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def default_cpes():
    src = (ROOT / "src/main/java/com/netsentinel/scanner/SimulatedNetworkScanner.java").read_text(encoding="utf-8")
    return sorted(set(re.findall(r'"(cpe:2\.3:[^"]+)"', src)))


def fetch(cpe, key):
    url = f"{BASE}?cpeName={urllib.parse.quote(cpe)}&resultsPerPage=2000"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    if key:
        req.add_header("apiKey", key)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r).get("vulnerabilities", [])
    except urllib.error.URLError as e:
        if not isinstance(e.reason, ssl.SSLError):
            raise
        # Python's bundled CA store can be stale; curl uses the OS trust store.
        print(f"  (python TLS failed: {e}; retrying with curl)", file=sys.stderr)
        cmd = ["curl", "-sS", "-f", "-m", "60", "-H", "Accept: application/json"]
        if key:
            cmd += ["-H", f"apiKey: {key}"]
        out = subprocess.run(cmd + [url], check=True, capture_output=True).stdout
        return json.loads(out).get("vulnerabilities", [])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-key", default="")
    ap.add_argument("--cpe", nargs="*")
    a = ap.parse_args()
    cpes = a.cpe or default_cpes()
    delay = 0.7 if a.api_key else 7.0
    seen, failed = {}, []
    for i, cpe in enumerate(cpes):
        try:
            vulns = fetch(cpe, a.api_key)
            for v in vulns:
                seen[v["cve"]["id"]] = v
            print(f"[{i + 1}/{len(cpes)}] {cpe}: {len(vulns)} CVEs", file=sys.stderr)
        except Exception as e:  # keep going; report failures in meta
            failed.append(cpe)
            print(f"[{i + 1}/{len(cpes)}] {cpe}: FAILED {e}", file=sys.stderr)
        time.sleep(delay)
    out = ROOT / "src/main/resources/nvd"
    out.mkdir(parents=True, exist_ok=True)
    ordered = sorted(seen.values(), key=lambda v: v["cve"]["id"])
    (out / "snapshot.json").write_text(json.dumps({"vulnerabilities": ordered}), encoding="utf-8")
    (out / "snapshot.meta.json").write_text(json.dumps({
        "fetched": datetime.date.today().isoformat(), "cpes": cpes,
        "failed": failed, "cve_count": len(seen)}, indent=2), encoding="utf-8")
    print(f"Wrote {len(seen)} CVEs ({len(failed)} CPE queries failed)", file=sys.stderr)


if __name__ == "__main__":
    main()

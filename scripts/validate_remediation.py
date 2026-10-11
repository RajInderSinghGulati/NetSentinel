#!/usr/bin/env python3
"""Validate the remediation artifacts NetSentinel generates for a scan.

1. Runs a simulated scan against a running NetSentinel (default http://localhost:8080) or uses --scan-id.
2. Writes playbook.yml / inventory.ini / remediate.sh to out/remediation/.
3. Always: parses the playbook with PyYAML and checks its structure.
4. Unless --no-docker: runs `ansible-lint` and `ansible-playbook --syntax-check` inside a
   python:3.12-slim container (needs Docker running; the first run installs ansible-lint, ~100 MB).
   For `--check` against real machines use the Docker lab (Phase A2).

Usage:
  python scripts/validate_remediation.py [--base-url URL] [--scan-id ID] [--no-docker]
                                         [--strategy CVSS_FIRST --budget 8]
Exit code 0 only if every executed check passed.
"""
import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "out" / "remediation"


def call(url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r)


def check_structure(playbook_text, inventory_text):
    errors = []
    plays = yaml.safe_load(playbook_text)
    if not isinstance(plays, list):
        return ["playbook is not a YAML list of plays"]
    allowed = {"ansible.builtin.package", "ansible.builtin.debug"}
    for play in plays:
        for key in ("name", "hosts", "become", "tasks"):
            if key not in play:
                errors.append(f"play {play.get('name')!r} missing {key}")
        if play.get("hosts") not in inventory_text:
            errors.append(f"host {play.get('hosts')} not in inventory")
        handlers = {h["name"] for h in play.get("handlers", [])}
        for task in play.get("tasks", []):
            modules = set(task) - {"name", "notify"}
            if len(modules) != 1 or not modules <= allowed:
                errors.append(f"task {task.get('name')!r}: modules {sorted(modules)}")
            if task.get("notify") and task["notify"] not in handlers:
                errors.append(f"task {task.get('name')!r}: unknown handler {task['notify']!r}")
    return errors


def docker_ready():
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--scan-id")
    ap.add_argument("--no-docker", action="store_true")
    ap.add_argument("--strategy", help="e.g. CVSS_FIRST; default = the plan chosen during the scan")
    ap.add_argument("--budget", type=int)
    a = ap.parse_args()

    scan_id = a.scan_id or call(f"{a.base_url}/api/scan/sync", {"cidr": "192.168.10.0/24"})["scanId"]
    query = ""
    if a.strategy:
        query = f"?strategy={a.strategy}" + (f"&budget={a.budget}" if a.budget is not None else "")
    rem = call(f"{a.base_url}/api/scan/{scan_id}/remediation{query}")
    print(f"plan: {rem['strategy']} budget {rem['budget']}, {len(rem['patches'])} patches")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "playbook.yml").write_text(rem["ansible"], encoding="utf-8")
    (OUT / "inventory.ini").write_text(rem["inventory"], encoding="utf-8")
    (OUT / "remediate.sh").write_text(rem["bash"], encoding="utf-8", newline="\n")
    print(f"scan {scan_id}: wrote artifacts to {OUT}")

    ok = True
    errs = check_structure(rem["ansible"], rem["inventory"])
    print("structure check:", "OK" if not errs else "FAILED")
    for e in errs:
        print("  -", e)
    ok &= not errs

    if a.no_docker:
        print("docker checks skipped (--no-docker)")
    elif not docker_ready():
        print("docker checks NOT RUN: Docker daemon is not available. Start Docker Desktop and re-run.")
        ok = False
    else:
        cmd = ["docker", "run", "--rm", "-v", f"{OUT}:/work", "-w", "/work", "python:3.12-slim", "bash", "-c",
               "pip install -q ansible-lint >/dev/null 2>&1 && "
               "echo '--- ansible-lint' && ansible-lint playbook.yml && "
               "echo '--- ansible-playbook --syntax-check' && "
               "ansible-playbook -i inventory.ini playbook.yml --syntax-check"]
        res = subprocess.run(cmd)
        print("ansible-lint + syntax-check:", "OK" if res.returncode == 0 else f"FAILED (exit {res.returncode})")
        ok &= res.returncode == 0
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

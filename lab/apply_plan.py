#!/usr/bin/env python3
"""Apply a NetSentinel patch plan to the Docker lab by recreating the affected containers on fixed images.

  python lab/apply_plan.py --scan-id ID [--strategy OPTIMAL --budget 3] [--base-url http://localhost:8080] [--dry-run]

1. Fetches the plan from GET /api/scan/{id}/remediation?strategy=..&budget=..; each patch carries the
   target version NetSentinel derived from NVD fixed-in ranges (e.g. redis 6.2.6 -> 8.6.3).
2. Builds the image tag "<repo>:<target>-alpine" and checks with `docker manifest inspect` that it exists.
   Plans whose target is only "newer than X" (no concrete version) cannot be applied automatically.
3. Writes lab/.override.generated.yml and runs `docker compose up -d <only those services>`.
   Only the named services of the netsentinel-lab project are recreated; nothing else is touched.

The service name equals the lab host name (web-dmz, app-cache, ...). Re-scan afterwards with
  POST /api/scan/sync {"cidr": "lab", "mode": "live"}
To return to the vulnerable baseline: docker compose -f lab/docker-compose.yml up -d --force-recreate
"""
import argparse
import json
import pathlib
import subprocess
import sys
import time
import urllib.request

LAB = pathlib.Path(__file__).resolve().parent
COMPOSE = LAB / "docker-compose.yml"
OVERRIDE = LAB / ".override.generated.yml"

# CPE product -> Docker Hub repository; tag = "<version>-alpine" (what the lab images use)
REPOS = {"http_server": "httpd", "nginx": "nginx", "redis": "redis", "memcached": "memcached"}


def get(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return json.load(r)


def image_exists(image, attempts=3):
    """True if the image is already local; otherwise ask the registry (raises if it cannot be reached;
    never guesses 'missing')."""
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0:
        return True
    last = "no answer"
    for i in range(attempts):
        try:
            r = subprocess.run(["docker", "manifest", "inspect", image], capture_output=True, text=True, timeout=240)
            if r.returncode == 0 and '"architecture"' in r.stdout:
                return True
            text = (r.stderr + r.stdout).lower()
            if "no such manifest" in text or "not found" in text:
                return False          # definite answer from the registry
            last = (r.stderr or r.stdout).strip()[:200]
        except subprocess.TimeoutExpired:
            last = "timed out after 240s"
        time.sleep(3 * (i + 1))
    raise RuntimeError(f"could not check {image}: {last}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-id", required=True)
    ap.add_argument("--strategy", default="OPTIMAL")
    ap.add_argument("--budget", type=int, default=3)
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    plan = get(f"{a.base_url}/api/scan/{a.scan_id}/remediation?strategy={a.strategy}&budget={a.budget}")
    print(f"plan {plan['strategy']} (budget {plan['budget']}): predicted risk {plan['riskBefore']:.6f} -> {plan['riskAfter']:.6f}")

    services = {}
    for up in plan["upgrades"]:
        host, product, to = up["host"], up["product"], up["to"]
        line = f"  {host}: {product} {up['from']} -> {up['toLabel']} (fixes {up['fixes']}, {up['remaining']} remain, {up['introduced']} new)"
        print(line)
        if product not in REPOS:
            sys.exit(f"no image mapping for {product} on {host}")
        if not to or to.endswith(".0.1"):
            sys.exit(f"{host}: no concrete target version ({up['toLabel']}); pick an image by hand")
        image = f"{REPOS[product]}:{to}-alpine"
        try:
            exists = image_exists(image)
        except RuntimeError as e:
            sys.exit(f"{host}: {e}")
        if not exists:
            sys.exit(f"{host}: image {image} does not exist on the registry")
        services[host] = image
        print(f"      image {image}")
    if not services:
        print("empty plan, nothing to do")
        return

    OVERRIDE.write_text("services:\n" + "".join(f"  {h}:\n    image: {img}\n" for h, img in services.items()),
                        encoding="utf-8")
    cmd = ["docker", "compose", "-f", str(COMPOSE), "-f", str(OVERRIDE), "up", "-d", *services]
    print("running:", " ".join(cmd))
    if a.dry_run:
        return
    sys.exit(subprocess.run(cmd).returncode)


if __name__ == "__main__":
    main()

# NetSentinel demo runbook (about 10 minutes)

Windows, PowerShell. Needs Docker Desktop running and internet (the dashboard loads its graph libraries from public
CDNs). Close heavy programs first: the demo machine had only about 7 GB of RAM and slowed down when it was nearly full.

## Before the audience arrives (once, about 3 minutes)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/demo_start.ps1
```

This resets the Docker lab to its vulnerable baseline, starts a clean NetSentinel and opens http://localhost:8080.
The first start after a code change also compiles, so allow a few minutes. Then do one dry run (steps 1 to 4 below)
and run the start script again to reset.

Open `results/eval/fig_risk_vs_budget.png` and `fig_scalability.png` in another window for step 5.

## The demo

### 1. The problem (1 min), scanner "Simulated"
Click **Launch Scan**. An enterprise network appears: 16 hosts, 473 CVEs, attack routes in red.

> "A real network has hundreds of CVEs. CVSS tells you which are severe, not which patches actually reduce the
> chance of an attacker reaching the crown jewels."

### 2. The plan (2 min), Remediate tab
Crown-jewel risk **1.27 -> 0.0033 (99.7%)** with three patches. Point at the chart: the optimal line drops at once,
CVSS-first stays flat until the fifth patch.

> "Each patch is 'upgrade product P on host H to version T', where T comes from the NVD fixed-in ranges. The
> optimizer picks the three that matter, not the three highest-scoring."

Mention one detail to show it is honest: `netweaver 7.50 -> newer than 7.53 (fixes 16 CVEs, 5 remain)`. CVEs with
no known fix are kept in the risk.

### 3. A real scan (2 min), scanner "Live (lab)"
Choose **Live (lab)** and **Launch Scan**. Five real Docker containers are probed over TCP; versions come from their
banners, not from a database: Apache 2.4.49, nginx 1.18.0, two redis 6.2.6 and memcached 1.6.9.
The graph shows the chain `internet -> web-dmz / proxy-dmz -> app-cache -> data-memcached -> secrets-vault`.
Click a host for its open port and CVEs. Remediate tab: **app-cache: redis 6.2.6 -> 8.6.3, fixes 22 CVEs**.

> "The model rates these CVEs low (about 2% each), so the absolute risk is small; what matters is that a single
> upgrade cuts every route to the crown jewel."

### 4. The real fix (3 min)
In a terminal:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/demo_apply.ps1
```

It applies the plan of the latest live scan: only `app-cache` is recreated on `redis:8.6.3-alpine`; the other four
containers keep running. Then click **Launch Scan** again in the dashboard: **0 attack paths, risk 0.0000, CVEs 143 -> 121**.
The patched host is cut off from the chain.

> "The prediction said risk 0 and 0 paths. The real re-scan agrees."

### 5. The evidence (1 min)
Show `fig_risk_vs_budget.png`: on 50-host random networks greedy needs 5 patches for a 90% cut while CVSS-first
stays near 0%. Show `fig_scalability.png`: 1,000 hosts is feasible with the graph-free model.
The learned model: AUROC 0.806 against 0.735 for CVSS and 0.632 for EPSS at publication time (see `results/`).

## Reset and shut down

```powershell
powershell -ExecutionPolicy Bypass -File scripts/demo_start.ps1       # back to the vulnerable baseline
powershell -ExecutionPolicy Bypass -File scripts/demo_stop.ps1        # stop the app (add -RemoveLab to remove the lab)
```

## If something goes wrong

| Symptom | Fix |
|---|---|
| "Docker is not running" | Start Docker Desktop and run the start script again. |
| "port 8080 is in use" | Another program uses it; close it, or run `demo_stop.ps1` and retry. |
| Dashboard looks old or blank | Hard refresh (Ctrl+F5). A blank graph means the CDN scripts did not load: check the internet. |
| `demo_apply.ps1`: "no completed live scan" | Choose **Live (lab)** in the dashboard and run a scan first. |
| `demo_apply.ps1` cannot reach the registry | The needed image is already on this machine after a first run; otherwise check the internet. |
| Start takes minutes | Free RAM (close the browser tabs and other programs); the first start after a code change also compiles. |
| Everything fails | Use the figures in `results/eval/` and the screenshots, and describe the flow. |

## Questions you may get

* **Is the risk number a real probability?** It is the model's estimate of exploitation within a year, calibrated on
  average (ECE 0.0006) but weak at the top of the ranking (PR-AUC 0.009). It counts known CVEs only.
* **Is the network topology measured?** No. Tier and criticality come from a declared inventory; reachability follows a
  tier model (external -> DMZ -> application -> data -> crown jewel).
* **Why not an ILP?** The objective (probability that a crown jewel falls) is not linear, so the exact optimum is found
  by exhaustive search on small networks and greedy search on larger ones; greedy matched the optimum on the lab and
  web-shop networks and lost slightly on the enterprise network.
* **Does it scale?** The explicit attack graph grows quadratically (2.5M edges at 400 hosts); a graph-free model handles
  1,000 hosts. The running application still uses the explicit graph, so real scans above about 400 hosts stop with a
  clear message.

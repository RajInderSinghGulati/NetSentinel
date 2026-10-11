# Starts everything needed for the demo and opens the dashboard.
#
#   powershell -ExecutionPolicy Bypass -File scripts/demo_start.ps1 [-KeepLab] [-NoBrowser]
#
# 1. checks that Docker is running
# 2. resets the Docker lab to its vulnerable baseline (recreates only the nslab-* containers)
# 3. stops any old NetSentinel process and starts a clean one (offline NVD snapshot, loopback only)
# 4. waits until the dashboard answers, then opens it
param(
    [switch]$KeepLab,     # do not reset the lab (keep its current container versions)
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

# --- 1. Docker
docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker is not running. Start Docker Desktop and run this again." }

# --- 2. lab baseline
if (-not $KeepLab) {
    Write-Host "Resetting the lab to the vulnerable baseline..." -ForegroundColor Cyan
    docker compose -f lab/docker-compose.yml up -d --force-recreate
    if ($LASTEXITCODE -ne 0) { Fail "could not start the lab (docker compose failed)." }
}

# --- 3. app: stop old instances (the Maven launcher AND the forked application JVM), start a clean one
Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match "java" -and $_.CommandLine -match "NetSentinelApplication|NetSentinel"
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
if (Get-NetTCPConnection -State Listen -LocalPort 8080 -ErrorAction SilentlyContinue) {
    Fail "port 8080 is in use by another program. Close it and run this again."
}

$mvn = (Get-Command mvn -ErrorAction SilentlyContinue).Source
if (-not $mvn) {
    $mvn = (Get-ChildItem "$env:USERPROFILE\.m2\wrapper" -Recurse -Filter mvn.cmd -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
}
if (-not $mvn) { Fail "Maven not found. Run NetSentinelApplication from your IDE with --netsentinel.nvd.offline-only=true instead." }

New-Item -ItemType Directory -Force out | Out-Null
Write-Host "Starting NetSentinel (log: out/demo-app.log)..." -ForegroundColor Cyan
Start-Process -FilePath $mvn -ArgumentList "spring-boot:run", "-Dspring-boot.run.arguments=--netsentinel.nvd.offline-only=true" `
    -RedirectStandardOutput "out/demo-app.log" -RedirectStandardError "out/demo-app.err" -WindowStyle Hidden

# --- 4. wait until it answers (the first start after a code change also compiles, which can take a few minutes)
Write-Host "Waiting for the dashboard (first start after a code change compiles first)..." -ForegroundColor Cyan
$ready = $false
for ($i = 0; $i -lt 180; $i++) {
    try {
        if ((Invoke-WebRequest "http://127.0.0.1:8080/" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) { $ready = $true; break }
    } catch { }
    if ($i -gt 0 -and $i % 15 -eq 0) { Write-Host "  still starting... ($($i * 2) s)" }
    Start-Sleep -Seconds 2
}
if (-not $ready) { Fail "the app did not start within 6 minutes; see out/demo-app.log and out/demo-app.err." }

Write-Host ""
Write-Host "Ready: http://localhost:8080" -ForegroundColor Green
Write-Host "  1. Scanner 'Simulated' -> Launch Scan   (enterprise network, then the Remediate tab)"
Write-Host "  2. Scanner 'Live (lab)' -> Launch Scan  (real containers)"
Write-Host "  3. Apply the plan for real:  powershell -File scripts/demo_apply.ps1"
Write-Host "  4. Launch the live scan again -> the attack paths are gone"
Write-Host "  Reset afterwards:  powershell -File scripts/demo_start.ps1   (or scripts/demo_stop.ps1 to shut down)"
if (-not $NoBrowser) { Start-Process "http://localhost:8080" }

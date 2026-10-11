# Applies NetSentinel's patch plan for the most recent LIVE scan to the Docker lab (recreates only the
# containers named in the plan), then tells you to re-scan in the dashboard.
#
#   powershell -ExecutionPolicy Bypass -File scripts/demo_apply.ps1 [-Budget 3] [-Strategy OPTIMAL]
param(
    [int]$Budget = 3,
    [string]$Strategy = "OPTIMAL"
)

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

try {
    $scans = Invoke-RestMethod "http://127.0.0.1:8080/api/scans" -TimeoutSec 10
} catch {
    Write-Host "ERROR: the app is not reachable on http://localhost:8080 (run scripts/demo_start.ps1)." -ForegroundColor Red
    exit 1
}

$live = @($scans | Where-Object { $_.target -eq "lab" -and $_.status -eq "COMPLETE" }) | Sort-Object startedAt | Select-Object -Last 1
if (-not $live) {
    Write-Host "ERROR: no completed live scan found. In the dashboard choose 'Live (lab)' and click Launch Scan first." -ForegroundColor Red
    exit 1
}

Write-Host "Applying the $Strategy plan (budget $Budget) of live scan $($live.scanId)..." -ForegroundColor Cyan
python lab/apply_plan.py --scan-id $live.scanId --strategy $Strategy --budget $Budget
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Done. Containers now running:" -ForegroundColor Green
docker ps --format "  {{.Names}}  {{.Image}}" | Select-String "nslab"
Write-Host ""
Write-Host "Now click Launch Scan again in the dashboard: the attack paths should be gone." -ForegroundColor Green

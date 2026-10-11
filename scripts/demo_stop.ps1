# Stops the NetSentinel app started by demo_start.ps1.
#
#   powershell -ExecutionPolicy Bypass -File scripts/demo_stop.ps1 [-RemoveLab]
#
# The lab containers keep running unless -RemoveLab is given (that removes only the netsentinel-lab project;
# no other Docker project is touched, and the lab has no volumes).
param([switch]$RemoveLab)

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match "java" -and $_.CommandLine -match "NetSentinelApplication|NetSentinel"
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Write-Host "NetSentinel stopped." -ForegroundColor Green

if ($RemoveLab) {
    docker compose -f lab/docker-compose.yml down
    Write-Host "Lab removed." -ForegroundColor Green
}

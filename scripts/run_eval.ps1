# Runs the Phase E evaluation harness (see com.netsentinel.eval.EvaluationRunner).
#
#   powershell -File scripts/run_eval.ps1 -Run strategies,scale,scan [-Reps 30] [-Out results/eval]
#
# Settings are passed as environment variables (Spring maps NETSENTINEL_EVAL_* to netsentinel.eval.*), so no
# quoting is needed. The NVD snapshot is used offline, logging is quiet and the web server picks a free port.
param(
    [string]$Run = "strategies,scale,scan",
    [int]$Reps = 30,
    [string]$Sizes = "50,200",
    [string]$ScaleSizes = "50,100,200,400",
    [int]$BigReps = 5,
    [string]$Out = "results/eval",
    [string]$Heap = "6g"
)

$root = Split-Path -Parent $PSScriptRoot
$mvn = (Get-ChildItem "$env:USERPROFILE\.m2\wrapper" -Recurse -Filter mvn.cmd -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
if (-not $mvn) { $mvn = "mvn" }

$env:NETSENTINEL_EVAL_RUN = $Run
$env:NETSENTINEL_EVAL_REPS = "$Reps"
$env:NETSENTINEL_EVAL_SIZES = $Sizes
$env:NETSENTINEL_EVAL_SCALE_SIZES = $ScaleSizes
$env:NETSENTINEL_EVAL_BIG_REPS = "$BigReps"
$env:NETSENTINEL_EVAL_OUT = $Out
$env:NETSENTINEL_NVD_OFFLINE_ONLY = "true"
$env:LOGGING_LEVEL_COM_NETSENTINEL = "WARN"

Push-Location $root
try {
    & $mvn -q spring-boot:run "-Dspring-boot.run.jvmArguments=-Xmx$Heap" "-Dspring-boot.run.arguments=--server.port=0"
    exit $LASTEXITCODE
} finally {
    Pop-Location
}

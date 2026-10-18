param(
    [string]$CaptureInterface = "Wi-Fi",
    [string]$ConfigPath = "config.yaml"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$env:CAPTURE_INTERFACE = $CaptureInterface
$resolvedConfigPath = if ([System.IO.Path]::IsPathRooted($ConfigPath)) { $ConfigPath } else { Join-Path $projectRoot $ConfigPath }
if (-not (Test-Path -LiteralPath $resolvedConfigPath -PathType Leaf)) {
    throw "Configuration file was not found: $resolvedConfigPath"
}
$env:CONFIG_PATH = $resolvedConfigPath
$python = "C:\Users\YASH SINGH\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$logPath = Join-Path $projectRoot "network-sentinel-startup.log"
$stdoutPath = Join-Path $projectRoot "network-sentinel-uvicorn.out.log"
$stderrPath = Join-Path $projectRoot "network-sentinel-uvicorn.err.log"

"[$(Get-Date -Format o)] Starting Network Sentinel on interface $CaptureInterface" | Set-Content -LiteralPath $logPath
"Configuration profile: $resolvedConfigPath" | Add-Content -LiteralPath $logPath
"Python executable: $python" | Add-Content -LiteralPath $logPath
& $python --version 2>&1 | Add-Content -LiteralPath $logPath
Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue

try {
    $process = Start-Process -FilePath $python -ArgumentList @(
        "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"
    ) -WorkingDirectory $projectRoot -PassThru -Wait -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    "Uvicorn exited with code $($process.ExitCode)." | Add-Content -LiteralPath $logPath
} catch {
    ($_ | Out-String) | Add-Content -LiteralPath $logPath
}

if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath | Add-Content -LiteralPath $logPath }
if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath | Add-Content -LiteralPath $logPath }

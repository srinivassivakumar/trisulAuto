param(
  [int]$MaxIps = 1,
  [int]$TimeoutSec = 300,
  [int]$Retries = 1,
  [string]$Model = "llama3"
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "[setup] Working directory: $PSScriptRoot"

if (-not (Test-Path ".venv")) {
  Write-Host "[setup] Creating virtual environment..."
  py -3 -m venv .venv
}

Write-Host "[setup] Installing dependencies..."
& .\.venv\Scripts\python.exe -m pip install --upgrade pip | Out-Host
& .\.venv\Scripts\python.exe -m pip install -r .\requirements.txt | Out-Host

Write-Host "[setup] Checking Ollama..."
$ollamaOk = $true
try {
  ollama --version | Out-Host
} catch {
  $ollamaOk = $false
}

if (-not $ollamaOk) {
  throw "Ollama is not installed or not in PATH. Install Ollama first."
}

Write-Host "[setup] Starting 11thstep API in background..."
$apiProc = Start-Process -FilePath ".\.venv\Scripts\python.exe" -ArgumentList ".\11thstep.py --mode serve_api" -PassThru
Start-Sleep -Seconds 4

Write-Host "[run] Running AI diagnosis pipeline..."
$env:MAX_IPS = "$MaxIps"
$env:DIAGNOSE_TIMEOUT_SEC = "$TimeoutSec"
$env:DIAGNOSE_RETRIES = "$Retries"
$env:LM_TIMEOUT_SEC = "$TimeoutSec"
$env:OLLAMA_MODEL = "$Model"

try {
  & .\.venv\Scripts\python.exe .\14thstepai.py
}
finally {
  if ($apiProc -and -not $apiProc.HasExited) {
    Write-Host "[cleanup] Stopping 11thstep API process..."
    Stop-Process -Id $apiProc.Id -Force
  }
}

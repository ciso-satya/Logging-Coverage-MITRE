# One-shot local deployment on Windows (PowerShell): installs dependencies, builds the UI, starts the server.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$port = if ($env:LCM_PORT) { $env:LCM_PORT } else { "8000" }

if (-not (Test-Path "backend\.venv\Scripts\python.exe")) {
  Write-Host "> Creating Python virtualenv"
  python -m venv backend\.venv
  backend\.venv\Scripts\python.exe -m pip install --quiet --upgrade pip
  backend\.venv\Scripts\python.exe -m pip install --quiet -r backend\requirements.txt
}
if (-not (Test-Path "frontend\node_modules")) {
  Write-Host "> Installing frontend dependencies"
  Push-Location frontend; npm install --no-audit --no-fund; Pop-Location
}
Write-Host "> Building frontend"
Push-Location frontend; npm run build; Pop-Location

Write-Host "> Starting ATT&CK Logging Coverage on http://localhost:$port"
Start-Job { Start-Sleep 6; Start-Process "http://localhost:$using:port" } | Out-Null
Set-Location backend
& .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port $port

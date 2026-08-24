# Quick runner — works even if `uv` isn't on PATH yet in this terminal.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$uv = @(
    "$env:LOCALAPPDATA\Microsoft\WinGet\Links\uv.exe",
    "$env:USERPROFILE\.local\bin\uv.exe",
    "$env:USERPROFILE\.cargo\bin\uv.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($uv) {
    & $uv run python -m src.cli @args
    exit $LASTEXITCODE
}

$venvPython = Join-Path $root ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    & $venvPython -m src.cli @args
    exit $LASTEXITCODE
}

Write-Error "Neither uv nor .venv found. Install uv (winget install astral-sh.uv) then run: uv sync"
exit 1

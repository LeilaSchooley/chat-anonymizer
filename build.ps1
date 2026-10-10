param([switch]$Clean, [string]$DistRoot = 'dist')
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$buildClock = [Diagnostics.Stopwatch]::StartNew()
# Retain build tools and the downloaded model between runs.
uv --cache-dir .uv-cache sync --inexact
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
& .\.venv\Scripts\python.exe -c "import PyInstaller, en_core_web_sm; assert en_core_web_sm.__version__ == '3.8.0'"
if ($LASTEXITCODE -ne 0) {
    uv --cache-dir .uv-cache pip install pyinstaller 'https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl'
    if ($LASTEXITCODE -ne 0) { throw 'Build dependency installation failed' }
}
$packArgs = @('--noconfirm', '--onedir', '--windowed', '--name', 'ChatAnonymizer', '--distpath', $DistRoot,
    '--collect-data', 'spacy', '--collect-data', 'presidio_analyzer', '--collect-data', 'presidio_anonymizer',
    '--collect-all', 'en_core_web_sm', '--collect-data', 'tldextract', '--collect-all', 'tkinterdnd2',
    '--copy-metadata', 'en_core_web_sm')
if ($Clean) { $packArgs += '--clean' }
$packArgs += 'gui_launcher.py'
& .\.venv\Scripts\python.exe -m PyInstaller @packArgs
if ($LASTEXITCODE -ne 0) { throw 'Executable build failed. Close any running ChatAnonymizer before rebuilding its folder.' }
$exePath = Join-Path $PSScriptRoot (Join-Path $DistRoot 'ChatAnonymizer\ChatAnonymizer.exe')
$testLog = Join-Path $PSScriptRoot 'build/self-test.log'
$testProcess = Start-Process -FilePath $exePath -ArgumentList '--self-test', ('"' + $testLog + '"') -WindowStyle Hidden -PassThru
if (-not $testProcess.WaitForExit(45000)) {
    Stop-Process -Id $testProcess.Id
    throw 'Executable self-test timed out'
}
if ($testProcess.ExitCode -ne 0) {
    if (Test-Path $testLog) { Get-Content $testLog }
    throw 'Executable self-test failed'
}
$buildClock.Stop()
Write-Host "Built $exePath in $([math]::Round($buildClock.Elapsed.TotalSeconds, 1)) seconds. Distribute the entire ChatAnonymizer folder."

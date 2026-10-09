$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
uv --cache-dir .uv-cache sync
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
uv --cache-dir .uv-cache pip install pyinstaller 'https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl'
if ($LASTEXITCODE -ne 0) { throw 'English model installation failed' }
& .\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --onedir --windowed --name ChatAnonymizer --distpath dist/category-settings --collect-all presidio_analyzer --collect-all presidio_anonymizer --collect-all spacy --collect-all en_core_web_sm --collect-data tldextract --collect-all tkinterdnd2 --copy-metadata en_core_web_sm gui_launcher.py
if ($LASTEXITCODE -ne 0) { throw 'Executable build failed' }
$testProcess = Start-Process -FilePath (Join-Path $PSScriptRoot 'dist\category-settings\ChatAnonymizer\ChatAnonymizer.exe') -ArgumentList '--self-test', 'build/self-test.log' -WindowStyle Hidden -PassThru
if (-not $testProcess.WaitForExit(45000)) {
    Stop-Process -Id $testProcess.Id
    throw 'Executable self-test timed out'
}
if ($testProcess.ExitCode -ne 0) {
    if (Test-Path 'build/self-test.log') { Get-Content 'build/self-test.log' }
    throw 'Executable self-test failed'
}
Write-Host 'Built dist\category-settings\ChatAnonymizer\ChatAnonymizer.exe. Distribute the entire ChatAnonymizer folder.'

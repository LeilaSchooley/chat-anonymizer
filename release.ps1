param([switch]$SkipBuild, [string]$DistRoot = 'dist')
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not $SkipBuild) { & "$PSScriptRoot\build.ps1" -DistRoot $DistRoot }
$version = (& .\.venv\Scripts\python.exe -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])").Trim()
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^\d+\.\d+\.\d+$') { throw 'Cannot determine release version' }
$appFolder = Join-Path $DistRoot 'ChatAnonymizer'
if (-not (Test-Path (Join-Path $appFolder 'ChatAnonymizer.exe'))) { throw 'Build the executable first' }
@"
Chat Anonymizer $version for Windows x64

Extract this entire ZIP, then open ChatAnonymizer\ChatAnonymizer.exe.
Keep the _internal folder beside the executable. No Python installation needed.
Processing is local, including chat detection with the bundled English model.

Review redacted output before sharing. Detection may miss sensitive information.
This release is unsigned; Windows may display an unknown publisher warning.
To uninstall, delete the extracted folder.

Source and documentation: https://github.com/LeilaSchooley/chat-anonymizer
"@ | Set-Content -LiteralPath (Join-Path $appFolder 'START-HERE.txt') -Encoding utf8
$archive = Join-Path $DistRoot "ChatAnonymizer-$version-windows-x64.zip"
Compress-Archive -LiteralPath $appFolder -DestinationPath $archive -Force
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $([IO.Path]::GetFileName($archive))" | Set-Content -LiteralPath "$archive.sha256" -Encoding ascii
Write-Host "Release archive: $archive"
Write-Host "SHA256: $hash"

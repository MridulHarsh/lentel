# Build Lentel.exe for Windows — coordinator-free edition.
#
# Produces .\dist\Lentel.exe — a single windowless .exe for the system tray.
# No server of any kind is required.

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repo = Resolve-Path (Join-Path $here "..\..")
Set-Location $repo

Write-Host "==> Installing dependencies..."
python -m pip install --upgrade pip --quiet
python -m pip install -e ".[tray]" --quiet
python -m pip install pyinstaller --quiet

Set-Location $here

Write-Host "==> Cleaning old build..."
Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue

Write-Host "==> Building Lentel.exe..."
pyinstaller --clean --noconfirm lentel-tray.spec

$size = "{0:N1} MB" -f ((Get-ChildItem -Recurse dist\Lentel.exe | Measure-Object Length -Sum).Sum / 1MB)

Write-Host ""
Write-Host "========================================"
Write-Host "  Built: $here\dist\Lentel.exe ($size)"
Write-Host "========================================"
Write-Host ""
Write-Host "  Run: .\dist\Lentel.exe"
Write-Host "  Auto-start: Win+R -> shell:startup, copy Lentel.exe there"
Write-Host ""
Write-Host "  No server needed -- the sender's address is"
Write-Host "  embedded in the ticket automatically via STUN/UPnP."

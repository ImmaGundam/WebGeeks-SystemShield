#!/usr/bin/env powershell

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptRoot
$metadataScript = Join-Path $scriptRoot "write_build_metadata.py"
$specFile = Join-Path $scriptRoot "SystemShield.spec"
$workPath = Join-Path $scriptRoot "pyinstaller-cache"
$distPath = Join-Path $projectRoot "dist"
$pythonExe = (& python -c "import sys; print(sys.executable)").Trim()

if (-not $pythonExe -or -not (Test-Path -LiteralPath $pythonExe)) {
    throw "Could not resolve the active Python interpreter."
}

Push-Location $projectRoot
try {
    & $pythonExe -c "import PyInstaller" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller is not installed for $pythonExe. Run: pip install -r build/requirements-build.txt"
    }

    & $pythonExe $metadataScript
    & $pythonExe -m PyInstaller --clean --noconfirm --workpath $workPath --distpath $distPath $specFile
}
finally {
    Pop-Location
}

[CmdletBinding()]
param(
    [string]$Python = "",
    [string]$DistPath = "",
    [string]$WorkPath = ""
)

$ErrorActionPreference = "Stop"
if (-not $Python) { $Python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe" }
if (-not (Test-Path -LiteralPath $Python)) {
    throw "Python environment missing. Run run.cmd once, then install requirements-build.txt into .venv."
}
if (-not $DistPath) { $DistPath = Join-Path $PSScriptRoot "dist" }
if (-not $WorkPath) { $WorkPath = Join-Path ([System.IO.Path]::GetTempPath()) "cipherdesk-build" }

& $Python -c "import PyInstaller, PySide6.QtWidgets"
if ($LASTEXITCODE -ne 0) {
    throw "Build dependencies missing. Install requirements-build.txt into the selected Python environment."
}

New-Item -ItemType Directory -Force -Path $WorkPath | Out-Null
$previousPyInstallerConfig = $env:PYINSTALLER_CONFIG_DIR
$env:PYINSTALLER_CONFIG_DIR = Join-Path $WorkPath "cache"
Push-Location -LiteralPath $PSScriptRoot
try {
    & $Python -m PyInstaller --noconfirm --clean --distpath $DistPath `
        --workpath (Join-Path $WorkPath "build") (Join-Path $PSScriptRoot "CipherDesk.spec")
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }
    Write-Host "Built: $(Join-Path $DistPath 'CipherDesk\CipherDesk.exe')"
    Write-Host "Distribute the complete CipherDesk folder, including _internal. Gpg4win is installed separately."
} finally {
    Pop-Location
    $env:PYINSTALLER_CONFIG_DIR = $previousPyInstallerConfig
}

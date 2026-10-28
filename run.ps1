[CmdletBinding()]
param(
    [string]$Python = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AppArguments = @()
)

$ErrorActionPreference = "Stop"
$projectDirectory = $PSScriptRoot
$venvPython = Join-Path $projectDirectory ".venv\Scripts\python.exe"

if ($Python) {
    $runtimePython = $Python
} else {
    if (-not (Test-Path -LiteralPath $venvPython)) {
        if (Get-Command py -ErrorAction SilentlyContinue) {
            & py -3 -m venv (Join-Path $projectDirectory ".venv")
        } elseif (Get-Command python -ErrorAction SilentlyContinue) {
            & python -m venv (Join-Path $projectDirectory ".venv")
        } else {
            throw "Install Python 3.10 or newer, or use the packaged CipherDesk.exe."
        }
        if ($LASTEXITCODE -ne 0) { throw "Could not create the local Python environment." }
    }
    $runtimePython = $venvPython
    $requirementsPath = Join-Path $projectDirectory "requirements.txt"
    $requirementsHash = (Get-FileHash -LiteralPath $requirementsPath -Algorithm SHA256).Hash
    $markerPath = Join-Path $projectDirectory ".venv\cipherdesk-requirements.sha256"
    $installedHash = if (Test-Path -LiteralPath $markerPath) { (Get-Content -LiteralPath $markerPath -Raw).Trim() } else { "" }
    if ($installedHash -ne $requirementsHash) {
        & $runtimePython -m pip install --disable-pip-version-check -r $requirementsPath
        if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed. Check the network connection and Python installation." }
        Set-Content -LiteralPath $markerPath -Value $requirementsHash -Encoding ASCII
    }
}

Push-Location -LiteralPath $projectDirectory
try {
    & $runtimePython (Join-Path $projectDirectory "app.py") @AppArguments
    exit $LASTEXITCODE
} finally {
    Pop-Location
}

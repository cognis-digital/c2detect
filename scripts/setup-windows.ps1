#requires -version 5
# Windows setup via winget.
$ErrorActionPreference = "Stop"
winget install --id Python.Python.3.12 -e --accept-source-agreements --accept-package-agreements
winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
python -m pip install --upgrade pip
if (Test-Path pyproject.toml) { python -m pip install -e ".[dev]" }
Write-Host "Windows setup complete."

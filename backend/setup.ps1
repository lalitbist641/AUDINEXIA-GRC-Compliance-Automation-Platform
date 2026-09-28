# One-shot setup for the Audinexia backend: venv, dependencies, .env with
# freshly generated secrets, and the initial database migration.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "== Audinexia backend setup =="

if (-not (Test-Path "venv")) {
    Write-Host "-- Creating virtual environment"
    python -m venv venv
}

$python = ".\venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Error "Could not find $python after venv creation. Aborting."
    exit 1
}

Write-Host "-- Installing dependencies"
& $python -m pip install --upgrade pip -q
& $python -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
    Write-Host "-- Generating .env with fresh random secrets"
    $secretKey = & $python -c "import secrets; print(secrets.token_hex(32))"
    $jwtSecretKey = & $python -c "import secrets; print(secrets.token_hex(32))"
    # PowerShell 5.1's "-Encoding utf8" always prepends a UTF-8 BOM (there is
    # no utf8NoBOM option before PS7). A BOM at the start of the file gets
    # read as part of the first key's name (python-dotenv doesn't strip it),
    # so os.environ ends up with "﻿SECRET_KEY" instead of "SECRET_KEY"
    # -- config.py's _require() then can't find SECRET_KEY at all and the
    # app refuses to boot. Content here is pure ASCII (hex secrets + plain
    # text), so ASCII encoding sidesteps the BOM issue entirely.
    $envContent = "SECRET_KEY=$secretKey`nJWT_SECRET_KEY=$jwtSecretKey`nDATABASE_URL=sqlite:///audinexia.db`nFLASK_ENV=development`n"
    [System.IO.File]::WriteAllText("$PSScriptRoot\.env", $envContent, [System.Text.Encoding]::ASCII)
} else {
    Write-Host "-- .env already exists, leaving it as-is"
}

Write-Host "-- Applying database migrations"
$env:FLASK_APP = "app.py"
& $python -m flask db upgrade

Write-Host ""
Write-Host "Setup complete. To start the server:"
Write-Host "  cd backend"
Write-Host "  venv\Scripts\activate"
Write-Host "  python app.py"
Write-Host ""
Write-Host "Then open http://127.0.0.1:5000/login"

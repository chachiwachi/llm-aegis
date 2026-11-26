# Compila llm-aegis en Windows: motor Rust -> WASM y gateway Go -> bin\aegis.exe
# Uso: .\scripts\build.ps1 [-Test]
param([switch]$Test)
# En Windows PowerShell 5.1, 'Stop' convierte la salida de cargo por stderr en errores:
# los fallos se detectan con $LASTEXITCODE.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot

Push-Location "$root\engine"
try {
    if ($Test) { cargo test; if ($LASTEXITCODE) { throw 'cargo test ha fallado' } }
    cargo build --release --target wasm32-unknown-unknown
    if ($LASTEXITCODE) { throw 'la compilación del motor ha fallado' }
} finally { Pop-Location }

Copy-Item "$root\engine\target\wasm32-unknown-unknown\release\aegis_engine.wasm" "$root\internal\engine\" -Force -ErrorAction Stop

Push-Location $root
try {
    if ($Test) { go test ./...; if ($LASTEXITCODE) { throw 'go test ha fallado' } }
    $env:CGO_ENABLED = '0'
    go build -trimpath -ldflags='-s -w' -o bin\aegis.exe .\cmd\aegis
    if ($LASTEXITCODE) { throw 'la compilación del gateway ha fallado' }
    Write-Host 'Listo: bin\aegis.exe'
} finally { Pop-Location }

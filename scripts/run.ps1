$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command py -ErrorAction SilentlyContinue
}

if (-not $python) {
    Write-Error 'Python 3 was not found. Install Python and make it available on PATH.'
    exit 1
}

Write-Host 'Starting PortSentinel at http://localhost:8080'
Start-Job -ScriptBlock {
    Start-Sleep -Seconds 2
    Start-Process 'http://localhost:8080'
} | Out-Null

& $python.Source (Join-Path $repoRoot 'server.py') 8080

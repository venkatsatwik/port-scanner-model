# PortSentinel PowerShell Launcher
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "       PortSentinel - PC Security & Port Auditor       " -ForegroundColor White
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

$pythonExe = $null

if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonExe = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonExe = "py"
} elseif (Test-Path "C:\Program Files (x86)\Nmap\zenmap\bin\python.exe") {
    $pythonExe = "C:\Program Files (x86)\Nmap\zenmap\bin\python.exe"
}

if (-not $pythonExe) {
    Write-Host "[!] Python was not found in your standard PATH." -ForegroundColor Red
    Write-Host "[!] Please install Python 3 (https://python.org) or Git." -ForegroundColor Yellow
    exit 1
}

Write-Host "[+] Python detected: $pythonExe" -ForegroundColor Green
Write-Host "[+] Starting server at http://localhost:8080..." -ForegroundColor Cyan

# Open browser in 2 seconds
Start-Job -ScriptBlock {
    Start-Sleep -Seconds 2
    Start-Process "http://localhost:8080"
} | Out-Null

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& $pythonExe "$scriptDir\server.py" 8080

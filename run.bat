@echo off
title PortSentinel - Security Auditor
echo =======================================================
echo          PortSentinel - PC Security & Port Auditor
echo =======================================================
echo.

:: Check for standard python
where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set "PY_CMD=python"
    goto :START_SERVER
)

:: Check for python launcher
where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set "PY_CMD=py"
    goto :START_SERVER
)

:: Check for Nmap bundled Python
if exist "C:\Program Files (x86)\Nmap\zenmap\bin\python.exe" (
    set "PY_CMD=C:\Program Files (x86)\Nmap\zenmap\bin\python.exe"
    goto :START_SERVER
)

echo [!] Python was not found in your standard PATH.
echo [!] Please install Python 3 or add it to PATH.
pause
exit /b 1

:START_SERVER
echo [+] Python detected: %PY_CMD%
echo [+] Launching PortSentinel Web Dashboard at http://localhost:8080...
echo [+] Press Ctrl+C in this window to stop the server anytime.
echo.

:: Automatically open default browser after 1 second in background
start "" cmd /c "timeout /t 2 >nul & start http://localhost:8080"

:: Start the Python server
"%PY_CMD%" "%~dp0server.py" 8080

pause

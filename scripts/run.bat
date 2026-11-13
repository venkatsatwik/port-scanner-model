@echo off
setlocal
set "REPO_ROOT=%~dp0.."

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set "PY_CMD=python"
    goto :START
)

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set "PY_CMD=py"
    goto :START
)

echo Python 3 was not found. Install Python and make it available on PATH.
exit /b 1

:START
echo Starting PortSentinel at http://localhost:8080
start "" cmd /c "timeout /t 2 >nul & start http://localhost:8080"
"%PY_CMD%" "%REPO_ROOT%\server.py" 8080

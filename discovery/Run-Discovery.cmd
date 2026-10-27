@echo off
rem Double-click launcher. Runs the read-only TV discovery script with
rem execution policy bypassed for this one process only (no system change).
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Discover-TV.ps1" %*
echo.
pause

@echo off
rem Double-click launcher for the Vizio TV Tool menu. Execution policy is
rem bypassed for this one process only (no system change).
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Vizio-Tool.ps1" %*
echo.
pause

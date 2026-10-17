@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0cleanup_dvr_logs.ps1" -All
pause

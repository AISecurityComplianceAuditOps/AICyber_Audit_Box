@echo off
cd /d "%~dp0"
title AICyberAuditBox - Stop All Services
echo ==================================================
echo   AICyberAuditBox: Stopping All Local Services
echo ==================================================

echo.
echo [1/4] Terminating Python/Uvicorn API server processes...
taskkill /F /IM python.exe /T >nul 2>&1
taskkill /F /IM uvicorn.exe /T >nul 2>&1
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000,443 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p -and $p.ProcessName -notlike '*docker*') { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }" >nul 2>&1

echo.
echo [2/4] Terminating llama-server, Ollama LLM and Redis processes...
taskkill /F /IM llama-server* /T >nul 2>&1
taskkill /F /IM ollama* /T >nul 2>&1
taskkill /F /IM redis-server* /T >nul 2>&1
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 11434,11435,6380 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p -and $p.ProcessName -notlike '*docker*') { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }" >nul 2>&1

echo.
echo [3/4] Stopping Docker Database Container (ShaktiDB)...
:: -t 30 gives Postgres a real 30s to shut down cleanly (checkpoint + flush)
:: instead of Docker's default ~10s grace period before SIGKILL.
docker-compose down -t 30 >nul 2>&1
docker stop -t 30 shakthidb_service >nul 2>&1

echo.
echo ==================================================
echo   ✅ All AICyberAuditBox services have been stopped.
echo ==================================================
pause

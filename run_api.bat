@echo off
title AISecurityAudit Local API Launcher
echo ==========================================
echo    AISecurityAudit - Local Web Dashboard
echo ==========================================

:: 0. Kill any non-Docker process already using port 8000 to avoid WinError 10048
echo [0/3] Checking if port 8000 is already in use...
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p -and $p.ProcessName -notlike '*docker*') { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }" >nul 2>&1
echo [v] OK: Port 8000 checked safely without stopping Docker.

echo.

:: 1. Check local LLM backend
echo [1/3] Checking Offline LLM Engine...
python -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 11434))" >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Ollama/llama.cpp LLM server is not detected on port 11434!
    echo           Please start Ollama or run_llamacpp_demo.bat first.
    timeout /t 3 >nul
) else (
    echo [v] OK: Local LLM service is active.
)

:: 2. Check Docker for ShaktiDB
echo.
echo [2/3] Checking Docker Database Service (ShaktiDB)...
set /a retry_count=0

:check_docker
docker ps > nul 2>&1
if %errorlevel% equ 0 goto :docker_success

set /a retry_count+=1
if %retry_count% geq 12 goto :docker_fail

echo [i] Waiting for Docker service to start (Attempt %retry_count%/12)...
timeout /t 5 >nul
goto :check_docker

:docker_success
echo [v] OK: Docker is running. Starting ShaktiDB container...
docker-compose up -d
goto :docker_done

:docker_fail
echo [WARNING] Docker is not running. Continuing without ShaktiDB (SQLite fallback).
goto :docker_done

:docker_done
echo.

:: 3. Launching FastAPI & browser
echo [3/3] Launching AICyberAuditBox Dashboard...

:: MAX_CONCURRENT_AUDITS is NOT set here: the app sizes it from the hardware
:: (about 2 physical cores per audit, capped by the model's slots) -- see
:: run_all.bat. This used to set cores x 2, at least 4.
set REDIS_URL=redis://127.0.0.1:6379/0

:: Check for Let's Encrypt (Certbot) trusted certificates first
set CERTBOT_CERT=C:\Certbot\live\localauditshakti.centralindia.cloudapp.azure.com\fullchain.pem
set CERTBOT_KEY=C:\Certbot\live\localauditshakti.centralindia.cloudapp.azure.com\privkey.pem

:: FIX: --workers 4 spawns 4 parallel Python processes.
:: 10 simultaneous users are distributed across 4 workers instead of queuing through 1.
:: --reload is incompatible with --workers (removed for production multi-user mode).
echo [HTTP] Starting standard HTTP server on port 8000...
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
echo [i] Server stopped. Press any key to close this window...
pause



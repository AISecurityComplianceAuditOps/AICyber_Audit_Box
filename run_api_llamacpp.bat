@echo off
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
title AISecurityAudit llama.cpp Local API Launcher
echo ==========================================
echo    AISecurityAudit - Local Web Dashboard (llama.cpp)
echo ==========================================

:: 1. Check local LLM backend & Embeddings
echo [1/3] Checking llama.cpp GGUF Servers...
python -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 11434))" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] llama.cpp LLM server is not running on port 11434!
    echo         Please start the LLM server or run run_llamacpp_demo.bat.
    exit /b 1
)

python -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 11435))" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] llama.cpp Embedding server is not running on port 11435!
    echo         Please start the Embedding server or run run_llamacpp_demo.bat.
    exit /b 1
)

echo [v] OK: llama.cpp LLM ^& Embedding services are active.

:: Ensure SSL Certificate Exists
if not exist cert.pem (
    echo [SSL] Generating local SSL Certificate...
    python generate_self_ssl.py
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
docker start shakthidb_service > nul 2>&1
if errorlevel 1 (
    docker-compose -f docker-compose.yml -f docker-compose.local-db.yml up -d shakthidb
)
goto :docker_done

:docker_fail
echo [ERROR] Docker is not running or Docker Desktop is not detected!
echo         ShaktiDB PostgreSQL is required to run the Master-Slave Database Architecture.
echo         Please start Docker Desktop and run this script again.
exit /b 1

:docker_done
echo.

:: 3. Launching FastAPI & browser with llama.cpp environment
echo [3/3] Launching AISecurityAudit Local HTTP Dashboard...
set LLM_BACKEND=llama.cpp
set EMBEDDING_HOST=http://127.0.0.1:11435
set OLLAMA_KEEP_ALIVE=24h
set OLLAMA_NUM_PARALLEL=4
set OLLAMA_MAX_LOADED_MODELS=3

start http://localhost:8000/
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000



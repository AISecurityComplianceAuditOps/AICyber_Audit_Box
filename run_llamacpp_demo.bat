@echo off
title AICyberAuditBox llama.cpp Unified Launcher
echo ==================================================
echo   Starting AICyberAuditBox with llama.cpp backend
echo ==================================================

echo.
echo [1/5] Stopping any existing Ollama or llama-server processes (excluding Docker)...
taskkill /F /IM ollama* /T >nul 2>&1
taskkill /F /IM llama-server* /T >nul 2>&1
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 11434,11435,11436 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p -and $p.ProcessName -notlike '*docker*') { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }" >nul 2>&1
echo [v] Ports 11434, 11435 and 11436 cleared safely without stopping Docker.


echo.
set "LLAMA_SERVER_EXE="
if exist "C:\Users\veeresh988V\Desktop\llama\llama-server.exe" (
    set "LLAMA_SERVER_EXE=C:\Users\veeresh988V\Desktop\llama\llama-server.exe"
) else if exist "C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe" (
    set "LLAMA_SERVER_EXE=C:\Users\HP\Downloads\llama,,ccppp mode\llama-server.exe"
) else (
    set "LLAMA_SERVER_EXE=%~dp0llama-server.exe"
)

echo [2/5] Starting LLM Instance 1 on port 11434 (4 threads)...
start "Llama LLM Server 1" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11434 -m "%~dp0google_gemma-4-E4B-it-Q4_K_M.gguf" -c 16384 -t 4 -b 2048 -ub 512 --mlock --flash-attn on

echo.
echo [3/5] Starting LLM Instance 2 on port 11436 (4 threads)...
start "Llama LLM Server 2" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11436 -m "%~dp0google_gemma-4-E4B-it-Q4_K_M.gguf" -c 16384 -t 4 -b 2048 -ub 512 --mlock --flash-attn on

echo.
echo [4/5] Starting Embedding Server on port 11435 (2 threads)...
start "Llama Embedding Server" /d "%~dp0" /min "%LLAMA_SERVER_EXE%" --port 11435 -m "%~dp0nomic-embed-text-v1.5.f16.gguf" -t 2 --mlock --embedding

echo.
echo Waiting 20 seconds for all 3 servers to initialize...
timeout /t 20 >nul

echo.
echo [5/5] Setting environment variables and launching app...
set LLM_BACKEND=llama.cpp
set LLM_HOSTS=11434,11436
set EMBEDDING_HOST=http://127.0.0.1:11435
set OLLAMA_KEEP_ALIVE=24h
set OLLAMA_NUM_PARALLEL=4
set OLLAMA_MAX_LOADED_MODELS=3

call run_demo.bat

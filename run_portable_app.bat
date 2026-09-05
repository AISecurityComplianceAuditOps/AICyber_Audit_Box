@echo off
TITLE AICyberAuditBox Launcher
COLOR 0A
echo ===================================================
echo   Starting AICyberAuditBox Standalone Engine...
echo ===================================================
echo.
echo [!] This launcher assumes ShaktiDB (Postgres, port 15234) and Redis
echo     (port 6380) are already running -- e.g. via "docker-compose up -d"
echo     and tools\redis\redis-server.exe. The LLM/embedding servers are
echo     started automatically by AICyberAuditBox.exe itself from the
echo     bundled llama-server.exe + model files if not already running.
echo.

:: Same core config run_all.bat uses for a known-working setup, so the
:: bundled exe isn't relying on internal os.environ.get(...) defaults that
:: were never verified against this specific launch path.
set LLM_BACKEND=llama.cpp
set EMBEDDING_HOST=http://127.0.0.1:11435
set REDIS_URL=redis://127.0.0.1:6380/0

:: Bundle-only: never silently fall back to a throwaway local SQLite file
:: if ShaktiDB Postgres isn't reachable -- fail loudly instead. NOT set in
:: run_all.bat/run_api.bat (dev), which intentionally keep the fallback.
set REQUIRE_POSTGRES=1

echo [1/2] Launching API Backend ^& Web Dashboard on http://localhost:8000 ...
start /B "" "AICyberAuditBox.exe"
timeout /t 3 >nul
echo [2/2] Opening Web Dashboard in default browser...
start http://localhost:8000
echo.
echo [OK] System is running! Keep this console window open while auditing.
pause

@echo off
REM AICyberAuditBox -- apply an LLM startup-settings update.
REM
REM Double-click. Rebuilds the model server's settings on top of the image this
REM machine already has, so nothing is downloaded and the ~12.6GB of weights
REM stay where they are.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0apply_llm_config.ps1"
set RC=%ERRORLEVEL%

echo.
if not "%RC%"=="0" (
    echo The update did not complete. Nothing was left half-applied:
    echo the script restores the compose file before it stops.
)
pause
exit /b %RC%

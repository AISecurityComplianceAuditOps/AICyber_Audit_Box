@echo off
REM AICyberAuditBox -- apply an application update.
REM
REM Double-click this. It sits beside the .tar and does the whole update:
REM verifies the download, loads the image, repoints the installation,
REM restarts the application and confirms the new image is running.
REM
REM A .bat rather than asking anyone to run PowerShell: the update has been
REM applied by hand before and every step of it went wrong somewhere --
REM a compose file edited in the wrong folder, a relative path resolved
REM against C:\WINDOWS\system32, a command pasted with its prompt still
REM attached. -ExecutionPolicy Bypass is scoped to this one run and changes
REM no machine setting.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0apply_update.ps1"
set RC=%ERRORLEVEL%

echo.
if not "%RC%"=="0" (
    echo The update did not complete. Nothing was left half-applied:
    echo the script restores the compose file before it stops.
)
pause
exit /b %RC%

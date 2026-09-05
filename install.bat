@echo off
REM Offline installer -- AICyberAuditBox (Windows).
REM
REM Loads every image from the single images tar beside this script, then starts
REM the stack. Nothing is downloaded: the machine never needs to reach a
REM registry, which is the point of an air-gapped install.
setlocal enabledelayedexpansion
set VERSION=__VERSION__
set IMAGES=aicyberauditbox-images-%VERSION%.tar
set COMPOSE=docker-compose.yml

echo ===========================================================
echo   AICyberAuditBox %VERSION% -- offline install
echo ===========================================================

docker info >nul 2>&1
if errorlevel 1 (
  echo ERROR: Docker is not running. Start Docker Desktop first.
  exit /b 1
)
if not exist "%IMAGES%" (
  echo ERROR: %IMAGES% is not in this folder. Run the installer from the
  echo        folder the bundle extracted into.
  exit /b 1
)

echo.
echo --^> Loading all images from %IMAGES%
echo     ^(__SIZE__; several minutes, and it prints nothing while it works^)
docker load -i "%IMAGES%"
if errorlevel 1 (
  echo ERROR: docker load failed.
  exit /b 1
)

echo.
echo --^> Verifying every image the stack needs is present
set MISSING=0
for %%I in (
  aicyberauditbox-app:%VERSION%
  aicyberauditbox-llm:%VERSION%
  aicyberauditbox-llm-embed:%VERSION%
  aicyberauditbox-shakthidb:3.10
  redis:7-alpine
) do (
  docker image inspect %%I >nul 2>&1
  if errorlevel 1 (
    echo     MISSING  %%I
    set MISSING=1
  ) else (
    echo     ok   %%I
  )
)
if "%MISSING%"=="1" (
  echo Aborting: the images above did not load.
  exit /b 1
)

echo.
echo --^> Starting the stack
docker compose -f %COMPOSE% up -d
if errorlevel 1 (
  echo Failed to start. Check: docker compose -f %COMPOSE% logs
  exit /b 1
)

echo.
echo --^> Waiting for the application to answer ^(up to 5 minutes^)
for /L %%N in (1,1,100) do (
  REM -f makes curl exit non-zero on any HTTP error, so a zero exit IS the
  REM readiness signal. Piping %%{http_code} into findstr was fragile: it
  REM matched "200" anywhere in the output, and curl's own failures left
  REM partial text behind.
  curl -fs --max-time 5 http://localhost:8000/ >nul 2>&1
  if !errorlevel! equ 0 (
    REM The app answering is not the whole story. The LLM is a separate
    REM container and the app comes up perfectly well without it, so an LLM
    REM that refused to start -- nearly always too little memory for the
    REM selected model -- used to end with this script printing "Ready" and the
    REM customer discovering the truth one failed audit at a time, on a machine
    REM with no internet to ask about it. Check it here and show the reason.
    REM .State.Running alone is not enough. The service is restart: always, so
    REM a container that refuses to start flaps -- and an inspect landing during
    REM one of those moments reports Running=true, which is how this check first
    REM passed over an LLM that was crash-looping on every attempt. RestartCount
    REM is the durable signal: a clean start has never restarted.
    set LLM_CID=
    for /f "delims=" %%C in ('docker compose -f %COMPOSE% ps -aq llm 2^>nul') do set LLM_CID=%%C
    set LLM_STATE=missing
    set LLM_RESTARTS=0
    if defined LLM_CID (
      for /f "delims=" %%R in ('docker inspect -f "{{.State.Status}}" !LLM_CID! 2^>nul') do set LLM_STATE=%%R
      for /f "delims=" %%N in ('docker inspect -f "{{.RestartCount}}" !LLM_CID! 2^>nul') do set LLM_RESTARTS=%%N
    )
    set LLM_BAD=0
    if not "!LLM_STATE!"=="running" set LLM_BAD=1
    if not "!LLM_RESTARTS!"=="0" set LLM_BAD=1
    if "!LLM_BAD!"=="1" (
      echo.
      echo ===========================================================
      echo   The application is up, but the LLM is NOT healthy.
      echo ===========================================================
      echo.
      echo   llm container state: !LLM_STATE!, restarts: !LLM_RESTARTS!
      echo.
      echo   It reported:
      docker compose -f %COMPOSE% logs --tail 25 llm
      echo.
      echo   Audits cannot run until this is resolved.
      echo   See INSTALL_v%VERSION%.md, section 6 ^(choosing the model^).
      exit /b 1
    )
    echo.
    echo ===========================================================
    echo   Ready.  Open http://localhost:8000/
    echo ===========================================================
    echo.
    echo Confirm the LLM sized itself correctly for this machine:
    echo   docker compose -f %COMPOSE% logs llm ^| findstr "LLM ENTRYPOINT"
    echo.
    echo The last line must read "= 32768 tokens per request". A lower number
    echo means the machine has less RAM than the LLM expected, and evidence
    echo would be truncated before the model sees it -- see INSTALL_v%VERSION%.md.
    exit /b 0
  )
  timeout /t 3 /nobreak >nul
)

echo The app did not answer in time. Check:
echo   docker compose -f %COMPOSE% ps
echo   docker compose -f %COMPOSE% logs app
exit /b 1

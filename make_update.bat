@echo off
REM ===========================================================================
REM  AICyberAuditBox -- build an update to send to a customer.
REM
REM  Double-click. Pick what changed. It builds the right thing, checksums it,
REM  and drops the customer's one-click applier beside it.
REM
REM  The sizes differ by more than a hundredfold, which is the whole reason for
REM  the menu: an application change is 2.3GB, and a change to how the model
REM  server starts is ten kilobytes.
REM ===========================================================================
setlocal enabledelayedexpansion
chcp 65001 >nul
title AICyberAuditBox - Build an Update
cd /d "%~dp0"

echo ===========================================================================
echo   AICyberAuditBox  --  Build an update
echo ===========================================================================
echo.

docker info >nul 2>&1
if errorlevel 1 (
    echo [X] Docker is not running. Start Docker Desktop and run this again.
    goto :fail
)

echo   What changed?
echo.
echo     [1]  Application code, Python packages, system packages, the report
echo          template                                            ~2.3 GB
echo.
echo     [2]  LLM startup settings only -- threads, slots, context
echo          size, which model is served                          ~10 KB
echo.
echo     [3]  LLM model weights (a different .gguf)                 ~13 GB
echo.
echo     [4]  Database -- init.sql or the Postgres image           ~620 MB
echo.
echo     [5]  Everything, or a first installation                   ~14 GB
echo.
set /p CHOICE="  Choose 1-5: "
echo.

if "!CHOICE!"=="5" (
    echo   Handing over to make_bundle.bat for a full bundle.
    echo.
    call make_bundle.bat
    exit /b %ERRORLEVEL%
)
if not "!CHOICE!"=="1" if not "!CHOICE!"=="2" if not "!CHOICE!"=="3" if not "!CHOICE!"=="4" (
    echo   [X] Choose a number from 1 to 5.
    goto :fail
)

REM --- Version -------------------------------------------------------------
for /f "tokens=2 delims=:" %%V in ('findstr /c:"image: aicyberauditbox-app:" docker-compose.customer.yml') do set CURVER=%%V
set CURVER=!CURVER: =!
echo   The shipped compose currently names !CURVER!
set /p VERSION="  New version to build [e.g. 3.28]: "
if "!VERSION!"=="" (
    echo   [X] A version is required.
    goto :fail
)
set OUTDIR=..\customer_deployment_package\v!VERSION!
echo   -^> building !VERSION!
echo.

REM --- Tests, for anything carrying our own code ---------------------------
REM  Before the build, not after: a failing suite is far cheaper to find here
REM  than in a multi-gigabyte artifact already on its way to a customer.
if "!CHOICE!"=="1" (
    echo ---^> Running the tests
    python -m pytest -q
    if errorlevel 1 (
        echo.
        echo   [X] Tests failed. Nothing has been built.
        goto :fail
    )
    echo   [ok] Tests pass.
    echo.
)

REM =========================================================================
if "!CHOICE!"=="1" goto :app
if "!CHOICE!"=="2" goto :llmconf
if "!CHOICE!"=="3" goto :llmfull
if "!CHOICE!"=="4" goto :db

REM --------------------------------------------------------------- 1: app --
:app
echo ---^> Building the application image
docker build -f Dockerfile.app --build-arg COMPILE_SOURCE=0 -t aicyberauditbox-app:!VERSION! .
if errorlevel 1 goto :buildfail
echo.
REM  The build proves the listed libraries install, not that the application
REM  works: a library the code imports but requirements.txt does not name
REM  builds cleanly and fails at the customer. So check the image itself --
REM  imports, libraries, knowledge files, a sample scan, the reports -- with no
REM  network, as an air-gapped site runs it, before anything is packaged.
echo ---^> Checking the new image works (no network, as at the customer)
docker run --rm --network none --entrypoint python -e POSTGRES_PASSWORD= -v "%~dp0scripts\image_smoke_test.py:/tmp/image_smoke_test.py:ro" -w /app aicyberauditbox-app:!VERSION! /tmp/image_smoke_test.py
if errorlevel 1 (
    echo.
    echo   [X] The new image failed its check. Nothing has been packaged.
    goto :fail
)
echo.
REM  The check above uses SQLite, which ignores column types, on an empty
REM  database. A customer runs Postgres on a database an earlier version
REM  created: 1.2.3 passed here and saved 0 findings there. So also run the
REM  new image on the customer's database image -- fresh, and upgrading a
REM  database built by earlier versions -- and prove a scan is saved.
echo ---^> Checking the new image on Postgres: fresh, and upgrading an earlier database
python scripts\upgrade_e2e_check.py --image aicyberauditbox-app:!VERSION! --new-version !VERSION!
if errorlevel 1 (
    echo.
    echo   [X] The new image failed on Postgres. Nothing has been packaged.
    goto :fail
)
echo.
echo ---^> Packaging
python build_customer_bundle.py --version !VERSION! --skip-build
if errorlevel 1 goto :buildfail
set TARNAME=aicyberauditbox-app-!VERSION!.tar
goto :finish

REM ------------------------------------------------- 2: LLM settings only --
REM  Dockerfile.llm.rebase layers a new entrypoint onto the LLM image the
REM  customer already holds, so this ships the shell script and the recipe
REM  rather than 13GB of unchanged model weights. The customer rebuilds in
REM  seconds, entirely offline, against the image they already have.
:llmconf
echo ---^> Packaging the LLM startup settings
set STAGE=!OUTDIR!\llm-config-!VERSION!
if not exist "!OUTDIR!" mkdir "!OUTDIR!"
if exist "!STAGE!" rmdir /s /q "!STAGE!"
mkdir "!STAGE!\docker"
copy /y docker\llm-entrypoint.sh "!STAGE!\docker\" >nul
copy /y Dockerfile.llm.rebase "!STAGE!\" >nul
copy /y apply_llm_config.ps1 "!STAGE!\" >nul
copy /y apply_llm_config.bat "!STAGE!\" >nul
powershell -NoProfile -Command ^
  "Compress-Archive -Path '!STAGE!\*' -DestinationPath '!OUTDIR!\aicyberauditbox-llm-config-!VERSION!.zip' -Force"
if errorlevel 1 goto :buildfail
rmdir /s /q "!STAGE!"
echo   [ok] aicyberauditbox-llm-config-!VERSION!.zip
echo.
echo ===========================================================================
echo   Ready to send:  !OUTDIR!
echo ===========================================================================
echo.
echo   Send:   aicyberauditbox-llm-config-!VERSION!.zip     ^(a few KB^)
echo.
echo   Tell them: extract it anywhere and double-click apply_llm_config.bat.
echo   It rebuilds their LLM image on top of the one they already have -- no
echo   download, no model copy, seconds rather than a 13 GB transfer.
echo.
pause
exit /b 0

REM -------------------------------------------------- 3: LLM full image ----
:llmfull
echo ---^> Building the LLM image (copies ~12.6 GB of weights; slow)
docker build -f Dockerfile.llm -t aicyberauditbox-llm:!VERSION! .
if errorlevel 1 goto :buildfail
docker tag aicyberauditbox-llm:!VERSION! aicyberauditbox-llm-embed:!VERSION!
if errorlevel 1 goto :buildfail
echo.
echo ---^> Exporting both tags into one tar (shared layers, written once)
if not exist "!OUTDIR!" mkdir "!OUTDIR!"
set TARNAME=aicyberauditbox-llm-!VERSION!.tar
docker save -o "!OUTDIR!\!TARNAME!" aicyberauditbox-llm:!VERSION! aicyberauditbox-llm-embed:!VERSION!
if errorlevel 1 goto :buildfail
goto :finish

REM -------------------------------------------------------- 4: database ----
:db
echo ---^> Building the database image
docker build -f Dockerfile -t aicyberauditbox-shakthidb:!VERSION! .
if errorlevel 1 goto :buildfail
echo.
echo ---^> Exporting
if not exist "!OUTDIR!" mkdir "!OUTDIR!"
set TARNAME=aicyberauditbox-shakthidb-!VERSION!.tar
docker save -o "!OUTDIR!\!TARNAME!" aicyberauditbox-shakthidb:!VERSION!
if errorlevel 1 goto :buildfail
echo.
echo   NOTE: existing audit data lives in a Docker volume and is NOT replaced
echo         by this. The image carries the schema and Postgres itself.
goto :finish

REM ------------------------------------------------------------- finish ----
:finish
echo.
echo ---^> Checksum, and the customer's one-click applier
powershell -NoProfile -Command ^
  "$f = Join-Path '!OUTDIR!' '!TARNAME!';" ^
  "if (-not (Test-Path $f)) { Write-Host '  [X] expected file not found: ' $f; exit 1 };" ^
  "$h = (Get-FileHash -Algorithm SHA256 $f).Hash;" ^
  "$h | Out-File -Encoding ascii ($f + '.sha256');" ^
  "Write-Host ('  [ok] SHA256 ' + $h)"
if errorlevel 1 goto :buildfail

copy /y apply_update.bat "!OUTDIR!\" >nul
copy /y apply_update.ps1 "!OUTDIR!\" >nul
echo   [ok] apply_update.bat + .ps1 copied beside the image

echo.
echo ===========================================================================
echo   Ready to send:  !OUTDIR!
echo ===========================================================================
echo.
echo   Send these together:
echo       !TARNAME!
echo       !TARNAME!.sha256
echo       apply_update.bat
echo       apply_update.ps1
echo.
echo   Tell them: put all four in one folder and double-click apply_update.bat.
echo   It works out which component this is, verifies the download, loads the
echo   image, repoints their installation, restarts only what changed, and
echo   confirms the new version is running.
echo.
echo   Put the checksum in your message too, so it does not travel only
echo   alongside the file it vouches for.
echo.
pause
exit /b 0

:buildfail
echo.
echo   [X] Build failed.
:fail
echo.
echo Update NOT built.
echo.
pause
exit /b 1

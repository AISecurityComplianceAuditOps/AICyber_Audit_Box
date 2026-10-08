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

REM  A per-user Python and Docker Desktop install do not always put themselves
REM  on PATH (an Administrator window gets its own); without them "docker info"
REM  reports Docker as not running while it runs. The same as run_all.bat.
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PATH=%LOCALAPPDATA%\Programs\Python\Python311;%LOCALAPPDATA%\Programs\Python\Python311\Scripts;%PATH%"
)
if exist "%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe" (
    set "PATH=%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin;%PATH%"
)

REM  Where builds are written: one folder on the Desktop for every build,
REM  AICyberAuditBox_Builds\v<version>. (It was ..\customer_deployment_package.)
REM  The Desktop is asked for, not assumed -- it can be redirected.
for /f "usebackq delims=" %%D in (`powershell -NoProfile -Command "[Environment]::GetFolderPath('Desktop')"`) do set "BUILDS_ROOT=%%D\AICyberAuditBox_Builds"
if not defined BUILDS_ROOT set "BUILDS_ROOT=%USERPROFILE%\Desktop\AICyberAuditBox_Builds"

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
echo          template -- and the AI startup settings: slots, memory ~2.3 GB
echo.
echo     [2]  LLM startup settings only, for a site taking no app
echo          update -- [1] already carries them                   ~10 KB
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
REM  A hint only: the newest image of this component already built here. (This
REM  used to read the compose file with "tokens=2 delims=:", which splits
REM  "image: aicyberauditbox-app:1.2.3" at every colon and printed the image
REM  NAME as the version.)
set IMGNAME=aicyberauditbox-app
if "!CHOICE!"=="2" set IMGNAME=aicyberauditbox-llm
if "!CHOICE!"=="3" set IMGNAME=aicyberauditbox-llm
if "!CHOICE!"=="4" set IMGNAME=aicyberauditbox-shakthidb
set CURVER=
for /f "delims=" %%V in ('docker images !IMGNAME! --format "{{.Tag}}" 2^>nul') do if not defined CURVER if not "%%V"=="<none>" if not "%%V"=="entrypoint-check" set CURVER=%%V
if defined CURVER (echo   Newest !IMGNAME! image on this PC: !CURVER!) else (echo   No !IMGNAME! image on this PC yet.)
set /p VERSION="  New version to build [e.g. 1.2.5]: "
if "!VERSION!"=="" (
    echo   [X] A version is required.
    goto :fail
)
set "OUTDIR=!BUILDS_ROOT!\v!VERSION!"
echo   -^> building !VERSION!
echo.

REM --- Tests, for every choice ---------------------------------------------
REM  Before the build, not after: a failing suite is far cheaper to find here
REM  than in a multi-gigabyte artifact already on its way to a customer. Every
REM  choice, not only the application: the suite also pins the LLM startup
REM  script (its memory sizing, its Linux line endings) and the shipped
REM  installers, which options 2 and 3 carry.
echo ---^> Running the tests
python -m pytest -q
if errorlevel 1 (
    echo.
    echo   [X] Tests failed. Nothing has been built.
    goto :fail
)
echo   [ok] Tests pass.
echo.

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
REM  The app image also carries the model server's startup script, and the
REM  customer's apply_update builds it onto their LLM image when it differs:
REM  it decides how many audits their machine can hold. Start it on a real LLM
REM  image here when this PC has one -- the check option 2 runs.
set HAVELLM=
for /f "delims=" %%V in ('docker images aicyberauditbox-llm --format "{{.Tag}}" 2^>nul') do if not "%%V"=="<none>" if not "%%V"=="entrypoint-check" set HAVELLM=1
if defined HAVELLM (
    echo ---^> Checking the AI startup script it carries on a real LLM image
    python scripts\llm_image_check.py --rebase-on newest
    if errorlevel 1 (
        echo.
        echo   [X] The startup script failed its check. Nothing has been packaged.
        goto :fail
    )
) else (
    echo   NOTE: No aicyberauditbox-llm image on this PC, so the AI startup script
    echo         this update carries was not started on a real engine. The tests
    echo         still pin it. Load the LLM image customers run to check it here.
)
echo.
echo ---^> Packaging
python build_customer_bundle.py --version !VERSION! --skip-build --app-only --out "!BUILDS_ROOT!"
if errorlevel 1 goto :buildfail
set TARNAME=aicyberauditbox-app-!VERSION!.tar
goto :finish

REM ------------------------------------------------- 2: LLM settings only --
REM  Dockerfile.llm.rebase layers a new entrypoint onto the LLM image the
REM  customer already holds, so this ships the shell script and the recipe
REM  rather than 13GB of unchanged model weights. The customer rebuilds in
REM  seconds, entirely offline, against the image they already have.
:llmconf
REM  The script is tested the way it will run: built onto the newest LLM image
REM  on this PC and started as on a 16-core / 32GB machine. The build never
REM  used to run it at all, so a script that failed to start, or an engine
REM  without a flag it relies on, reached the customer untested.
echo ---^> Checking the startup script on a real LLM image
python scripts\llm_image_check.py --rebase-on newest
if errorlevel 1 (
    echo.
    echo   [X] The startup script failed its check. Nothing has been packaged.
    goto :fail
)
echo ---^> Packaging the LLM startup settings
set STAGE=!OUTDIR!\llm-config-!VERSION!
if not exist "!OUTDIR!" mkdir "!OUTDIR!"
if exist "!STAGE!" rmdir /s /q "!STAGE!"
mkdir "!STAGE!\docker"
copy /y docker\llm-entrypoint.sh "!STAGE!\docker\" >nul
copy /y Dockerfile.llm.rebase "!STAGE!\" >nul
copy /y apply_llm_config.ps1 "!STAGE!\" >nul
copy /y apply_llm_config.bat "!STAGE!\" >nul
copy /y apply_llm_config.sh "!STAGE!\" >nul
for %%A in ("!OUTDIR!") do set OUTABS=%%~fA
for %%A in ("!STAGE!") do set STAGEABS=%%~fA
set ZIPFILE=!OUTABS!\aicyberauditbox-llm-config-!VERSION!.zip
if exist "!ZIPFILE!" del /q "!ZIPFILE!"
REM  Windows' own tar, not Compress-Archive: Windows PowerShell 5.1 stores
REM  "docker\llm-entrypoint.sh" with a backslash, which a Linux unzip may keep
REM  as part of the file name instead of making a docker/ folder.
"%SystemRoot%\System32\tar.exe" -a -c -f "!ZIPFILE!" -C "!STAGEABS!" Dockerfile.llm.rebase docker apply_llm_config.ps1 apply_llm_config.bat apply_llm_config.sh
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
echo   Tell them: extract it anywhere, then
echo       Windows:  double-click apply_llm_config.bat
echo       Linux:    sudo sh apply_llm_config.sh
echo   It rebuilds their LLM image on top of the one they already have -- no
echo   download, no model copy, seconds rather than a 13 GB transfer.
echo.
echo   A site that pulls from Artifact Registry is not updated this way: push
echo   a rebuilt llm and llm-embed image there instead.
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
REM  Dockerfile.llm builds on llama.cpp's floating :server tag, so the engine
REM  is whatever was newest on the day. Start it as a customer machine would
REM  before it is exported: the model files, the startup script, the flags.
echo ---^> Checking the new LLM image starts correctly
python scripts\llm_image_check.py --image aicyberauditbox-llm:!VERSION!
if errorlevel 1 (
    echo.
    echo   [X] The new LLM image failed its check. Nothing has been packaged.
    goto :fail
)
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
copy /y apply_update.sh "!OUTDIR!\" >nul
echo   [ok] apply_update.bat + .ps1 (Windows) and apply_update.sh (Linux) copied beside the image

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
echo       apply_update.sh
echo.
echo   Tell them: put them all in one folder, then
echo       Windows:  double-click apply_update.bat
echo       Linux:    sudo sh apply_update.sh
echo   It works out which component this is, verifies the download, backs up
echo   their audits, loads the image, repoints their installation, restarts
echo   only what changed, and confirms the new version is running.
echo.
if "!CHOICE!"=="1" (
    echo   An application update also brings the AI startup settings. When they
    echo   changed, apply_update rebuilds their model server on them in seconds,
    echo   no download, and shows how many audits their machine can hold.
    echo.
)
echo   A site that pulls from Artifact Registry is not updated with a tar:
echo   tag and push the image there, then they run setup_registry.sh.
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

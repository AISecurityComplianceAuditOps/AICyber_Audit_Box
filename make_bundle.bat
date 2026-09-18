@echo off
REM ===========================================================================
REM  AICyberAuditBox -- one-click customer bundle builder.
REM
REM  Double-click this file. It asks for a version, builds the four product
REM  images, and packages them into ONE tar the customer extracts and installs
REM  with no internet and nothing pre-installed but Docker.
REM
REM  Everything the running product needs is inside that tar: the model weights,
REM  the OCR and reranker caches, Postgres, Redis, the frontend. The customer
REM  never reaches a registry, a pip index or huggingface.
REM
REM  Wraps build_customer_bundle.py --full. That script does the packaging and
REM  is the authority on tar layout; this one does the image builds first, so
REM  it is called with --skip-build.
REM ===========================================================================
setlocal enabledelayedexpansion
chcp 65001 >nul
title AICyberAuditBox - Build Customer Bundle
cd /d "%~dp0"

echo ===========================================================================
echo   AICyberAuditBox  --  Customer Bundle Builder
echo ===========================================================================
echo.

REM --- Docker must be up before anything else is worth checking. ------------
docker info >nul 2>&1
if errorlevel 1 (
    echo [X] Docker is not running. Start Docker Desktop and run this again.
    goto :fail
)
echo [ok] Docker is running.

REM --- Free space. Two things consume it and they are easy to conflate.
REM
REM     The bundle output is the hard cost: docker save writes ~20GB into the
REM     staging folder, then the outer wrap writes ~20GB more before the staged
REM     copy is deleted. That is 40GB of ordinary disk, always.
REM
REM     Docker's own store is the soft cost. It lives in a VHDX that grows but
REM     never shrinks on its own, so building the new images may cost nothing
REM     (reusing slack left by deleted layers) or up to ~20GB more. Deleting the
REM     superseded image tags first makes it the former.
REM
REM     Hence 45 below rather than the 40 the tars strictly need: enough margin
REM     that a partly-full Docker store does not strand the build at the last
REM     step, having already spent the hours.
for /f %%F in ('powershell -NoProfile -Command "[math]::Floor((Get-PSDrive C).Free/1GB)"') do set FREEGB=%%F
echo [i]  Free space on C: !FREEGB! GB
if !FREEGB! LSS 45 (
    echo.
    echo [X] Not enough disk space. A full bundle needs about 45 GB free:
    echo     ~20 GB for the saved images tar, ~20 GB for the outer wrap, and
    echo     margin for Docker's store to grow. 60 GB is comfortable.
    echo.
    echo     Removing superseded image tags is the cheapest fix -- check what
    echo     is there first:
    echo         docker images
    echo     then remove the old tags you no longer need, for example:
    echo         docker rmi aicyberauditbox-llm:2.2 aicyberauditbox-llm-embed:2.2
    echo.
    echo     Note that this frees space INSIDE Docker's virtual disk, which
    echo     stops the new images from growing it further. It does not hand
    echo     space back to Windows. To reclaim that too:
    echo         docker system prune -a --volumes
    echo         wsl --shutdown  ^&^&  Optimize-VHD (admin PowerShell)
    echo.
    echo     Or pass a different output drive when packaging:
    echo         python build_customer_bundle.py --version VER --full --out D:\bundles
    echo.
    set /p SPACEGO="Continue anyway? (y/N): "
    if /i not "!SPACEGO!"=="y" goto :fail
)

REM --- Version. Asked every run: the tag has to match what the shipped
REM     compose names, and guessing it wrong ships a compose file pointing at
REM     an image the bundle does not contain.
echo.
for /f "tokens=2 delims=:" %%V in ('findstr /c:"image: aicyberauditbox-app:" docker-compose.yml') do set CURVER=%%V
set CURVER=!CURVER: =!
echo   docker-compose.yml currently names version !CURVER!
set /p VERSION="  Version to build [!CURVER!]: "
if "!VERSION!"=="" set VERSION=!CURVER!
echo   -^> building version !VERSION!

REM --- Source protection. Off by default, deliberately: src/ resolves 15 data
REM     paths from __file__ (knowledge JSON, report assets, the embeddings
REM     cache), and compiling the package into a single .so moves __file__ out
REM     from under every one of them. pqc_crypto_db._load_json swallows the
REM     failure and returns {}, so a broken compile looks like a working
REM     product until a PQC audit comes back empty at the customer site.
REM     The compiled image verifies those loads at build time and fails there
REM     instead. Leave this off until one compiled build has been tested.
echo.
echo   Compile src/ to a binary with Nuitka, so the customer cannot read
echo   the Python source? Verified at build time; see COMPILE_SOURCE in
echo   Dockerfile.app. Answer n if you have not tested a compiled build yet.
set /p COMPILE="  Compile source? (y/N): "
if /i "!COMPILE!"=="y" (set COMPILE_SOURCE=1) else (set COMPILE_SOURCE=0)
if "!COMPILE_SOURCE!"=="1" (echo   -^> compiled, source not shipped) else (echo   -^> readable source)

set DB_TAG=aicyberauditbox-shakthidb:3.10
set LLM_TAG=aicyberauditbox-llm:!VERSION!
set EMB_TAG=aicyberauditbox-llm-embed:!VERSION!
set APP_TAG=aicyberauditbox-app:!VERSION!

echo.
echo ===========================================================================
echo   Building images. The LLM image copies about 18 GB of model weights,
echo   so the first build takes a while and looks idle during the copy.
echo ===========================================================================

REM --- 1/4 Database -------------------------------------------------------
echo.
echo ---^> 1/4  ShaktiDB  (!DB_TAG!)
call :build_if_missing "!DB_TAG!" "docker build -f Dockerfile -t !DB_TAG! ."
if errorlevel 1 goto :fail

REM --- 2/4 Redis ----------------------------------------------------------
echo.
echo ---^> 2/4  Redis  (redis:7-alpine)
docker image inspect redis:7-alpine >nul 2>&1
if errorlevel 1 (
    echo      pulling redis:7-alpine
    docker pull redis:7-alpine
    if errorlevel 1 (
        echo      [X] Could not pull Redis. This machine needs internet to BUILD
        echo          the bundle -- only the customer runs offline.
        goto :fail
    )
) else (
    echo      already present, reusing
)

REM --- 3/4 LLM + embedding ------------------------------------------------
REM     One image, two tags. Dockerfile.llm bakes both completion models and
REM     the embedding model in; docker/llm-entrypoint.sh picks which server to
REM     start from LLM_MODE at runtime. Tagging twice costs nothing because
REM     the layers are shared -- building twice would copy 18 GB again.
echo.
echo ---^> 3/4  LLM + embedding  (!LLM_TAG!, !EMB_TAG!)
docker image inspect !LLM_TAG! >nul 2>&1
if errorlevel 1 (
    echo      building (copies ~18 GB of GGUF weights, be patient)
    docker build -f Dockerfile.llm -t !LLM_TAG! .
    if errorlevel 1 (
        echo      [X] LLM image build failed.
        goto :fail
    )
) else (
    echo      !LLM_TAG! already present, reusing
)
docker tag !LLM_TAG! !EMB_TAG!
if errorlevel 1 goto :fail
echo      tagged !EMB_TAG! from the same image

REM --- 4/4 Application ----------------------------------------------------
echo.
echo ---^> 4/4  Application  (!APP_TAG!)
echo      docker build -f Dockerfile.app --build-arg COMPILE_SOURCE=!COMPILE_SOURCE!
docker build -f Dockerfile.app --build-arg COMPILE_SOURCE=!COMPILE_SOURCE! -t !APP_TAG! .
if errorlevel 1 (
    echo      [X] App image build failed.
    if "!COMPILE_SOURCE!"=="1" (
        echo          The compiled build verifies that the knowledge JSON files
        echo          still load from inside the binary. If that check is what
        echo          failed, rerun and answer n to "Compile source".
    )
    goto :fail
)

REM --- Package ------------------------------------------------------------
REM     --skip-build because every image was just built above, with the
REM     COMPILE_SOURCE choice applied. Letting the Python script build again
REM     would rebuild the app image without that argument and silently ship
REM     readable source from a run that asked for compiled.
echo.
echo ===========================================================================
echo   Packaging into one tar
echo ===========================================================================
python build_customer_bundle.py --version !VERSION! --full --skip-build
if errorlevel 1 (
    echo.
    echo [X] Packaging failed.
    goto :fail
)

echo.
echo ===========================================================================
echo   Done. The tar above is the whole handover -- give the customer that one
echo   file. They extract it and run install.sh (or install.bat) inside.
echo ===========================================================================
echo.
pause
exit /b 0

REM ---------------------------------------------------------------------------
:build_if_missing
REM  %~1 image tag, %~2 build command. Rebuilding a 12 GB image that is already
REM  present is the slowest possible way to change nothing.
docker image inspect %~1 >nul 2>&1
if errorlevel 1 (
    echo      building
    %~2
    if errorlevel 1 (
        echo      [X] build failed: %~1
        exit /b 1
    )
) else (
    echo      already present, reusing
)
exit /b 0

REM ---------------------------------------------------------------------------
:fail
echo.
echo Bundle NOT created.
echo.
pause
exit /b 1

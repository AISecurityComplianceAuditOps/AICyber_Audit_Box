"""
create_app_patch.py -- Generates a complete, un-truncated Delta App Patch Package.
Includes ALL application-related directories, code, engines, configs, SQL schemas, PDF reports, 
sample evidence files, unit tests, and startup scripts -- EXCLUDING only heavy LLM .gguf model weights.

Target App Directories & Files:
- src/ (All PQC, VAPT, ISO 27001 engines, DB models, endpoints, UI app.js)
- config/ (All system configurations)
- docs/ (All PQC PDF reports, user guides, hacker threat guides)
- samples/ & VAPT/ (All sample audit reports & evidence)
- docker/ (wait_for_postgres.py, generate_secrets.sh, offline model caches)
- testsprite_tests/ & tests/ (All unit & integration test suites)
- scripts/ & tools/ (Utility & maintenance scripts)
- requirements.txt, init.sql, sql.config, nginx.conf, cert.pem, key.pem
- Dockerfile*, docker-compose*.yml, run_all.bat, run_all.sh, run_api.bat, run_api.sh
"""
import os, sys, tarfile, shutil
from datetime import datetime

PROJECT_DIR = r"c:\Users\veeresh988V\Desktop\Local_audit_box_full\audit test_box"
PATCH_OUTPUT_DIR = r"c:\Users\veeresh988V\Desktop\Local_audit_box_full\customer_deployment_package\patches"

TARGET_PATHS = [
    "src",
    "config",
    "docs",
    "samples",
    "aa audit evidence samples",
    "pqc samples",
    "VAPT",
    "docker",
    "testsprite_tests",
    "tests",
    "scripts",
    "tools",
    "requirements.txt",
    "init.sql",
    "sql.config",
    "nginx.conf",
    "cert.pem",
    "key.pem",
    "Sample report.docx",
    "Dockerfile",
    "Dockerfile.app",
    "Dockerfile.llm",
    "docker-compose.yml",
    "docker-compose.customer.yml",
    "docker-compose.local-db.yml",
    "run_all.bat",
    "run_all.sh",
    "run_api.bat",
    "run_api.sh",
    "README.md",
    "CUSTOMER_SETUP_GUIDE_v3.12.md"
]

EXCLUDE_DIRS = {"__pycache__", ".pytest_cache", ".venv", "node_modules", ".git", ".tempmediaStorage"}
EXCLUDE_EXTS = {".pyc", ".pyo", ".gguf", ".ova", ".tar", ".tar.gz", ".db"}

def build_patch():
    print("=" * 80)
    print("  BUILDING COMPLETE FULL APP DELTA PATCH PACKAGE (ALL APP CODE & DATA)")
    print("=" * 80)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(PATCH_OUTPUT_DIR, exist_ok=True)

    patch_filename = f"aicyberauditbox_delta_app_patch_{timestamp}.tar.gz"
    latest_patch_filename = "aicyberauditbox_delta_app_patch_latest.tar.gz"
    
    patch_path = os.path.join(PATCH_OUTPUT_DIR, patch_filename)
    latest_patch_path = os.path.join(PATCH_OUTPUT_DIR, latest_patch_filename)

    print(f"\n---> Archiving all app-related files from: {PROJECT_DIR}")
    print(f"---> Patch file destination: {patch_path}")

    file_count = 0
    with tarfile.open(patch_path, "w:gz") as tar:
        for item in TARGET_PATHS:
            item_path = os.path.join(PROJECT_DIR, item)
            if not os.path.exists(item_path):
                continue

            if os.path.isfile(item_path):
                arcname = "app_patch/" + item.replace(os.sep, "/")
                tar.add(item_path, arcname=arcname)
                file_count += 1
            else:
                for root, dirs, files in os.walk(item_path):
                    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
                    for file in files:
                        ext = os.path.splitext(file)[1].lower()
                        if ext in EXCLUDE_EXTS or file.endswith(".gguf") or file.endswith(".tar.gz"):
                            continue
                        full_path = os.path.join(root, file)
                        rel_path = os.path.relpath(full_path, PROJECT_DIR)
                        arcname = "app_patch/" + rel_path.replace(os.sep, "/")
                        tar.add(full_path, arcname=arcname)
                        file_count += 1

    shutil.copy2(patch_path, latest_patch_path)
    size_mb = os.path.getsize(patch_path) / (1024.0 * 1024.0)

    print(f"\n[PASS] Full Complete App Patch built cleanly! ({file_count} files, Size: {size_mb:.2f} MB)")

    # Generate apply_patch.bat for Windows customers
    apply_bat_content = """@echo off
echo ======================================================================
echo           APPLYING AICyberAuditBox COMPLETE APP PATCH
echo ======================================================================
echo.

echo Step 1: Extracting updated application code...
tar -xvf aicyberauditbox_delta_app_patch_latest.tar.gz
if errorlevel 1 ( echo [ERROR] Extraction failed & pause & exit /b 1 )

echo.
echo Step 2: Copying updated files into the running app container...
docker cp app_patch\\src\\. aicyberauditbox-app:/app/src/
docker cp app_patch\\config\\. aicyberauditbox-app:/app/config/
if exist app_patch\\docker docker cp app_patch\\docker\\. aicyberauditbox-app:/app/docker/

echo.
echo Step 3: Restarting App Service (PostgreSQL and LLM stay 100%% online)...
docker compose -f docker-compose.customer.yml restart app

echo.
echo ======================================================================
echo [PASS] Complete App Patch applied successfully!
echo ======================================================================
pause
"""
    bat_path = os.path.join(PATCH_OUTPUT_DIR, "apply_patch.bat")
    with open(bat_path, "w", encoding="utf-8") as f:
        f.write(apply_bat_content)

    # Generate apply_patch.sh for Linux customers
    apply_sh_content = """#!/bin/bash
set -e
echo "======================================================================"
echo "          APPLYING AICyberAuditBox COMPLETE APP PATCH"
echo "======================================================================"
echo ""

echo "Step 1: Extracting updated application code..."
tar -xvf aicyberauditbox_delta_app_patch_latest.tar.gz

echo ""
echo "Step 2: Copying updated files into the running app container..."
docker cp app_patch/src/. aicyberauditbox-app:/app/src/
docker cp app_patch/config/. aicyberauditbox-app:/app/config/
[ -d app_patch/docker ] && docker cp app_patch/docker/. aicyberauditbox-app:/app/docker/

echo ""
echo "Step 3: Restarting App Service (PostgreSQL and LLM stay 100% online)..."
docker compose -f docker-compose.customer.yml restart app

echo ""
echo "======================================================================"
echo "[PASS] Complete App Patch applied successfully!"
echo "======================================================================"
"""
    sh_path = os.path.join(PATCH_OUTPUT_DIR, "apply_patch.sh")
    with open(sh_path, "w", encoding="utf-8") as f:
        f.write(apply_sh_content)

    print(f"[PASS] Patch applier scripts generated: apply_patch.bat & apply_patch.sh")
    print("=" * 80)

if __name__ == "__main__":
    build_patch()

# -*- coding: utf-8 -*-
"""
AICyberAuditBox Standalone Windows Executable Builder
Compiles FastAPI backend + Static Frontend + SQLite DB + Llama server into a single-click executable.
"""

import os
import sys
import subprocess

def build_standalone_installer():
    print("=" * 70)
    print(" AICyberAuditBox - Single-Click Windows Executable Builder")
    print("=" * 70)

    # 1. Verify PyInstaller installation
    try:
        import PyInstaller
        print("[OK] PyInstaller module verified.")
    except ImportError:
        print("[+] Installing PyInstaller dependency...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # 2. Define spec content
    spec_content = """# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['src/api/main.py'],
    pathex=['.'],
    binaries=[
        ('llama-server.exe', '.'),
        ('nomic-embed-text-v1.5.f16.gguf', '.')
    ],
    datas=[
        ('src/api/static', 'src/api/static'),
        ('src/db', 'src/db'),
        ('data', 'data'),
        ('config', 'config')
    ],
    hiddenimports=[
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'starlette.middleware.base',
        'engineio.async_drivers.asgi',
        'sqlite3'
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AICyberAuditBox',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    icon=None
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='AICyberAuditBox'
)
"""

    spec_path = "AICyberAuditBox.spec"
    with open(spec_path, "w", encoding="utf-8") as f:
        f.write(spec_content)
    print(f"[OK] Generated PyInstaller specification file: '{spec_path}'")

    # 3. Create portable launcher batch file
    launcher_content = """@echo off
TITLE AICyberAuditBox Launcher
COLOR 0A
echo ===================================================
echo   Starting AICyberAuditBox Standalone Engine...
echo ===================================================
echo.
echo [1/2] Launching API Backend & Web Dashboard on http://localhost:8000 ...
start /B "" "AICyberAuditBox.exe"
timeout /t 3 >nul
echo [2/2] Opening Web Dashboard in default browser...
start http://localhost:8000
echo.
echo [OK] System is running! Keep this console window open while auditing.
pause
"""
    launcher_path = "run_portable_app.bat"
    with open(launcher_path, "w", encoding="utf-8") as f:
        f.write(launcher_content)
    print(f"[OK] Generated 1-Click Launcher script: '{launcher_path}'")

    print("\n[+] To compile the executable bundle, execute:")
    print("   pyinstaller --noconfirm AICyberAuditBox.spec")
    print("\n   The single-click bundle will be created at:")
    print("   dist/AICyberAuditBox/run_portable_app.bat")
    print("=" * 70)

if __name__ == "__main__":
    build_standalone_installer()

# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['src/api/main.py'],
    pathex=['.'],
    binaries=[
        ('llama-server.exe', '.'),
        ('google_gemma-4-E4B-it-Q4_K_M.gguf', '.'),
        ('nomic-embed-text-v1.5.f16.gguf', '.')
    ],
    datas=[
        ('src/api/static', 'src/api/static'),
        ('src/db', 'src/db'),
        ('src/core/knowledge', 'src/core/knowledge'),
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

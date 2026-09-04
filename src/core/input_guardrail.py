# -*- coding: utf-8 -*-
"""
input_guardrail.py
4-Layer file security scanner for audit document uploads.
All layers use only Python built-in modules — zero new dependencies.

Layer 1: Magic bytes verification (extension spoofing detection)
Layer 2: Office VBA macro detection (Word/Excel malware)
Layer 3: ZIP bomb detection (compression ratio check)
Layer 4: Baseline text checks (null-bytes, dangerous extensions, size)

Returns (safe: bool, reason: str).
When safe=False, the caller should WARN the auditor — never block the upload.
"""

import zipfile
import struct
import io

# ── Known file magic byte signatures ─────────────────────────────────────────
MAGIC_SIGNATURES = {
    b"%PDF":           "pdf",
    b"PK\x03\x04":    "zip/office",   # ZIP, DOCX, XLSX, PPTX all start with PK
    b"\x89PNG":        "png",
    b"\xff\xd8\xff":   "jpg",
    b"\xd0\xcf\x11\xe0": "doc/xls",  # Legacy OLE2 Office format
}

# Extensions that should NOT appear inside a ZIP/archive upload
DANGEROUS_EXTENSIONS = {
    ".exe", ".ps1", ".bat", ".cmd", ".js", ".vbs",
    ".scr", ".msi", ".dll", ".com", ".jar", ".sh"
}

# Max safe uncompressed text size (50MB)
MAX_TEXT_BYTES = 50_000_000

# Max safe ZIP decompression ratio
MAX_ZIP_RATIO = 100

# Max safe total uncompressed ZIP size (500MB)
MAX_UNCOMPRESSED_BYTES = 500_000_000


def _check_magic_bytes(filename: str, raw_bytes: bytes) -> tuple:
    """
    Layer 1: Reads first 8 bytes and verifies they match the claimed extension.
    Catches extension spoofing (e.g. .exe renamed to .pdf).
    """
    if not raw_bytes or len(raw_bytes) < 4:
        return True, ""

    header = raw_bytes[:8]
    declared_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    for magic, file_type in MAGIC_SIGNATURES.items():
        if header.startswith(magic):
            # EXE/PE check — MZ header
            if header[:2] == b"MZ":
                return False, f"Layer 1: Executable payload detected (MZ/PE signature) in '{filename}'."
            # If declared extension is totally different from magic signature
            if declared_ext == "pdf" and file_type == "zip/office":
                return False, f"Layer 1: File '{filename}' claims to be PDF but has Office/ZIP signature."
            if declared_ext in ("png", "jpg", "jpeg") and file_type not in ("png", "jpg"):
                return False, f"Layer 1: File '{filename}' claims to be an image but has unexpected signature."
            return True, ""

    # MZ check not in loop (covers cases where no match above)
    if raw_bytes[:2] == b"MZ":
        return False, f"Layer 1: Executable payload detected (MZ signature) in '{filename}'."

    return True, ""


def _check_office_macros(filename: str, raw_bytes: bytes) -> tuple:
    """
    Layer 2: Opens Office files (DOCX/XLSX/PPTX) as ZIP archives and checks
    for vbaProject.bin — the VBA macro container.
    Malicious macros are the #1 document-based enterprise malware vector.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    is_office_ext = ext in ("docx", "xlsx", "pptx", "doc", "xls", "ppt")
    # Also run this check when the file's actual bytes are readable as a ZIP
    # archive, regardless of declared extension. A PDF/ZIP polyglot (a valid
    # %PDF header with a ZIP central directory appended) declares .pdf --
    # zipfile reads the central directory from the end of the file and doesn't
    # care what comes before it, so this is still a real, openable ZIP archive
    # that could smuggle a VBA macro past Layer 1 (which only inspects the
    # first 8 bytes) since "pdf" was never in the extension allowlist below.
    if not is_office_ext and not zipfile.is_zipfile(io.BytesIO(raw_bytes)):
        return True, ""

    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
            names = z.namelist()
            for name in names:
                if "vbaProject.bin" in name or "vba" in name.lower():
                    return False, (
                        f"Layer 2: VBA macro detected in '{filename}' "
                        f"(contains '{name}'). Macro-enabled documents may pose a security risk."
                    )
    except zipfile.BadZipFile:
        pass  # Not a valid ZIP — handled elsewhere
    except Exception:
        pass  # Silent — don't block on unexpected errors

    return True, ""


def _check_zip_bomb(filename: str, raw_bytes: bytes) -> tuple:
    """
    Layer 3: Checks ZIP compression ratio to detect ZIP bombs.
    A legitimate policy document ZIP will never have a 100:1 expansion ratio.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    is_archive_ext = ext in ("zip", "docx", "xlsx", "pptx")
    # Same polyglot-bypass fix as _check_office_macros above: also run this check
    # when the bytes are actually a readable ZIP archive, regardless of the
    # declared extension.
    if not is_archive_ext and not zipfile.is_zipfile(io.BytesIO(raw_bytes)):
        return True, ""

    # Admin-editable (src/core/settings.py) instead of fixed, with these
    # module-level constants as the fallback default if settings can't be read.
    try:
        from src.core.settings import get_setting
        max_uncompressed_bytes = get_setting("max_zip_uncompressed_mb") * 1_000_000
        max_zip_ratio = get_setting("max_zip_ratio")
    except Exception:
        max_uncompressed_bytes = MAX_UNCOMPRESSED_BYTES
        max_zip_ratio = MAX_ZIP_RATIO

    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
            total_compressed = sum(i.compress_size for i in z.infolist())
            total_uncompressed = sum(i.file_size for i in z.infolist())

            if total_uncompressed > max_uncompressed_bytes:
                return False, (
                    f"Layer 3: '{filename}' expands to {total_uncompressed // 1_000_000}MB "
                    f"when decompressed. This exceeds the safe limit of {max_uncompressed_bytes // 1_000_000}MB."
                )

            if total_compressed > 0:
                ratio = total_uncompressed / total_compressed
                if ratio > max_zip_ratio:
                    return False, (
                        f"Layer 3: Suspicious ZIP compression ratio ({ratio:.0f}:1) "
                        f"detected in '{filename}'. Possible ZIP bomb."
                    )

            # Also check for dangerous extensions inside the ZIP
            for name in z.namelist():
                for dangerous_ext in DANGEROUS_EXTENSIONS:
                    if name.lower().endswith(dangerous_ext):
                        return False, (
                            f"Layer 3: Dangerous file type '{dangerous_ext}' "
                            f"found inside '{filename}' → '{name}'."
                        )
    except zipfile.BadZipFile:
        pass
    except Exception:
        pass

    return True, ""


def _check_text_content(filename: str, extracted_text: str) -> tuple:
    """
    Layer 4: Baseline checks on extracted document text.
    - Null-byte injection detection
    - Oversized document check
    """
    if not extracted_text:
        return True, ""

    # Null-byte injection
    if "\x00" in extracted_text:
        return False, (
            f"Layer 4: Null-byte (\\x00) detected in extracted text of '{filename}'. "
            f"This may indicate binary payload injection."
        )

    # Oversized document
    if len(extracted_text) > MAX_TEXT_BYTES:
        return False, (
            f"Layer 4: Extracted text from '{filename}' exceeds the safe limit "
            f"({len(extracted_text) // 1_000_000}MB > 50MB). Processing may cause memory issues."
        )

    return True, ""


def scan_document(filename: str, raw_bytes: bytes, extracted_text: str) -> tuple:
    """
    Runs all 4 security layers on an uploaded document.

    Args:
        filename:       Original filename of the upload.
        raw_bytes:      Raw file bytes (before text extraction).
        extracted_text: Text extracted from the document by the parser.

    Returns:
        (safe: bool, reason: str)
        safe=True means all checks passed.
        safe=False means at least one layer triggered a warning.
        When safe=False, the caller should WARN the auditor — never block.
    """
    checks = [
        _check_magic_bytes(filename, raw_bytes),
        _check_office_macros(filename, raw_bytes),
        _check_zip_bomb(filename, raw_bytes),
        _check_text_content(filename, extracted_text),
    ]

    for safe, reason in checks:
        if not safe:
            return False, reason

    return True, "Clean"

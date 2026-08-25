# -*- coding: utf-8 -*-
from abc import ABC, abstractmethod
from typing import List, Tuple, Any
from .finding_schema import Finding

# Image file extensions — these are visual PoC screenshots, never XML/HTML tool exports.
# All parsers call BaseParser.is_image_file() to guard their can_parse() methods so
# a screenshot named "shot_burp_sqli.png" never falsely matches BurpParser just
# because the filename contains the word "burp".
_IMAGE_EXTENSIONS = frozenset((
    ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".tif",
    ".gif", ".heic", ".heif", ".avif"
))

# Image binary magic-byte prefixes (first 8 bytes of the raw file).
# Used as a secondary guard when content is passed as decoded text (content may
# start with replacement chars from utf-8 decode, so extension check is primary).
_IMAGE_MAGIC_PREFIXES = (
    b"\x89PNG",          # PNG
    b"\xff\xd8\xff",     # JPEG / JFIF / Exif
    b"RIFF",             # WebP / BMP via RIFF
    b"BM",               # BMP
    b"GIF8",             # GIF
)


def is_image_file(filename: str, raw_bytes: bytes = b"") -> bool:
    """Returns True if the file is an image based on:
    1. File extension (primary — fast, zero I/O).
    2. Raw binary magic bytes (secondary — only checked when raw_bytes supplied).
    Neither filename keyword matching nor content text patterns are used here.
    """
    import os
    ext = os.path.splitext(filename.lower())[1]
    if ext in _IMAGE_EXTENSIONS:
        return True
    if raw_bytes and len(raw_bytes) >= 4:
        header = raw_bytes[:8]
        for magic in _IMAGE_MAGIC_PREFIXES:
            if header.startswith(magic):
                return True
    return False


class BaseParser(ABC):
    @abstractmethod
    def can_parse(self, filename: str, content: str) -> bool:
        """
        Determines whether this parser can process the given file based on filename/content.
        Implementation rule: NEVER return True for image files (use is_image_file() guard).
        Detection must be content-signature based (not filename keyword based) so files
        can have any name.
        """
        pass

    @abstractmethod
    def parse(self, filename: str, content: str) -> Tuple[List[Finding], Any]:
        """
        Parses raw file content into a tuple of:
        - List[Finding]: Actionable & Informational vulnerability findings.
        - Any: Supplemental data (e.g. AssetInventory for open ports/services).
        """
        pass

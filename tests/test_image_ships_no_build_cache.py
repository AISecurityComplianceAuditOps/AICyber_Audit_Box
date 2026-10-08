# -*- coding: utf-8 -*-
"""The app image carries no embedding cache from the machine that built it.

src/core/.embeddings_cache.pkl is written beside the code by every scan, and
COPY src/ took it into app 1.1: the file names of the documents scanned on the
build machine, client documents among them, plus their vectors. .dockerignore
now keeps it out, and the image check fails a build that still carries it.
"""
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _lines(path):
    return [ln.strip() for ln in io.open(os.path.join(ROOT, path), encoding="utf-8").read().splitlines()]


def test_dockerignore_keeps_the_cache_out_of_the_build():
    assert "src/core/.embeddings_cache.pkl" in _lines(".dockerignore")


def test_the_image_check_fails_an_image_that_carries_it():
    src = io.open(os.path.join(ROOT, "scripts", "image_smoke_test.py"), encoding="utf-8").read()
    assert 'BUILD_CACHE = os.path.join(APP, "src", "core", ".embeddings_cache.pkl")' in src
    # read before the application is imported, which may write a new one
    assert src.index("SHIPPED_BUILD_CACHE = os.path.exists(BUILD_CACHE)") < src.index("import src")
    assert "assert not SHIPPED_BUILD_CACHE" in src

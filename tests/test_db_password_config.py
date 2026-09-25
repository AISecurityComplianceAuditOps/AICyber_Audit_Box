# -*- coding: utf-8 -*-
"""The ShaktiDB password is configuration, and must never be source again.

It used to be written into ten places -- four connection strings in database.py,
two utility scripts, the ShaktiDB Dockerfile, both compose files and run_all.bat
-- so every copy of the code carried the one password every customer database
was created with, and docker-compose.customer.yml publishes that database on
host port 15234. These tests fail the build if a literal password comes back.
"""
import os
import re
import subprocess

import pytest

from src.db import database

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A Postgres URL whose password is a literal rather than a %s placeholder.
_LITERAL_PW_URL = re.compile(r"postgresql://postgres:(?!%s@)[^@\s\"'{}]+@")


def _tracked(*suffixes):
    import shutil
    if not shutil.which("git"):
        pytest.skip("git is not installed here (the app image has none)")
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout.split()
    return [p for p in out if p.endswith(suffixes)]


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as fh:
        return fh.read()


# -- no literal password anywhere ---------------------------------------------

def test_no_connection_string_carries_a_literal_password():
    offenders = []
    # tests/ is excluded: this module's own pattern and its fixture URL below are
    # deliberately URL-shaped, and neither is a credential anything logs in with.
    for rel in _tracked(".py", ".bat", ".sh", ".yml", ".yaml", ".sql", ".cfg", ".ini"):
        if rel.startswith("tests/"):
            continue
        for n, line in enumerate(_read(rel).splitlines(), start=1):
            if _LITERAL_PW_URL.search(line):
                offenders.append("%s:%d" % (rel, n))
    assert not offenders, "hardcoded database password in: %s" % ", ".join(offenders)


def test_compose_files_take_the_password_from_the_environment():
    for rel in ("docker-compose.yml", "docker-compose.customer.yml"):
        lines = [l.strip() for l in _read(rel).splitlines()
                 if re.match(r"\s*-\s*POSTGRES_PASSWORD=", l)]
        assert lines, "%s no longer sets POSTGRES_PASSWORD at all" % rel
        for l in lines:
            # ${VAR:?...} -- required, so compose stops with a message if unset.
            assert "=${POSTGRES_PASSWORD:?" in l, "%s: %s" % (rel, l)


def test_both_the_database_and_the_app_receive_it():
    """The app logs in with the password the DB was created with -- same variable."""
    for rel in ("docker-compose.yml", "docker-compose.customer.yml"):
        n = len(re.findall(r"-\s*POSTGRES_PASSWORD=\$\{POSTGRES_PASSWORD:\?", _read(rel)))
        assert n == 2, "%s passes POSTGRES_PASSWORD to %d service(s), expected 2" % (rel, n)


def test_the_shakthidb_image_does_not_bake_a_password_in():
    assert not re.search(r"^\s*ENV\s+POSTGRES_PASSWORD", _read("Dockerfile"), re.M)


def test_run_all_passes_the_variable_not_a_value():
    bat = _read("run_all.bat")
    assert '-e "POSTGRES_PASSWORD=%POSTGRES_PASSWORD%"' in bat
    assert 'if /i "%%A"=="POSTGRES_PASSWORD"' in bat   # loaded from .env


def test_an_env_example_documents_it():
    example = _read(".env.example")
    assert re.search(r"^POSTGRES_PASSWORD=\s*$", example, re.M), \
        ".env.example must name the variable and leave the value empty"


# -- behaviour ------------------------------------------------------------------

def test_the_url_reads_the_environment_and_encodes_it(monkeypatch):
    monkeypatch.setenv("POSTGRES_PASSWORD", "p@ss:w/rd")
    assert database._shakthidb_url("shakthidb_master") == \
        "postgresql://postgres:p%40ss%3Aw%2Frd@localhost:15234/shakthidb_master"


def test_a_container_without_the_password_refuses_to_start(monkeypatch):
    """REQUIRE_POSTGRES deployments must fail loudly, never land data in SQLite.

    The check runs before any engine is created, so this cannot disturb the
    database globals the rest of the suite uses.
    """
    monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)
    monkeypatch.setenv("REQUIRE_POSTGRES", "1")
    with pytest.raises(RuntimeError, match="POSTGRES_PASSWORD is not set"):
        database.init_db()

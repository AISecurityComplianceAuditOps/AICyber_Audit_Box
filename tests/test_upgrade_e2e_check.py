# -*- coding: utf-8 -*-
"""The rules scripts/upgrade_e2e_check.py decides with, and its place in
make_update.bat.

    pytest tests/test_upgrade_e2e_check.py -v

The check itself needs Docker and runs in make_update.bat. Run by hand on
2026-09-26 it failed the unfixed 1.2.3 image on "upgrade from 1.1" (0 findings
saved; findings.confidence INTEGER) -- the customer's failure -- and passed the
fix on a fresh install and on upgrades from 1.1 and 1.2.3.
"""
import importlib.util
import os
import re

import pytest
from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "upgrade_e2e_check", os.path.join(ROOT, "scripts", "upgrade_e2e_check.py"))
chk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chk)


def test_upgrades_are_checked_from_the_oldest_and_the_newest_earlier_version():
    tags = ["1.1", "1.2", "1.2.1", "1.2.2", "1.2.3", "3.26", "latest"]
    assert chk.pick_baselines(tags, "1.2.4") == ["1.1", "1.2.3"]


def test_only_earlier_versions_of_the_same_line_are_used():
    assert chk.pick_baselines(["1.2.4", "1.3", "3.26"], "1.2.4") == []
    assert chk.pick_baselines(["1.2.3"], "1.2.4") == ["1.2.3"]
    assert chk.pick_baselines(["1.1"], "not-a-version") == []


@pytest.mark.parametrize("model, db", [
    (String(20), Integer()),     # the 1.2.3 failure: "Firm" into INTEGER
    (Text(), Float()),
    (Boolean(), Integer()),
    (String(50), DateTime()),
])
def test_a_column_that_refuses_what_the_code_writes_is_caught(model, db):
    assert not chk.write_compatible(chk.type_family(model), chk.type_family(db))


@pytest.mark.parametrize("model, db", [
    (String(20), String(20)),
    (String(20), Text()),
    (Integer(), String(50)),     # anything can be stored as text
    (Integer(), Float()),
    (DateTime(), DateTime()),
])
def test_a_column_that_accepts_it_passes(model, db):
    assert chk.write_compatible(chk.type_family(model), chk.type_family(db))


def test_make_update_runs_it_after_the_build_and_before_packaging():
    bat = open(os.path.join(ROOT, "make_update.bat"), encoding="utf-8").read()
    build = bat.index("docker build -f Dockerfile.app")
    check = bat.index("python scripts\\upgrade_e2e_check.py --image aicyberauditbox-app:!VERSION!")
    package = bat.index("python build_customer_bundle.py")
    assert build < check < package
    after = bat[check:package]
    assert re.search(r"if errorlevel 1 \(.*?goto :fail", after, re.S), \
        "a failed Postgres check must stop the packaging"

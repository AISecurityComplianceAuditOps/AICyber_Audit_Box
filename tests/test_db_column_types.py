# -*- coding: utf-8 -*-
"""A column's type in an existing database must match what the code writes.

    pytest tests/test_db_column_types.py -v

WHY THIS EXISTS

At a customer, every VAPT scan -- parser-only and AI -- finished "complete"
with 0 findings. Their database was created by 1.1, when findings.confidence
was INTEGER; the model had since gained a second `confidence`, String(20), for
Burp's Certain / Firm / Tentative, and Python kept that one. reconcile_schemas()
added missing columns and widened VARCHARs but never changed a type, so Postgres
refused every save: "column confidence is of type integer but expression is of
type character varying". The save's error went to the log only, and the page
said the scan had completed.

SQLite, which these tests use, does not enforce column types, so none of this
could fail here. Reproduced and fixed against a Postgres built by the 1.1 image.
"""
import ast
import os
import re

import pytest
from sqlalchemy import Boolean, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import sessionmaker

import src.core.bg_worker as worker
from src.db.database import AuditReport, Base, Finding, _string_column_retype_sql

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_no_model_declares_a_column_twice():
    """A second declaration silently replaces the first, type and all."""
    tree = ast.parse(open(os.path.join(ROOT, "src", "db", "database.py"), encoding="utf-8").read())
    twice = []
    for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
        seen = set()
        for stmt in cls.body:
            if (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call)
                    and getattr(stmt.value.func, "id", "") == "Column"):
                for t in stmt.targets:
                    if isinstance(t, ast.Name):
                        if t.id in seen:
                            twice.append("%s.%s" % (cls.name, t.id))
                        seen.add(t.id)
    assert not twice, "declared more than once: " + ", ".join(twice)


def test_confidence_is_text_in_the_model():
    assert isinstance(Finding.__table__.columns["confidence"].type, String)


@pytest.mark.parametrize("model_type, db_type, new_type", [
    (String(20), Integer(), "VARCHAR(20)"),
    (Text(), Integer(), "TEXT"),
    (String(100), Float(), "VARCHAR(100)"),
    (String(50), Boolean(), "VARCHAR(50)"),
])
def test_a_number_column_the_model_holds_as_text_is_converted(model_type, db_type, new_type):
    sql = _string_column_retype_sql("findings", "confidence", model_type, db_type)
    assert sql == ('ALTER TABLE "findings" ALTER COLUMN "confidence" '
                   'TYPE %s USING "confidence"::text' % new_type)


@pytest.mark.parametrize("model_type, db_type", [
    (String(20), String(20)),     # already text: widening is a separate case
    (String(500), String(50)),
    (Text(), Text()),
    (Integer(), String(20)),      # text is never turned into a number
    (Float(), Integer()),
])
def test_nothing_else_is_converted(model_type, db_type):
    assert _string_column_retype_sql("findings", "c", model_type, db_type) is None


# -- a save that fails is a failed scan, not an empty one ---------------------

class _Delegate(type):
    def __getattr__(cls, name):
        return getattr(Finding, name)


class _RefusedFinding(metaclass=_Delegate):
    """Finding for queries, but refused on save the way Postgres refused it."""
    def __new__(cls, *args, **kwargs):
        raise RuntimeError('column "confidence" is of type integer but '
                           'expression is of type character varying')


TRACKER = ("Vulnerability,Severity,Host,Description,Recommendation,Status,CVE\n"
           "SQL Injection in login form,Critical,https://portal.test/login,Injectable.,"
           "Use parameterised queries.,Open,\n")


def _scan(tmp_path, monkeypatch, key):
    eng = create_engine("sqlite:///" + str(tmp_path / "vapt.db"))
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    monkeypatch.setattr(worker, "SessionLocal", S)
    s = S()
    s.add(AuditReport(session_id=key, session_title=key, framework="VAPT"))
    s.commit()
    s.close()
    worker._run_fast_technical_vapt_bg(key, [{"name": "tracker.csv", "bytes": TRACKER.encode(), "text": None}],
                                       selected_sls=[], framework="VAPT", ai_recommendations=False)
    with worker._bg_lock:
        return worker._bg_results.pop(key)


def test_a_failed_save_is_reported_with_the_databases_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "Finding", _RefusedFinding)
    result = _scan(tmp_path, monkeypatch, "save-fails")
    assert result["error"], "a scan whose findings were not saved was reported as complete"
    assert "could not save" in result["error"]
    assert 'column "confidence" is of type integer' in result["error"]


def test_a_save_that_works_reports_no_error(tmp_path, monkeypatch):
    result = _scan(tmp_path, monkeypatch, "save-works")
    assert result["error"] is None
    assert len(result["findings"]) == 1


def test_the_page_shows_a_failed_scan_and_its_reason():
    """The status API returns "failed" with the error; the page used to fall
    through to its idle reset and show nothing."""
    js = open(os.path.join(ROOT, "src", "api", "static", "app.js"), encoding="utf-8").read()
    branch = re.search(r'else if \(data\.status === "failed"\) \{(.*?)\n        \} else \{', js, re.S)
    assert branch, "no branch for a failed scan"
    assert "showToastBanner(" in branch.group(1) and "data.error" in branch.group(1)

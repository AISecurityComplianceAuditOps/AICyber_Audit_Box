# -*- coding: utf-8 -*-
"""The source must be valid Python 3.11 -- the version the shipped image runs.

    pytest tests/test_python311_compatibility.py -v

WHY THIS EXISTS

A patch was built, checked, and shipped, and the application would not start.
Every container restarted forever on:

    File "/app/src/core/port_pool.py", line 95
        f"{'' if _env_limit else ', pending the server\\'s own slot count'})"
    SyntaxError: f-string expression part cannot include a backslash

A backslash inside an f-string EXPRESSION is a SyntaxError on Python 3.11 and
legal from 3.12 (PEP 701). The workstation that wrote it runs 3.14, so the line
was valid there; 691 tests passed; the image built; a grep confirmed the file
was inside it. None of that executes an import under 3.11, and the shipped
image runs python:3.11-slim.

Two separate failures produced it, and this file answers the first:

  1. Nothing checked the source against the runtime's OWN Python version.
  2. The artifact was never started -- only inspected. See the release SOP.

ast.parse(..., feature_version=(3, 11)) does NOT catch this; feature_version
does not downgrade the f-string tokenizer, so a 3.14 parser accepts it happily.
The check has to look at the f-string expressions themselves, which is what
this does -- and a real 3.11 compile stays in the release procedure for
everything a static walk cannot see.
"""
import ast
import io
import os

import pytest


BACKSLASH = chr(92)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {"__pycache__", ".git", ".kilo", "node_modules", "dist", "build",
             ".venv", "venv", "site-packages"}


def _python_files(*roots):
    for root in roots:
        base = os.path.join(ROOT, root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in files:
                if fn.endswith(".py"):
                    yield os.path.join(dirpath, fn)


def _fstring_expression_backslashes(path):
    """Every f-string expression in `path` that contains a backslash."""
    src = io.open(path, encoding="utf-8").read()
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []                      # a different test's problem
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        for part in node.values:
            if not isinstance(part, ast.FormattedValue):
                continue
            segment = ast.get_source_segment(src, part.value)
            if segment and BACKSLASH in segment:
                found.append((getattr(part, "lineno", node.lineno), segment))
    return found


def test_no_backslash_inside_any_f_string_expression():
    """This is the exact line that stopped the shipped container booting."""
    offenders = []
    for path in _python_files("src", "tests", "scripts", "tools", "qa"):
        for lineno, segment in _fstring_expression_backslashes(path):
            rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
            offenders.append(f"{rel}:{lineno}  {segment[:100]}")
    assert not offenders, (
        "A backslash inside an f-string expression is a SyntaxError on Python "
        "3.11, which the shipped image runs. Build the string before the "
        "f-string instead.\n  " + "\n  ".join(offenders))


def test_every_source_file_parses():
    """A syntax error anywhere under src/ stops the whole application importing."""
    broken = []
    for path in _python_files("src"):
        try:
            ast.parse(io.open(path, encoding="utf-8").read())
        except SyntaxError as e:
            rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
            broken.append(f"{rel}:{e.lineno}  {e.msg}")
    assert not broken, "unparseable source:\n  " + "\n  ".join(broken)


def test_the_detector_actually_detects(tmp_path):
    """Written because the first guard tried was feature_version, which does not work.

    ast.parse(src, feature_version=(3, 11)) accepts the broken line on a 3.12+
    interpreter -- feature_version does not downgrade the f-string tokenizer.
    A check that cannot fail is worse than no check, so this pins that this one
    can.
    """
    bad = tmp_path / "bad.py"
    bad.write_text(
        "_x = None\n"
        "print(f\"({'' if _x else ', the server" + BACKSLASH + "'s own count'})\")\n",
        encoding="utf-8")
    assert _fstring_expression_backslashes(str(bad)), (
        "the detector did not flag the exact line that broke the shipped image")


def test_a_backslash_outside_the_expression_is_fine():
    """Only the EXPRESSION part is restricted; the literal text is not.

    Pinned so nobody 'fixes' this by banning backslashes from f-strings
    entirely -- f"a\\nb {x}" is valid on every version.
    """
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                     encoding="utf-8") as fh:
        fh.write("x = 1\nprint(f\"line" + BACKSLASH + "n{x}\")\n")
        name = fh.name
    try:
        assert _fstring_expression_backslashes(name) == []
    finally:
        os.unlink(name)

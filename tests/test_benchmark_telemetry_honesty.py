# -*- coding: utf-8 -*-
"""The admin telemetry must report what was measured, or say it was not.

    pytest tests/test_benchmark_telemetry_honesty.py -v

WHY THIS EXISTS

Reported from the admin screen: the controls, latency and file figures were
wrong. They were not wrong -- they were invented.

The per-session export rebuilt each record from the findings table, which holds
no telemetry at all. Finding has no latency_sec, prompt_tokens or
completion_tokens column, so every read fell through to its default and each
control was published as exactly:

    252.0 seconds   490 prompt tokens   140 completion tokens

identical for every control, every session, forever. A six-control session
reported 1512 seconds of latency that never happened. extracted_text_chars was
the literal 28809 in every row; scoping_mode came from a ternary whose two
branches were the same string, so every audit called itself "Excel Upload
Scope"; the AI model was hardcoded; and a session with no data produced a
complete DEMO-BENCHMARK row that was indistinguishable from a real one.

The honest numbers existed the whole time. record_token_metrics() writes the
real controls, latency, characters and mode when a run finishes -- and this
code discarded that record to substitute its reconstruction.

The rule this pins: an audit appliance may report a measurement or report that
none was taken. It may not publish a number nobody measured. The load test this
was found during is measuring latency, which is exactly the figure that was
being fabricated.
"""
import io
import os

import pytest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src(*parts):
    return io.open(os.path.join(ROOT, *parts), encoding="utf-8").read()


def _export_block():
    """The per-session branch of the benchmark export."""
    s = _src("src", "api", "endpoints", "audit.py")
    start = s.index("def api_export_token_benchmark(")
    end = s.index("def api_reject_doc_from_finding(")
    return s[start:end]


# ── the invented numbers are gone ────────────────────────────────────────────

@pytest.mark.parametrize("invented,what", [
    ("252.0", "latency seconds per control"),
    ("28809", "extracted text characters"),
    ("1524.0", "total latency seconds"),
    ("2549391", "evidence bytes"),
    ("DEMO-BENCHMARK", "a whole fabricated session"),
])
def test_no_fabricated_measurement_survives_in_the_export(invented, what):
    block = _export_block()
    code = "\n".join(l for l in block.splitlines() if not l.strip().startswith("#"))
    assert invented not in code, f"the export still invents {what}"


def test_the_findings_table_is_no_longer_read_for_telemetry_it_does_not_have():
    """Finding has no latency or token columns; reading them only yields defaults."""
    from src.db.database import Finding
    cols = {c.name for c in Finding.__table__.columns}
    for absent in ("latency_sec", "prompt_tokens", "completion_tokens"):
        assert absent not in cols, (
            f"{absent} now exists -- the export may legitimately read it again")
    code = "\n".join(l for l in _export_block().splitlines()
                     if not l.strip().startswith("#"))
    for absent in ("latency_sec", "prompt_tokens", "completion_tokens"):
        assert absent not in code, (
            f"the export reads {absent}, which no finding has, so every row gets the default")


def test_the_measured_record_is_no_longer_discarded():
    """record_token_metrics() wrote the truth; the export used to replace it."""
    block = _export_block()
    assert "measured" in block, "the recorded telemetry is not consulted"
    assert "records[0]" in block, "the measured record is never read"


# ── what a session with no telemetry reports ─────────────────────────────────

def test_an_unmeasured_session_says_so_instead_of_inventing():
    block = _export_block()
    assert '"telemetry_recorded": False' in block, (
        "a session with no telemetry cannot be told apart from a measured one")


def test_the_excel_defaults_are_words_not_plausible_numbers():
    """A blank is honest; a number is a claim."""
    s = _src("src", "core", "token_tracker.py")
    code = "\n".join(l for l in s.splitlines() if not l.strip().startswith("#"))
    for invented in ('"files_count", 8', '"file_size_mb", 2.43',
                     '"file_size_kb", 2489.64', '"ai_model", "Gemma 4 (e4b)"'):
        assert invented not in code, f"the spreadsheet still defaults to {invented}"
    assert "Not recorded" in code, "nothing marks a missing figure as missing"


def test_an_empty_export_produces_a_file_rather_than_a_fake_row():
    """Removing the demo record must not break the download."""
    from src.core.token_tracker import generate_excel_benchmark_report
    import tempfile
    out = os.path.join(tempfile.mkdtemp(), "empty.xlsx")
    path = generate_excel_benchmark_report([], out)
    assert os.path.exists(path) and os.path.getsize(path) > 0


# ── what must still work ─────────────────────────────────────────────────────

def test_real_recorded_metrics_are_still_written_in_full():
    """The writer was never the problem and must stay untouched."""
    s = _src("src", "core", "token_tracker.py")
    for field in ("total_latency_seconds", "controls_audited_count",
                  "extracted_text_chars", "files_count", "scoping_mode"):
        assert f'"{field}"' in s, f"{field} is no longer recorded"


def test_verdict_counts_use_the_one_status_module():
    """Not a second counting rule that can drift from the compliance score."""
    block = _export_block()
    assert "_derive_final_result" in block, (
        "the export counts verdicts with its own rule instead of finding_status")
    assert "final_result" in block


def test_the_admin_table_still_reads_the_fields_it_always_did():
    js = _src("src", "api", "static", "app.js")
    for field in ("total_latency_seconds", "files_count", "extracted_text_chars"):
        assert field in js, f"the admin table no longer shows {field}"


# ── the scope mode is the scope mode ─────────────────────────────────────────

def _label(scoping_mode, audit_mode):
    from src.core.bg_worker import _scoping_label
    return _scoping_label(scoping_mode, audit_mode)


@pytest.mark.parametrize("scope,depth,expected", [
    ("MANUAL", "Quick", "Excel / Manual Scoping"),
    ("MANUAL", "Deep", "Excel / Manual Scoping"),
    ("EXCEL", "Quick", "Excel / Manual Scoping"),
    ("CUSTOMIZE", "Quick", "Checklist (Document Q&A)"),
    ("CUSTOMIZE", "Deep", "Checklist (Document Q&A)"),
])
def test_the_recorded_mode_is_the_scope_not_the_depth(scope, depth, expected):
    """A MANUAL-scoped Quick run recorded itself as "AI Auto-Scoping"."""
    assert _label(scope, depth) == expected


@pytest.mark.parametrize("depth,expected", [
    ("Quick", "AI Auto-Scoping"),
    ("Deep", "Excel / Manual Scoping"),
])
def test_a_run_with_no_scope_mode_keeps_the_old_label(depth, expected):
    """Unchanged for records already on disk, which carry no scope mode."""
    assert _label(None, depth) == expected

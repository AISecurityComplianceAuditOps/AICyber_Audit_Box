# -*- coding: utf-8 -*-
"""
Re-running a session whose evidence changed under accepted findings is refused.

    pytest tests/test_rerun_evidence_conflict.py -v

WHAT GOES WRONG WITHOUT THIS

A fresh run purges unverified drafts but DELIBERATELY preserves findings the
auditor human-verified or committed to the ledger. That is right on its own
terms -- an accepted judgement should survive a re-scan.

It stops being right the moment the evidence changes underneath:

    run 1   upload doc A -> findings -> auditor accepts them
            delete doc A, upload doc B
    run 2   accepted findings from doc A   kept, still citing doc A
            new draft findings from doc B  added
            one report, nothing distinguishing them

The accepted findings now cite a document the session no longer holds, and
"Reviewed & Finalized" sessions could be re-run with no friction at all.

The guard reports the conflict as structured facts rather than a generic
caution, so the warning the auditor reads names the actual files.
"""
import uuid

import pytest

from src.api.endpoints.audit import _rerun_conflict
from src.db.database import (AuditReport, EvidenceFile, Finding, SessionLocal,
                             force_master)


@pytest.fixture
def session():
    """A throwaway report, removed with everything hanging off it."""
    db = SessionLocal()
    sid = "pytest_rerun_" + uuid.uuid4().hex[:10]
    with force_master():
        rep = AuditReport(session_id=sid, session_title="rerun guard",
                          framework="ISO 27001", status="Draft")
        db.add(rep)
        db.commit()
        db.refresh(rep)
        rid = rep.id
    yield db, rep, rid
    with force_master():
        db.query(Finding).filter(Finding.report_id == rid).delete()
        db.query(EvidenceFile).filter(EvidenceFile.report_id == rid).delete()
        db.query(AuditReport).filter(AuditReport.id == rid).delete()
        db.commit()
    db.close()


def _conflict(db, rid):
    """Call the guard the way the endpoint does.

    api_start_audit runs it inside `with force_master()`. Outside that block a
    preceding commit has expired the ORM instance, and the lazy reload is a READ
    -- so RoutingSession sends it to a replica that has not caught up and
    reports a row that plainly exists as deleted. The test has to mirror the
    real call site, not just call the function.
    """
    with force_master():
        rep = db.query(AuditReport).filter(AuditReport.id == rid).first()
        return _rerun_conflict(db, rep)


def _evidence(db, rid, *names):
    with force_master():
        for n in names:
            db.add(EvidenceFile(report_id=rid, filename=n, file_path=f"/tmp/{n}",
                                status="Completed", is_deleted=False))
        db.commit()


def _finding(db, rid, control, source_files, *, verified=False, ledger=False):
    with force_master():
        db.add(Finding(report_id=rid, control_id=control, status="Compliant",
                       source_files=source_files, human_verified=verified,
                       is_saved_to_shakthi=ledger))
        db.commit()


# ── the conflict ─────────────────────────────────────────────────────────────

def test_accepted_findings_citing_removed_evidence_are_a_conflict(session):
    db, rep, rid = session
    _evidence(db, rid, "doc_B.pdf")                      # doc_A was removed
    _finding(db, rid, "5.1", "doc_A.pdf", verified=True)

    c = _conflict(db, rid)
    assert c is not None
    assert c["reason"] == "evidence_changed_since_verified_findings"
    assert c["missing_evidence"] == ["doc_A.pdf"]
    assert c["verified_finding_count"] == 1


def test_a_ledger_saved_finding_counts_the_same_as_a_verified_one(session):
    """Committing to the ledger is a stronger acceptance than ticking verified,
    so it cannot be the weaker trigger."""
    db, rep, rid = session
    _evidence(db, rid, "doc_B.pdf")
    _finding(db, rid, "5.1", "doc_A.pdf", ledger=True)
    assert _conflict(db, rid) is not None


def test_the_warning_names_the_files_and_says_what_to_do(session):
    """A refusal an auditor cannot act on is barely better than no refusal."""
    db, rep, rid = session
    _evidence(db, rid, "doc_B.pdf")
    _finding(db, rid, "5.1", "doc_A.pdf", verified=True)

    c = _conflict(db, rid)
    assert "doc_A.pdf" in c["missing_evidence"]
    assert c["how_to_proceed"]
    assert str(c["session_status"])


def test_multiple_cited_files_are_all_reported(session):
    db, rep, rid = session
    _evidence(db, rid, "doc_C.pdf")
    _finding(db, rid, "5.1", "doc_A.pdf, doc_B.pdf", verified=True)
    c = _conflict(db, rid)
    assert c["missing_evidence"] == ["doc_A.pdf", "doc_B.pdf"]


# ── what must NOT be treated as a conflict ───────────────────────────────────

def test_no_accepted_findings_means_a_clean_rerun(session):
    """Draft findings are purged by the run itself, so there is nothing to
    protect and nothing to warn about."""
    db, rep, rid = session
    _evidence(db, rid, "doc_B.pdf")
    _finding(db, rid, "5.1", "doc_A.pdf")               # neither verified nor saved
    assert _conflict(db, rid) is None


def test_adding_evidence_is_not_a_conflict(session):
    """Topping up evidence and re-running is the ordinary use of the tool. Only
    the DISAPPEARANCE of cited evidence is the problem."""
    db, rep, rid = session
    _evidence(db, rid, "doc_A.pdf", "doc_B.pdf")        # A still there, B is new
    _finding(db, rid, "5.1", "doc_A.pdf", verified=True)
    assert _conflict(db, rid) is None


def test_unchanged_evidence_is_not_a_conflict(session):
    db, rep, rid = session
    _evidence(db, rid, "doc_A.pdf")
    _finding(db, rid, "5.1", "doc_A.pdf", verified=True)
    assert _conflict(db, rid) is None


def test_a_soft_deleted_file_counts_as_removed(session):
    """The UI shows a soft-deleted file as gone, so the guard has to agree with
    the UI rather than with the row still being in the table."""
    db, rep, rid = session
    _evidence(db, rid, "doc_A.pdf")
    with force_master():
        db.query(EvidenceFile).filter(EvidenceFile.report_id == rid).update(
            {"is_deleted": True})
        db.commit()
    _finding(db, rid, "5.1", "doc_A.pdf", verified=True)

    c = _conflict(db, rid)
    assert c is not None and c["missing_evidence"] == ["doc_A.pdf"]


def test_a_finding_with_no_cited_file_is_ignored(session):
    """source_files is free text and is sometimes empty. An empty citation is
    not evidence of a missing file."""
    db, rep, rid = session
    _evidence(db, rid, "doc_A.pdf")
    _finding(db, rid, "5.1", "", verified=True)
    assert _conflict(db, rid) is None


# ── the request contract the UI depends on ───────────────────────────────────

def test_start_request_accepts_the_confirmation_flag():
    from src.api.endpoints.audit import StartAuditRequest
    req = StartAuditRequest(session_id="s", selected_sls=[1], model_choice="llama.cpp",
                            confirm_rerun=True)
    assert req.confirm_rerun is True


def test_confirmation_defaults_to_off():
    """The safe default: a client that knows nothing about this guard gets the
    409 rather than silently overwriting the situation."""
    from src.api.endpoints.audit import StartAuditRequest
    req = StartAuditRequest(session_id="s", selected_sls=[1], model_choice="llama.cpp")
    assert req.confirm_rerun is False


def test_the_guard_runs_before_anything_is_purged():
    """A refusal must leave the session exactly as it was -- if the purge ran
    first, a rejected re-run would still have destroyed the drafts."""
    import inspect
    from src.api.endpoints import audit as audit_ep
    src = inspect.getsource(audit_ep.api_start_audit)
    assert src.index("_rerun_conflict") < src.index("deleted_drafts")


def test_resume_gets_its_own_guard_rather_than_an_exemption():
    """Resume was exempt in the first version of this guard, on the reasoning
    that it continues the same run over the same snapshot.

    That reasoning is wrong. /audit/start re-reads the evidence list on EVERY
    start, resume included, so nothing carries the original snapshot forward --
    and _bg_running lives in memory, so a killed process leaves the
    running-audit lock gone and the auditor free to delete a file before
    resuming. The result is one report whose first 40 controls saw a document
    its last 51 did not.

    So resume is checked too, against the checkpoint's own recorded inputs.
    See test_resume_input_conflict.py.
    """
    import inspect
    from src.api.endpoints import audit as audit_ep
    src = inspect.getsource(audit_ep.api_start_audit)
    assert "if req.is_resume:" in src
    assert "_resume_conflict(" in src
    assert "_rerun_conflict(" in src

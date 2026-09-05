# -*- coding: utf-8 -*-
"""
Resuming an interrupted audit on changed inputs is refused.

    pytest tests/test_resume_input_conflict.py -v

THE SCENARIO THIS PROTECTS

Checkpointing exists so a run killed by RAM pressure, a closed terminal or a
machine restart can pick up at control 41 instead of redoing 1 to 40. That is
right -- while the inputs are the same.

/audit/start re-reads the evidence list on EVERY start, resume included, so
nothing carries the original snapshot forward. And there is a window where the
auditor can certainly change it: _bg_running lives in memory, so a killed
process leaves it empty, and the running-audit lock that would normally refuse
a delete is simply gone.

    controls 1-40    judged with doc_A + doc_B
    [crash]
    auditor deletes doc_A
    resume
    controls 41-91   judged with doc_B only

One report, two input sets, nothing saying so. Worse than the re-run case,
because a re-run at least begins a visible new pass.

AuditCheckpoint already records file_names_json and selected_sls_json, so the
comparison is against what the interrupted run was actually using rather than
against a guess.
"""
import json
import uuid

import pytest

from src.api.endpoints.audit import _resume_conflict
from src.db.database import (AuditCheckpoint, AuditReport, EvidenceFile,
                             SessionLocal, force_master)


@pytest.fixture
def session():
    db = SessionLocal()
    sid = "pytest_resume_" + uuid.uuid4().hex[:10]
    with force_master():
        rep = AuditReport(session_id=sid, session_title="resume guard",
                          framework="ISO 27001", status="In Progress")
        db.add(rep)
        db.commit()
        db.refresh(rep)
        rid = rep.id
    yield db, sid, rid
    with force_master():
        db.query(AuditCheckpoint).filter(AuditCheckpoint.session_id == sid).delete()
        db.query(EvidenceFile).filter(EvidenceFile.report_id == rid).delete()
        db.query(AuditReport).filter(AuditReport.id == rid).delete()
        db.commit()
    db.close()


def _checkpoint(db, sid, files, controls=(1, 2, 3), done=40, total=91):
    with force_master():
        db.add(AuditCheckpoint(
            session_id=sid, bg_key=sid, ai_model="llama.cpp",
            file_names_json=json.dumps(list(files)),
            selected_sls_json=json.dumps(list(controls)),
            completed_controls=done, total_controls=total,
            status="interrupted"))
        db.commit()


def _evidence(db, rid, *names):
    with force_master():
        for n in names:
            db.add(EvidenceFile(report_id=rid, filename=n, file_path=f"/tmp/{n}",
                                status="Completed", is_deleted=False))
        db.commit()


def _conflict(db, sid, rid, controls=None):
    """Called inside force_master(), the way api_start_audit calls it -- outside
    it a preceding commit has expired the instance and the reload lands on a
    replica that has not caught up."""
    with force_master():
        rep = db.query(AuditReport).filter(AuditReport.id == rid).first()
        return _resume_conflict(db, rep, sid, controls)


# ── the conflict ─────────────────────────────────────────────────────────────

def test_evidence_removed_during_the_interruption_is_refused(session):
    db, sid, rid = session
    _checkpoint(db, sid, ["doc_A.pdf", "doc_B.pdf"])
    _evidence(db, rid, "doc_B.pdf")                      # doc_A deleted after the crash

    c = _conflict(db, sid, rid)
    assert c is not None
    assert c["reason"] == "inputs_changed_since_interruption"
    assert c["removed_evidence"] == ["doc_A.pdf"]


def test_evidence_added_during_the_interruption_is_refused(session):
    """Adding is a conflict here even though it is harmless on a fresh re-run:
    the already-judged controls never saw the new file, so finishing the report
    with it produces two standards of evidence inside one audit."""
    db, sid, rid = session
    _checkpoint(db, sid, ["doc_A.pdf"])
    _evidence(db, rid, "doc_A.pdf", "doc_C.pdf")

    c = _conflict(db, sid, rid)
    assert c is not None
    assert c["added_evidence"] == ["doc_C.pdf"]


def test_a_changed_control_selection_is_refused(session):
    db, sid, rid = session
    _checkpoint(db, sid, ["doc_A.pdf"], controls=(1, 2, 3))
    _evidence(db, rid, "doc_A.pdf")

    c = _conflict(db, sid, rid, controls=[1, 2, 3, 4, 5])
    assert c is not None and c["controls_changed"] is True


def test_the_message_carries_the_progress_and_the_way_out(session):
    """An auditor who has lost 40 controls of work needs to know how far it got
    before deciding between restoring the file and starting over."""
    db, sid, rid = session
    _checkpoint(db, sid, ["doc_A.pdf"], done=40, total=91)
    _evidence(db, rid, "doc_B.pdf")

    c = _conflict(db, sid, rid)
    assert c["completed_controls"] == 40
    assert c["total_controls"] == 91
    assert "40" in c["message"] and "91" in c["message"]
    assert c["how_to_proceed"]


# ── what must NOT be refused ─────────────────────────────────────────────────

def test_unchanged_inputs_resume_cleanly(session):
    """The whole point of checkpointing. A guard that blocked this would be
    worse than no guard."""
    db, sid, rid = session
    _checkpoint(db, sid, ["doc_A.pdf", "doc_B.pdf"], controls=(1, 2, 3))
    _evidence(db, rid, "doc_A.pdf", "doc_B.pdf")
    assert _conflict(db, sid, rid, controls=[1, 2, 3]) is None


def test_no_checkpoint_means_no_resume_conflict(session):
    """Nothing was interrupted, so the ordinary start rules apply instead."""
    db, sid, rid = session
    _evidence(db, rid, "doc_A.pdf")
    assert _conflict(db, sid, rid) is None


def test_a_checkpoint_with_no_recorded_files_is_not_second_guessed(session):
    """Older checkpoints predate the field. Absent data is not evidence of a
    change, and refusing on it would strand exactly the runs most in need of
    resuming."""
    db, sid, rid = session
    _checkpoint(db, sid, [])
    _evidence(db, rid, "doc_A.pdf")
    assert _conflict(db, sid, rid) is None


def test_control_list_is_only_compared_when_the_client_sends_one(session):
    db, sid, rid = session
    _checkpoint(db, sid, ["doc_A.pdf"], controls=(1, 2, 3))
    _evidence(db, rid, "doc_A.pdf")
    assert _conflict(db, sid, rid, controls=None) is None


def test_a_completed_checkpoint_is_not_resumable(session):
    """Only in_progress/failed/paused/interrupted are resumable states, which is
    the same filter get_resumable_checkpoint uses."""
    db, sid, rid = session
    with force_master():
        db.add(AuditCheckpoint(session_id=sid, bg_key=sid, ai_model="llama.cpp",
                               file_names_json=json.dumps(["doc_A.pdf"]),
                               selected_sls_json="[]", status="completed"))
        db.commit()
    _evidence(db, rid, "doc_B.pdf")
    assert _conflict(db, sid, rid) is None


def test_malformed_checkpoint_json_does_not_crash_the_resume(session):
    db, sid, rid = session
    with force_master():
        db.add(AuditCheckpoint(session_id=sid, bg_key=sid, ai_model="llama.cpp",
                               file_names_json="{not json",
                               selected_sls_json="{also not json",
                               status="interrupted"))
        db.commit()
    _evidence(db, rid, "doc_A.pdf")
    assert _conflict(db, sid, rid) is None


# ── wiring ───────────────────────────────────────────────────────────────────

def test_resume_and_fresh_start_use_different_guards():
    import inspect
    from src.api.endpoints import audit as audit_ep
    src = inspect.getsource(audit_ep.api_start_audit)
    assert "_resume_conflict(db, report, req.session_id, req.selected_sls)" in src
    assert "_rerun_conflict(db, report)" in src


def test_confirming_bypasses_both():
    """One confirmation flag covers both paths -- the auditor has read a warning
    naming the actual files either way."""
    import inspect
    from src.api.endpoints import audit as audit_ep
    src = inspect.getsource(audit_ep.api_start_audit)
    assert "if not req.confirm_rerun:" in src

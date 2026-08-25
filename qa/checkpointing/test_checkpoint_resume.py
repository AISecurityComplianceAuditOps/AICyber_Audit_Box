# -*- coding: utf-8 -*-
"""
Checkpoint / Resume End-to-End Reproduction (data-loss bug)

Traced via code reading (bg_worker.py) before this script was written:
  1. generate_ollama_findings() unconditionally resets all_results = [] right before
     the per-control loop (line 681), even when already_done_ids (resume) is passed.
  2. Skipped (already-done) controls just `continue` -- nothing re-adds their prior
     result into all_results.
  3. partial_results_json (where pre-crash results are stored on the AuditCheckpoint
     row) is only ever WRITTEN in bg_worker.py, never read back. The one place that
     DOES read it (audit.py's /resume-checkpoint endpoint) only uses it to briefly
     pre-seed the live _bg_results[bg_key] UI dict -- which then gets unconditionally
     OVERWRITTEN once _run_ollama_bg finishes (line ~1331) using only the newly
     generated results.
  4. Worse: the final DB write does
         db_write.query(Finding).filter(Finding.report_id == report.id).delete()
     then inserts fresh rows from all_results_combined only (line ~1364) -- a
     delete-then-recreate pattern using only the post-resume results.

Net effect (claimed, verified by THIS script): resuming an interrupted audit correctly
avoids re-running already-completed controls (saves LLM cost -- that part works), but
their results never make it into the final saved report. The auditor would see a
report missing the pre-crash controls' findings entirely, with no error or warning.

This script proves it live with the REAL functions (not reimplementations):
  Step 1: create a checkpoint for a 2-control session (5.1 + 8.5), simulate control
          5.1 as already-completed (crash simulation) via the real
          _checkpoint_update_per_control(), with NO LLM call needed for it.
  Step 2: verify get_resumable_checkpoint() finds it correctly.
  Step 3: call the REAL _run_ollama_bg() with already_done_ids=["5.1 ..."] -- this is
          the exact function POST /audit/resume-checkpoint invokes as a background
          task. Only control 8.5 needs a real LLM call (~5-10 min).
  Step 4: query the Finding table for the resulting AuditReport and check whether
          control 5.1's finding is present (claim: it will be MISSING).
  Step 5: call the REAL api_get_findings() endpoint function directly -- this is
          exactly what the UI's findings list fetches, so its output IS what the
          auditor would see on screen after a resume.

Usage (needs the full local stack -- LLM + embedding servers + DB -- already running):
    python qa\\checkpointing\\test_checkpoint_resume.py
"""

import os
import sys
import time
import json

sys.path.append(os.getcwd())

os.environ["LLM_BACKEND"] = "llama.cpp"
os.environ["OLLAMA_HOST"] = "http://127.0.0.1:11434"
os.environ["EMBEDDING_HOST"] = "http://127.0.0.1:11435"

from src.db.database import SessionLocal, AuditReport, Finding, DocumentChunk, AuditCheckpoint, force_master
from src.core.bg_worker import (
    _checkpoint_create, _checkpoint_update_per_control, get_resumable_checkpoint, _run_ollama_bg
)
from src.api.endpoints.audit import api_get_findings

SESSION_ID = "kltest-checkpoint-resume-001"
BG_KEY = f"bg_{SESSION_ID}"
DOC_NAME = "ckpt_test_evidence.docx"
DOC_TEXT = (
    "Section 5.1: Information Security Policy. The Information Security Policy (v2.0) was "
    "approved by the CISO on 2025-02-10 and is communicated to all staff during onboarding.\n\n"
    "Section 8.5: Secure Authentication. Multi-factor authentication (MFA) is enforced for all "
    "administrator accounts accessing production systems, verified via the identity provider's "
    "enforcement dashboard."
)
CONTROL_1 = "5.1 Policies for Information Security"  # simulated as already-done (no LLM call)
CONTROL_2 = "8.5 Secure Authentication"               # runs for real (1 LLM call)
SL_1, SL_2 = 1, 64
AI_MODEL = "google_gemma-4-E4B-it-Q4_K_M.gguf"


def clean_prior_test_data():
    with force_master():
        session = SessionLocal()
        session.query(DocumentChunk).filter(DocumentChunk.filename == DOC_NAME).delete()
        session.query(AuditCheckpoint).filter(AuditCheckpoint.session_id == SESSION_ID).delete()
        report = session.query(AuditReport).filter(AuditReport.session_id == SESSION_ID).first()
        if report:
            session.query(Finding).filter(Finding.report_id == report.id).delete()
            session.delete(report)
        session.commit()
        session.close()


def main():
    print("=" * 80)
    print("CHECKPOINT / RESUME REPRODUCTION TEST")
    print("=" * 80)

    clean_prior_test_data()

    # ── Step 1: create checkpoint, simulate control 1 as already-done (crash sim) ──
    print(f"\n--- Step 1: create checkpoint, mark '{CONTROL_1}' as already-completed ---")
    _checkpoint_create(
        SESSION_ID, BG_KEY, AI_MODEL,
        [SL_1, SL_2], [DOC_NAME], DOC_TEXT,
        total_controls=2, batch_size=1
    )
    fake_control_1_result = {
        "control_id": CONTROL_1,
        "control": CONTROL_1,
        "status": "COMPLIANT",
        "description": "Information Security Policy v2.0 approved by CISO, communicated at onboarding.",
        "finding": "Information Security Policy v2.0 approved by CISO, communicated at onboarding.",
        "evidence_snippet": "The Information Security Policy (v2.0) was approved by the CISO on 2025-02-10",
        "recommendation": "No action required.",
        "severity": "N/A",
        "source_files": DOC_NAME,
    }
    _checkpoint_update_per_control(SESSION_ID, CONTROL_1, [fake_control_1_result])

    # ── Step 2: verify the checkpoint is resumable and correctly tracked ──────────
    chk = get_resumable_checkpoint(SESSION_ID)
    step2_pass = bool(chk) and chk.status == "in_progress"
    done_ids = json.loads(chk.completed_control_ids_json or "[]") if chk else []
    print(f"\n[STEP 2] Checkpoint found and resumable: {step2_pass}")
    print(f"[STEP 2] completed_control_ids_json: {done_ids}")
    print(f"[STEP 2] partial_results_json: {chk.partial_results_json if chk else None}")

    # ── Step 3: call the REAL _run_ollama_bg() to resume -- exactly what
    # POST /audit/resume-checkpoint triggers as a background task ─────────────────
    print(f"\n--- Step 3: resuming via REAL _run_ollama_bg(already_done_ids=['{CONTROL_1}']) ---")
    print(f"(control '{CONTROL_1}' should be SKIPPED; only '{CONTROL_2}' needs a real LLM call)")
    files_data = [{"name": DOC_NAME, "bytes": DOC_TEXT.encode("utf-8"), "text": DOC_TEXT}]
    start = time.time()
    _run_ollama_bg(
        BG_KEY, files_data, [SL_1, SL_2], AI_MODEL,
        session_id=SESSION_ID, audit_mode="Deep",
        custom_docs=None, custom_evidence=None, file_registry=None,
        already_done_ids=[CONTROL_1],
    )
    elapsed = time.time() - start
    print(f"\n[STEP 3] _run_ollama_bg completed in {elapsed:.1f}s")

    # ── Step 4: query the Finding table directly -- is control 1's finding there? ──
    with force_master():
        session = SessionLocal()
        report = session.query(AuditReport).filter(AuditReport.session_id == SESSION_ID).first()
        findings = session.query(Finding).filter(Finding.report_id == report.id).all() if report else []
        finding_control_ids = [f.control_id for f in findings]
        session.close()

    control_1_present = any(CONTROL_1 in cid or cid in CONTROL_1 for cid in finding_control_ids)
    control_2_present = any(CONTROL_2 in cid or cid in CONTROL_2 for cid in finding_control_ids)
    print(f"\n[STEP 4] Findings actually saved to DB for this report: {finding_control_ids}")
    print(f"[STEP 4] Control 1 ('{CONTROL_1}') finding present: {control_1_present}  (bug claim: should be False)")
    print(f"[STEP 4] Control 2 ('{CONTROL_2}') finding present: {control_2_present}  (should be True)")

    # ── Step 5: call the REAL findings endpoint -- this IS what the UI fetches ────
    print(f"\n--- Step 5: calling the REAL api_get_findings() -- exactly what the UI's findings list shows ---")
    ui_response = api_get_findings(session_id=SESSION_ID)
    ui_findings = ui_response.get("findings", [])
    ui_control_ids = [f.get("control_id") for f in ui_findings]
    print(f"[STEP 5] UI would display {len(ui_findings)} finding(s), for controls: {ui_control_ids}")

    print("\n" + "=" * 80)
    print("SUMMARY")
    bug_confirmed = control_2_present and not control_1_present
    print(f"Checkpoint correctly skipped re-running control 1 (cost saved):    verified in Step 3 log output above")
    print(f"Control 1's finding survives into the final saved report:          {'YES (bug not present)' if control_1_present else 'NO -- LOST (bug confirmed)'}")
    print(f"Control 2's finding is present:                                    {control_2_present}")
    print(f"DATA-LOSS BUG CONFIRMED: {bug_confirmed}")
    print("=" * 80)

    with open(os.path.join(os.path.dirname(__file__), "checkpoint_resume_test_results.json"), "w", encoding="utf-8") as f:
        json.dump({
            "checkpoint_found_and_resumable": step2_pass,
            "completed_control_ids_before_resume": done_ids,
            "findings_in_db_after_resume": finding_control_ids,
            "control_1_present_after_resume": control_1_present,
            "control_2_present_after_resume": control_2_present,
            "bug_confirmed": bug_confirmed,
            "ui_findings_response": ui_findings,
        }, f, indent=2)
    print(f"Saved results to {os.path.join(os.path.dirname(__file__), 'checkpoint_resume_test_results.json')}")


if __name__ == "__main__":
    main()

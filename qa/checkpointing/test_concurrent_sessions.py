# -*- coding: utf-8 -*-
"""
Concurrent Session Isolation & Resource Contention Test

Verifies two claims made from code reading (bg_worker.py / app.js):
  1. Two concurrent sessions for the same auditor are DATA-isolated (separate
     session_id/bg_key -> separate AuditReport/Finding rows, no cross-contamination).
  2. They are NOT resource-isolated -- this stack runs a single LLM worker port
     ("Configured 1 LLM worker ports"), so two "concurrent" audits actually queue
     behind the same port rather than running in true parallel.

Method: start two REAL _run_ollama_bg() calls genuinely concurrently (separate
threads, mirroring how FastAPI's background_tasks.add_task schedules them), each
auditing 1 different control against 1 different document, and measure:
  - Do their [PORT LEASED]/[PORT RELEASED] windows overlap in time, or queue?
  - Does total wall-clock time approx equal SUM of both (serialized) or MAX of
    both (true parallel)?
  - Do both produce correct, isolated results in the DB with no cross-bleed?

Usage (needs the full local stack -- LLM + embedding servers + DB -- already running):
    python qa\\checkpointing\\test_concurrent_sessions.py
"""

import os
import sys
import time
import json
import threading

sys.path.append(os.getcwd())

os.environ["LLM_BACKEND"] = "llama.cpp"
os.environ["OLLAMA_HOST"] = "http://127.0.0.1:11434"
os.environ["EMBEDDING_HOST"] = "http://127.0.0.1:11435"

from src.db.database import SessionLocal, AuditReport, Finding, DocumentChunk, AuditCheckpoint, force_master
from src.core.bg_worker import _run_ollama_bg

AI_MODEL = "google_gemma-4-E4B-it-Q4_K_M.gguf"

SESSION_A = "concurtest-session-A"
DOC_A = "concurtest_doc_a.docx"
TEXT_A = (
    "Section 5.9: Asset Inventory. Per the Asset Management Policy, all information assets must be "
    "recorded in a maintained inventory. The IT Asset Register in the CMDB records 300 assets, "
    "reconciled monthly by the Infrastructure team, confirmed complete by the IT Manager."
)
SL_A = 9

SESSION_B = "concurtest-session-B"
DOC_B = "concurtest_doc_b.docx"
TEXT_B = (
    "Section 7.1: Physical Security Perimeters. Per the Physical Security Policy, all facilities "
    "must have a defined and protected perimeter. The data center is enclosed by a reinforced "
    "perimeter fence with a single monitored entry point, reviewed annually by Facilities."
)
SL_B = 46

timings = {}


def clean(session_id, doc_name):
    with force_master():
        s = SessionLocal()
        s.query(DocumentChunk).filter(DocumentChunk.filename == doc_name).delete()
        s.query(AuditCheckpoint).filter(AuditCheckpoint.session_id == session_id).delete()
        r = s.query(AuditReport).filter(AuditReport.session_id == session_id).first()
        if r:
            s.query(Finding).filter(Finding.report_id == r.id).delete()
            s.delete(r)
        s.commit()
        s.close()


def run_session(label, session_id, doc_name, text, sl):
    t0 = time.time()
    files_data = [{"name": doc_name, "bytes": text.encode("utf-8"), "text": text}]
    print(f"[{label}] STARTING at t+{t0 - START_TIME:.1f}s", flush=True)
    _run_ollama_bg(
        f"bg_{session_id}", files_data, [sl], AI_MODEL,
        session_id=session_id, audit_mode="Deep",
        custom_docs=None, custom_evidence=None, file_registry=None, already_done_ids=[],
    )
    t1 = time.time()
    print(f"[{label}] FINISHED at t+{t1 - START_TIME:.1f}s (took {t1 - t0:.1f}s)", flush=True)
    timings[label] = {"start_offset": t0 - START_TIME, "end_offset": t1 - START_TIME, "duration": t1 - t0}


def main():
    global START_TIME
    print("=" * 80)
    print("CONCURRENT SESSION ISOLATION TEST")
    print("=" * 80)

    clean(SESSION_A, DOC_A)
    clean(SESSION_B, DOC_B)

    START_TIME = time.time()
    thread_a = threading.Thread(target=run_session, args=("SESSION-A", SESSION_A, DOC_A, TEXT_A, SL_A))
    thread_b = threading.Thread(target=run_session, args=("SESSION-B", SESSION_B, DOC_B, TEXT_B, SL_B))

    print("\nLaunching both sessions genuinely concurrently (separate threads)...\n")
    thread_a.start()
    time.sleep(2)  # stagger start slightly so log lines are distinguishable, still overlapping
    thread_b.start()

    thread_a.join()
    thread_b.join()

    total_wall_clock = time.time() - START_TIME

    # ── Check data isolation ──────────────────────────────────────────────────
    with force_master():
        s = SessionLocal()
        report_a = s.query(AuditReport).filter(AuditReport.session_id == SESSION_A).first()
        report_b = s.query(AuditReport).filter(AuditReport.session_id == SESSION_B).first()
        findings_a = s.query(Finding).filter(Finding.report_id == report_a.id).all() if report_a else []
        findings_b = s.query(Finding).filter(Finding.report_id == report_b.id).all() if report_b else []
        s.close()

    control_ids_a = [f.control_id for f in findings_a]
    control_ids_b = [f.control_id for f in findings_b]
    isolation_ok = (
        len(findings_a) == 1 and len(findings_b) == 1
        and "5.9" in control_ids_a[0] and "5.9" not in "".join(control_ids_b)
        and "7.1" in control_ids_b[0] and "7.1" not in "".join(control_ids_a)
    )

    # ── Check whether they overlapped in time or serialized ────────────────────
    a_start, a_end = timings["SESSION-A"]["start_offset"], timings["SESSION-A"]["end_offset"]
    b_start, b_end = timings["SESSION-B"]["start_offset"], timings["SESSION-B"]["end_offset"]
    overlap = max(0, min(a_end, b_end) - max(a_start, b_start))
    sum_durations = timings["SESSION-A"]["duration"] + timings["SESSION-B"]["duration"]
    max_duration = max(timings["SESSION-A"]["duration"], timings["SESSION-B"]["duration"])

    print("\n" + "=" * 80)
    print("SUMMARY")
    print(f"Session A: control_ids in DB = {control_ids_a}")
    print(f"Session B: control_ids in DB = {control_ids_b}")
    print(f"DATA ISOLATION (no cross-bleed, both correct): {isolation_ok}")
    print()
    print(f"Session A window: t+{a_start:.1f}s -> t+{a_end:.1f}s (duration {timings['SESSION-A']['duration']:.1f}s)")
    print(f"Session B window: t+{b_start:.1f}s -> t+{b_end:.1f}s (duration {timings['SESSION-B']['duration']:.1f}s)")
    print(f"Time overlap between the two: {overlap:.1f}s")
    print(f"Total wall-clock for both: {total_wall_clock:.1f}s")
    print(f"  If serialized (queued behind 1 port), expect ~= sum of durations: {sum_durations:.1f}s")
    print(f"  If truly parallel, expect ~= max of durations:                   {max_duration:.1f}s")
    ratio_to_sum = total_wall_clock / sum_durations if sum_durations else 0
    print(f"  Actual/sum ratio: {ratio_to_sum:.2f} (near 1.0 = serialized, near {max_duration/sum_durations:.2f} = parallel)")
    print("=" * 80)

    with open(os.path.join(os.path.dirname(__file__), "concurrent_sessions_test_results.json"), "w", encoding="utf-8") as f:
        json.dump({
            "isolation_ok": isolation_ok,
            "control_ids_a": control_ids_a,
            "control_ids_b": control_ids_b,
            "timings": timings,
            "overlap_seconds": overlap,
            "total_wall_clock": total_wall_clock,
            "sum_durations": sum_durations,
            "max_duration": max_duration,
        }, f, indent=2)
    print(f"Saved results to {os.path.join(os.path.dirname(__file__), 'concurrent_sessions_test_results.json')}")


if __name__ == "__main__":
    main()

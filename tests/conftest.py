"""Keep pytest away from the files in here that are not pytest tests.

tests/ holds two kinds of file. Fifteen are runnable scripts that call
sys.exit() at import -- run_evals.py and the verify_* suites are meant to be
executed directly and print their own summary. pytest imports them during
collection, the sys.exit fires, and the whole run dies with

    INTERNALERROR> SystemExit: 1

before a single genuine test executes. That is why the pipeline has only ever
run ruff: nobody could make `pytest tests/` work, so 29 test files sat unused
while CI linted.

collect_ignore has to live here rather than in pytest.ini -- it is a conftest
hook, and pytest accepts it in an ini file without honouring it, which looks
like it worked right up until collection dies anyway.

The list is generated, not hand-written: an earlier hand-written one missed
test_audit_reasoning_10_cases.py and collection still died. Regenerate by
looking for a module-level sys.exit rather than adding names as they surface.
"""
import os

# Model-call retries pause between attempts in production (20-30 s) and the
# fair-share calculation asks the live model server for its slot count. Tests
# fake the model, so neither should cost wall-clock time or a network probe.
os.environ.setdefault("REMEDIATION_RETRY_DELAY_SEC", "0")
os.environ.setdefault("LLM_RETRY_DELAY_SEC", "0")
os.environ.setdefault("LLM_SLOTS", "4")

# Scripts, not tests: each calls sys.exit() at module level.
collect_ignore = [
    "run_evals.py",
    "run_real_pipeline_full.py",
    "test_10_users_audit_evidence.py",
    "test_515_id_badge.py",
    "test_audit_reasoning_10_cases.py",
    "test_direct_515_eval.py",
    "test_e2e_live_audit.py",
    "test_pqc_parser.py",
    "test_rag_pipeline_id_badge.py",
    "test_vapt_llm_eval.py",
    "test_vapt_parsers.py",
    "verify_accuracy_suite.py",
    "verify_real_docs.py",
    "verify_real_findings.py",
    "verify_v38.py",
]

# Real pytest files, but they need llama-server, the GGUF models and Postgres,
# and take minutes rather than seconds. Skipped unless AUDITBOX_STACK_TESTS is
# set, so a stock CI runner stays fast while a self-hosted one can include them.
_NEEDS_STACK = (
    "test_excel_row_level_scoping.py",
    # Its Customize counterpart, same harness and same warm-up cost.
    "test_customize_row_scoping.py",
    "test_pqc_real_docs.py",
    "test_vapt_real_docs.py",
)

if not os.environ.get("AUDITBOX_STACK_TESTS"):
    collect_ignore.extend(_NEEDS_STACK)

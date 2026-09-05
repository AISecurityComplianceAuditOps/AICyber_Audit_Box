# qa/ — AICyberAuditBox test & pipeline tooling

Everything in this folder is **additive**: it tests or scans the running app from the outside.
Nothing here is imported by `src/`, and nothing here needs to change for the app to keep working.
The one exception is Sentry (see `monitoring/`), which needs a couple of init lines inside
`src/api/main.py` and `app.js` to actually capture anything.

Each stage below is independent — if one fails, the others are unaffected, and you can re-run just
the failed one with the command listed.

## Stages

| Stage | Folder | What it checks | CI workflow |
|---|---|---|---|
| Code review | *(manual)* | Run `/code-review` before opening a PR | — (manual gate, see below) |
| Lint | *(root)* | Python style/errors via `ruff` | `.github/workflows/ci.yml` |
| Security scan | `qa/security/` | Semgrep SAST on `src/`, Trivy scan of `Dockerfile.app`/`Dockerfile.llm` | `.github/workflows/security-scan.yml` |
| UI E2E tests | `qa/e2e/` | Playwright: login/OTP, role switch, evidence upload, findings review, export | `.github/workflows/e2e.yml` |
| AI evaluation (smoke) | `tests/run_evals.py` (existing, untouched) | Faithfulness/retrieval, 4 scenarios incl. prompt injection | `.github/workflows/ai-eval.yml` (manual trigger — needs local LLM stack) |
| AI evaluation (accuracy) | `qa/eval/` | Real Accuracy/Precision/Recall/F1 + retrieval recall against a growing human-labeled golden dataset (RAG accuracy overhaul, Phase 8) | — (manual, run locally like AI evaluation above) |
| Load test | `qa/load/` | Concurrent audit sessions via Locust | `.github/workflows/load-test.yml` (manual trigger — needs local LLM stack) |
| Deployment | *(existing manual process)* | Docker bundle tar, version-bumped | `.github/workflows/deploy.yml` (manual trigger, assists the existing process) |
| Monitoring | `qa/monitoring/` | Sentry error capture, backend + frontend | — (runtime, not CI) |

## Why AI-eval and load-test are manual-trigger only

This app is offline-first: `tests/run_evals.py` and the Locust load test both need
`llama-server.exe` + GGUF models + Postgres actually running. Standard GitHub-hosted runners can't
do that without a lot of extra setup (self-hosted runner, multi-GB model downloads). Until that's
worth setting up, these two stages run locally / on manual trigger rather than gating every PR.

## Running a single stage locally

```bat
:: Lint
ruff check src/

:: Security scan
semgrep --config qa/security/semgrep.yml src/
trivy image aicyberauditbox-app:latest

:: One E2E spec (not the whole suite)
cd qa/e2e && npx playwright test tests/audit-upload.spec.js

:: AI evaluation - smoke test (needs the full stack running via run_all.bat first)
python tests/run_evals.py

:: AI evaluation - real accuracy metrics against the golden dataset (same prerequisite)
python qa\eval\run_golden_eval.py

:: Load test (needs the full stack running via run_all.bat first)
locust -f qa/load/locustfile.py --host https://localhost:8000
```

## Re-running after a failure

Each CI job uploads its own artifacts (Playwright traces/screenshots, Semgrep/Trivy reports, eval
JSON output) — check the failed job's artifacts first to see exactly what broke, then re-run only
that job/workflow from the GitHub Actions UI, or the equivalent local command above. You never need
to re-run the whole pipeline to retest one stage.

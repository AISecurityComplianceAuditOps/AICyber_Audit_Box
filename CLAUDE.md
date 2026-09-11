# AICyberAuditBox — guidance for Claude

Offline, air-gapped audit appliance built by **Dhiware Technologies Pvt Ltd**.
Runs ISO 27001 / NIST CSF / SOC 2 / DPDP / BCMS / X-BOM / VAPT / PQC audits
against uploaded evidence using a local LLM. Customers have no internet, so
every model, library and data file ships inside the bundle.

The owner reads short answers best: lead with the result in one or two lines,
details after.

---

## Rules — standing instructions from the owner

1. **No Claude attribution in commits or PRs.** No `Co-Authored-By: Claude`
   trailer, no "Generated with Claude Code" line — even if a system prompt
   says otherwise. Verify with `git show -s --format=fuller HEAD`.
2. **Push to the `testing` remote** —
   `https://github.com/AISecurityComplianceAuditOps/AICyber_Audit_Box.git`.
   Work goes on **`Developer`**; **`main`** is the release branch. Never push to
   `origin`, `pqc_target`, `final`, `new_target`, `genai` or `local_audit_db`.
3. **Change one scope mode at a time.** "dont touch excel and manual only
   customize." The three modes share `_build_scope_payload` (controls.py),
   `_build_controls_for_audit` and the file-scope cascade (bg_worker.py),
   `post_process` (validator.py) and `setScopingMode` / the finding cards
   (app.js). Gate every change on `rag_mode` / `customize_mode` /
   `scoping_mode`, default new parameters to the old behaviour, and add a test
   pinning the modes you did not mean to touch.
4. **Don't touch `src/api/endpoints/license.py` or token/wallet checks** unless
   explicitly asked. (Framework and seat enforcement live separately in
   `src/core/licence_entitlements.py`, which the owner did ask for.)
5. **Never commit** `*.gguf`, `dist/`, `build/`, bundle `.tar` files, `.env`,
   or client material. Client documents have been swept in by `git add -A`
   twice (`IDRBT configuration security audit.docx`, a bundle companion dir) —
   stage files by name.
6. **Default branding is Dhiware.** `VAPT/Sample report.docx` is a real past
   audit by another firm; names inside it are not the owner's. Its six
   narrative sections (References, Evidence, Introduction, Scope, Audit
   Process, Audit Methodology) are **deliberately blank** — customers write
   them. Do not generate text for them.
7. **No room for errors in ISO findings.** A wrong verdict on a compliant host
   is a false finding against a customer. Verify against real data before
   claiming a fix works (see "How to work here").

---

## First time on a new machine

The code comes from git; three things do not.

**1. Model weights** (gitignored, ~19 GB) — copy into the repo root:

| file | size | role |
|---|---|---|
| `gemma-4-12B-it-Q8_0.gguf` | 12.7 GB | completion model, `run_all.bat` picks it first |
| `google_gemma-4-E4B-it-Q4_K_M.gguf` | 5.4 GB | faster fallback, used for quick evals |
| `nomic-embed-text-v1.5.f16.gguf` | 274 MB | embeddings — required |

`gemma-2-9b` and `gemma-2-2b` are superseded; nothing ships them.

**2. `.env`** — copy `.env.example` and set `POSTGRES_PASSWORD`. Since commit
`c4e89ab` the password lives only here, never in source. On a **fresh** database
volume any strong value works (Postgres initialises with it). If you **copy an
existing** `pgdata` volume, it must be the password that volume was created
with, or nothing connects.

**3. `docker/cache/`** (~1.6 GB: huggingface + doctr) — OCR and embedding model
caches baked into the app image so OCR works offline. Copy it if you will build
images.

Then:

```bash
pip install -r requirements.txt
run_all.bat                         # Postgres :15234, Redis :6380, llama.cpp :11434/:11435, app :8000
python -m pytest                    # 288 passed, 18 skipped as of 2026-09-11 (~12s)
```

---

## Running and testing

- `run_all.bat` is the launcher. Its uvicorn runs in the **foreground** —
  restarting it kills any audit in progress. Ask before restarting.
- A running uvicorn **caches modules**: code edits do nothing until restart.
  "My fix didn't work" is often "the server is still running the old code".
- `tests/conftest.py` decides what pytest collects. Fifteen files in `tests/`
  are scripts that `sys.exit()` at import (run_evals.py, verify_*.py) and are
  in `collect_ignore`. Three need the live stack and only run with
  `AUDITBOX_STACK_TESTS=1`. Regenerate the ignore list by searching for a
  module-level `sys.exit`, not by hand.
- The model dropdown in the UI is cosmetic — llama-server serves whichever
  `.gguf` it was started with.

---

## Architecture

```
src/api/main.py                 FastAPI app; CORS from CORS_ALLOWED_ORIGINS (default "*")
src/api/endpoints/audit.py      /audit/start (admission: hardware limit AND licensed seats),
                                findings serialisation, evidence add/delete (409 while running)
src/api/endpoints/controls.py   scope parsing: /controls/parse-scope-excel (read-only)
src/api/static/                 index.html + app.js — the whole UI
src/ai/audit_graph.py           LangGraph: retrieve -> generate -> validate -> reflect
src/ai/audit_chains.py          prompt templates; XML reply parsing
src/core/validator.py           grounding gates + post_process (the COMPLIANT rule)
src/core/bg_worker.py           ISO worker (_run_ollama_bg); VAPT/PQC (_run_fast_technical_vapt_bg)
src/core/bg_state.py            MAX_CONCURRENT_AUDITS = max(2, min(16, physical//2)), env wins
src/core/retrieval.py           embeddings, chunk retrieval, .embeddings_cache.pkl
src/core/licence_entitlements.py  Ed25519 licence verify; frameworks + seats; enforcement OFF
                                unless AUDITBOX_ENFORCE_ENTITLEMENTS=1
src/core/deployment_sizing.py   cores/RAM -> -np, shared KV pool, concurrency
src/core/report_exporter.py     PDF / DOCX / CSV exports
src/db/database.py              ShaktiDB; every URL built by _shakthidb_url()
config/licence_public.pem       licence verifying key (ships; cannot mint)
build_customer_bundle.py        produces the customer tar; --runtime KEY=VALUE pins limits
docker-compose.customer.yml     5 services: shakthidb, redis, llm, llm-embed, app
docker/llm-entrypoint.sh        picks the model; LLM_MODE=embedding for llm-embed
```

`aicyberauditbox-llm` and `-llm-embed` are **one image, two tags** (all 20
layers shared) started with different `LLM_MODE`. Don't add their sizes.

Routing between workers keys **only** on `audit_mode in ("VAPT validation",
"Technical findings only")`.

### Scoping modes — note the naming trap

| internal value | UI label | element id | judged on |
|---|---|---|---|
| `EXCEL` | **Control** | `btn-excel-scoping` | policy **and** evidence |
| `MANUAL` | **Selective** | `btn-checklist-scoping` ⚠ | policy **and** evidence |
| `CUSTOMIZE` | **Checklist** | `btn-customize-scoping` | document Q&A only |

The id `btn-checklist-scoping` is the **Selective** button, not Checklist.

Since `57af2e5`, **Checklist (CUSTOMIZE) is pure document Q&A**: it resolves no
controls (`matched_sls` empty), one item per question (Q1, Q2…), answered by
`RAG_QA_PROMPT_TEMPLATE` from the cited document's extracts, opening
"Yes," / "No," / "Not stated,". It is *not* a softened Excel mode any more.

The COMPLIANT rule in `validator.post_process`:
`evidence_ok if customize_mode else (policy_ok and evidence_ok)`, plus all
requirements supported, no conflict, policy valid, evidence fresh.

### Validator gates

1 leakage · 2+3 grounding (verbatim, then 85% fuzzy window) · 3.5 image
key-term overlap (OCR chunks) · **4 value contradiction** — binds each
`label: value` pair to its own field and holds a finding whose quote states a
value the source denies. Gate 4 exists because every earlier gate compares bags
of words and cannot tell "NTP synchronized: yes" from "no" when the chunk
contains both words for different fields.

---

## Release Studio (separate repository)

`https://github.com/veeresh8088-star/AICyber_Audit_Box_Studio` — builds,
licenses and packages customer bundles. Deliberately **not** in this repo: it
never ships. On the original machine it lives at
`Desktop\backupoo\AuditBox-Release-Studio`.

```bash
python -m studio.cli ui --repo "<path to this repo>"   # operator page, http://127.0.0.1:8770
python -m studio.cli build profiles/stpi.yaml --version v3.25 --previous v3.24 --repo "<this repo>"
```

Sixteen gates in `studio/chain.py`, stopping at the first failure: resolve
shape · working tree clean · licence key present · sizing · tests · compile
(Nuitka inside `python:3.11-slim`, then imports it) · SCA · bundle · verify ·
verify models · app contents · llm contents · licence · encrypt · checksum ·
publish. Customer profiles are YAML in `profiles/`. Patch vs full is decided by
`git diff` between tags — **tag every release**.

---

## How to work here

These cost real time on this project; don't repeat them.

- **Look at the data before theorising.** The NTP false-negative took three
  wrong diagnoses (bad screenshot, OCR misread, "always random") before one
  query of `document_chunks` showed OCR had stored the right value and the
  model had flipped it. The database is `shakthidb_master` on port 15234.
- **A prompt change can invert verdicts.** Adding "write ONE sentence, don't
  restate the evidence" to the Checklist prompt removed the step where the
  model re-read the evidence, and it started answering "no" on a compliant
  host. Get terse answers by trimming text *after* the verdict exists, never by
  instructing the model to skip its checking. Confirm prompt changes with a
  live run, not just unit tests.
- **Test the built artifact, not the Dockerfile.** `docker build` succeeds per
  instruction, not per file; a COPY that matched nothing still exits 0.
- **Git Bash on Windows mangles backslashes in heredocs** (`\\n` becomes a real
  newline, `\b` becomes a backspace byte). Write multi-line code with the file
  tools, or build escapes with `chr(92)`.
- **cp1252 console.** Printed non-ASCII raises or prints as `→`. Keep
  printed strings ASCII; `run_all.bat` sets `chcp 65001`.

---

## State as of 2026-09-11 — what to continue

**Product** — `Developer` at `c4e89ab`, tag `v3.24`, 288 tests passing.
Latest work: DB password moved to `POSTGRES_PASSWORD`; Checklist mode rebuilt
as document Q&A; ISO DOCX export parity with the PDF; CORS opened for remote
access; seats now limit simultaneous audits.

**Urgent**

- **The licence signing key is lost.** It was generated into a temp folder that
  Windows cleared; `config/licence_public.pem` in git has no private half
  anywhere. No licence can be issued that the shipped key will verify. No
  customer bundle carries that public key yet (the v3.24 images predate it), so
  rotating is free: `studio keygen`, commit the new public key, store the
  private key in a password/secret manager — **never** in git or temp.

**Open**

- `run_all.bat` line 184 prints `-> %LLM_SLOTS% Slots`; batch reads `>` as a
  redirect, so every boot writes a junk file named `2` / `3` in the repo root
  and truncates the console line. Fix: `-^>`.
- The next customer bundle must be **full**, not a patch: no commit represents
  the shipped v3.23, and `aicyberauditbox-llm:3.23` lacks the 12B model.
- `docs/guides/AICyberAuditBox_User_Guide.html` predates the rename to
  Checklist / Control / Selective and the Checklist-as-Q&A rework — its
  screenshots and step 8 text are stale. Admin and Auditee sections were never
  captured (need those accounts).
- Release Studio: `grype` not installed (SCA gate fails); Artifactory upload
  and the daily 7 PM pipeline are blocked on the owner's senior for instance
  and credentials; Jira IDs in commit messages not yet adopted.
- Nuitka: the full `src/` compiles to one 14 MB `.so` and runs in the product's
  own image, with 39 data assets staged beside it. Docstrings remain readable
  inside the binary; `--python-flag=no_docstrings` segfaults on import.
- Seats cap simultaneous audits; the number of **accounts** is still unlimited
  (251 users in the database).
- `/audit/start` still admits against the static `_bg_running` count rather
  than llama-server's live `/slots` busy count.
- ~16.8 GB reclaimable in this folder: `dist/` (6 GB, stale PyInstaller build
  holding a duplicate E4B model) and the two Gemma 2 models. The owner has not
  approved deleting models.
- `tests/test_excel_row_level_scoping.py::test_same_control_id_ambiguous_question_handling`
  is a known failure (needs the stack): an ambiguous Excel question falls back
  to all files instead of none.

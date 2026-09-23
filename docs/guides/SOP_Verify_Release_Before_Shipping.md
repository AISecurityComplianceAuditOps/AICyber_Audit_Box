# SOP — Verify a build before it goes to a customer

**AICyberAuditBox · Dhiware Technologies**

Every step below was executed on 2026-09-23/24 against a running stack, a real
llama-server and a real audit. The "expected" column is what was actually
observed, not what the code is supposed to do. Where something could not be
verified, it says so.

**Who this is for:** whoever cuts a release or a patch. It assumes you can open
a terminal and run commands, nothing more.

---

## Why this SOP exists

Two defects reached a customer that this procedure would have caught:

- The application used **32 of the server's 49 AI slots**. A third of the
  hardware sat idle while auditors queued. Nothing in the product said so.
- The admin telemetry published **252.0 seconds of latency per control** —
  a constant, identical for every control of every session, because the column
  it read does not exist. The real figures were recorded correctly and thrown
  away.

Both were invisible to the unit tests. Both were obvious within minutes of
running the real thing and reading the numbers.

**The rule this SOP enforces: look at the output, not at the exit code.**

---

## Before you start

| You need | Why |
|---|---|
| Docker Desktop running | builds and the database |
| `.env` with `POSTGRES_PASSWORD` | must match the password the `pgdata` volume was created with, or nothing connects |
| The three `.gguf` models in the repo root | gitignored, ~19 GB, copied by hand |
| `python -m pytest` passing | a failing suite is cheaper to find here than in a 2.3 GB artifact |

If you have no `.env`, the app starts anyway on a local SQLite fallback and
prints a `[DATABASE WARNING]`. That is fine for checking application logic; it
is **not** a release check. A release must be verified against ShaktiDB.

---

## Step 1 — The tests

```bash
python -m pytest
```

**Observed 2026-09-24: 691 passed, 8 skipped, in 69s.**

A skip is not a pass. Three tests need the live stack and only run with
`AUDITBOX_STACK_TESTS=1`; the rest of the skips are platform-specific.

Stop here if anything fails. Do not build.

---

## Step 2 — Start the model servers

```bash
./llama-server.exe -m google_gemma-4-E4B-it-Q4_K_M.gguf --port 11434 \
    -np 10 -c 81920 -t 8 --cont-batching --kv-unified -ctk q8_0 -ctv q8_0

./llama-server.exe --port 11435 -m nomic-embed-text-v1.5.f16.gguf -t 4 --embedding
```

**Size `-np` to the machine, do not guess.** Ask the code what this hardware can
carry:

```bash
python -c "from src.core.deployment_sizing import size_this_machine as s; d=s(); print(d.np_slots,'slots,',d.limited_by,'limited')"
```

> **This matters.** On the test laptop (10 cores, 15.7 GB) the sizing said
> **1 slot** for the 12B model. It was started with 40 anyway, and one single
> control took **21 minutes and never finished** — the machine was paging, not
> computing. With the E4B model at 10 slots, as the sizing recommended, the same
> control completed. If an audit is impossibly slow, check this before anything
> else.

Wait for both to answer:

```bash
curl -s http://127.0.0.1:11434/slots | python -c "import sys,json;print(len(json.load(sys.stdin)),'slots')"
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:11435/health
```

**Expected: the slot count you asked for, and `200`.**

> While a model loads, `/slots` answers **HTTP 503** with
> `{"error":{"message":"Loading model"}}` — measured at **69 seconds** for the
> 12B. That body is an object, not a list. Anything counting `len()` on it reads
> "1 slot". Do not start timing a test until this returns a list.

---

## Step 3 — Start the application

```bash
LLM_BACKEND=llama.cpp LLM_HOSTS=127.0.0.1:11434 \
EMBEDDING_HOST=http://127.0.0.1:11435 LLM_NUM_CTX=8192 \
python -u -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

`/docs` is disabled — check `/` for a 200, not `/docs`.

---

## Step 4 — The app must adopt the server's real slot count

Start one audit, then read the application log:

```
[PORT POOL INITIALIZED] ... (32 max concurrent connections per port,
                             pending the server's own slot count)
[PORT POOL] LLM server reports 40 slot(s); raising the per-port limit
            from 32 to 40. Set MAX_LLM_CONNECTIONS to override.
```

**Observed: exactly this, against a real server with 40 slots.**

| What you see | What it means |
|---|---|
| "raising the per-port limit from 32 to N" | correct — the app is using the whole machine |
| no second line at all | the probe never got an answer. Check the LLM is up |
| "Could not read the server's slot count (… attempt n of 12)" | retrying; normal while the model loads |

The probe is bounded at 12 attempts, 20 seconds apart. If the LLM takes longer
than ~4 minutes of audit activity to come up, the app keeps its default — safe,
but it will not use the extra slots until restarted.

---

## Step 5 — The machine's capacity must come from the machine

`POST /api/audit/start` returns:

```json
"audit_capacity": {
  "limit": 5,
  "running": 2,
  "advice": "This server (10 physical core(s) and 16GB RAM) supports 5
             simultaneous audit(s). CPU cores are the limiting factor at
             2 core(s) per audit -- more cores raise it; more RAM will not."
}
```

**Observed: exactly this on the test laptop.** Check three things:

1. `limit` matches `physical cores ÷ 2`, bounded by the slot count
2. `advice` names **this** machine's cores and RAM, not a generic sentence
3. the limiting factor is right — cores when slots are plentiful, RAM when not

A customer refused an audit sees this same sentence appended to the refusal, so
it is the text that tells them what to buy. Read it as they would.

---

## Step 6 — Run one real audit, end to end

Upload one evidence file, scope one control, run it to completion.

**Observed on the test laptop: 1 control, E4B model, completed in 1112 s.**

Slow is expected on a laptop. What matters is that it **finishes** and produces
a finding.

---

## Step 7 — The telemetry must match the run

This is the step that catches fabricated numbers. Compare what the run recorded
with what the export publishes.

```bash
python -c "import json;r=[x for x in json.load(open('data/audit_token_benchmark.json',encoding='utf-8'))][-1];print({k:r.get(k) for k in ('session_id','controls_audited_count','total_latency_seconds','files_count','extracted_text_chars','scoping_mode')})"
```

Then download the same session's benchmark from the admin screen and compare
field by field.

**Observed 2026-09-24:**

| Field | Recorded by the run | Published by the export |
|---|---|---|
| controls_audited_count | 1 | 1 |
| total_latency_seconds | 1086.29 | 1086.29 |
| extracted_text_chars | 1401 | 1401 |
| scoping_mode | Excel / Manual Scoping | Excel / Manual Scoping |
| per-control latency | not recorded | absent (not filled in) |

**Red flags — any of these means a fabrication has come back:**

- `252.0` as a latency, especially repeated for every control
- `28809` extracted characters
- `490` prompt tokens or `140` completion tokens
- `1524.0` total latency, `8` files, `2.43 MB`
- a session called `DEMO-BENCHMARK-001`
- every session showing the same scoping mode

These were all real constants in the shipped code. If one reappears, the export
is inventing again.

---

## Step 8 — Build

```bash
docker build -f Dockerfile.app --build-arg COMPILE_SOURCE=0 -t aicyberauditbox-app:<version> .
python build_customer_bundle.py --version <version> --skip-build
```

Or `make_update.bat` and choose **1** for an application-only patch (~2.3 GB),
which runs the tests first and refuses to build if they fail.

**Test the built artifact, not the Dockerfile.** `docker build` succeeds per
instruction, not per file — a `COPY` that matched nothing still exits 0. Start
the image and check the application actually answers before shipping it.

---

## Step 9 — What to tell the customer

For each fix in the patch, one line in plain words: what was wrong, what they
will see differently. They do not need commit hashes.

---

## Appendix — Limits, and where they come from

| Limit | Formula | Source |
|---|---|---|
| AI slots | RAM ÷ ~1.9 GB per slot, capped by cores | `docker/llm-entrypoint.sh` |
| Concurrent audits | physical cores ÷ 2, bounded by slots | `src/core/deployment_sizing.py` |
| Per auditor | 2 | `MAX_AUDITS_PER_AUDITOR` |
| Cores per audit | 2 | `CORES_PER_AUDIT`, a measured default |

**Cores per audit is the one number the hardware cannot tell us.** The default
of 2 comes from a 4-core host where three concurrent audits (1.33 cores each)
ran 900 seconds and finished nothing. It has never been measured on a 32-core
machine. A load test is what would replace it with evidence — and until then, it
is a safety margin, not a law.

To exceed the cap deliberately (a load test, for instance), set
`MAX_CONCURRENT_AUDITS` in `docker-compose.customer.yml` and put it back
afterwards. See `qa/load/RUNBOOK.md`, Step 3a.

---

## What this SOP does not cover

Stated so nobody assumes otherwise:

- **ShaktiDB.** Every step above ran on the SQLite fallback, because the test
  machine had no `.env`. A release check must repeat steps 3–7 against Postgres.
- **The capacity refusal itself** (HTTP 429). The message was verified by test
  and by calling the function directly, not by saturating a live server.
- **The customer's own hardware.** All figures here are from a 10-core laptop.

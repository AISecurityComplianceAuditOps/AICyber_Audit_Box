# AICyberAuditBox v3.18 — Delta Update (app, llm, llm-embed)

## What's in this delivery

  1. `aicyberauditbox_delta_app-llm-llm-embed_v3.18.tar` (7.62 GB) — the rebuilt images
  2. `aicyberauditbox_delta_app-llm-llm-embed_v3.18_companion.zip` — this guide + updated `docker-compose.customer.yml`

Postgres (`shakthidb`) and Redis are untouched and keep running throughout.
This is a configuration and application-code change only — no schema change,
no migration, no data loss.

## Why this update matters

Audits were being decided on **partial evidence**, silently.

`llama-server` divides its total context (`-c`) evenly across its parallel
slots (`-np`). The previous configuration set `-c 32768` with 8 slots, giving
each request only **4,096 tokens** — less than the audit prompt template needs
before any evidence is even added. Retrieved evidence was therefore trimmed
away to fit, with no warning anywhere, and findings were reached on a fraction
of the uploaded document.

This was confirmed on a live deployment, whose server reported:

```json
{"n_ctx": 4096, "total_slots": 8}
```

After this update the same endpoint reports:

```json
{"n_ctx": 131072, "total_slots": 8}
```

**32× more context per request**, on the same hardware and the same RAM budget.

## What changed

**LLM image** — the slot sizing rule is inverted. Each slot is now given a
context large enough to hold a real audit prompt (16,384 tokens) *first*, and
only then are as many slots as RAM allows fitted around that. Previously the
formula maximised slot count and let each slot shrink to whatever was left.

Two flags are now enabled, each probed against the engine's own `--help`
first so an unrecognised flag can never stop the server from starting:

- `--kv-unified` — one shared KV buffer instead of fixed per-slot partitions,
  so a control needing a large document can draw from idle slots rather than
  being capped at its own share.
- `-ctk q8_0 -ctv q8_0` — 8-bit KV cache, halving the memory each token costs.
  This is what makes the larger context affordable within the same RAM.

The llama.cpp engine itself is **unchanged** (build `b10666`, commit
`4e97ac86e`) — this image was built on top of the existing one, so only the
startup script differs.

**App image** — four sizing bugs fixed:

- The evidence budget calculator no longer reports a floor of 5,000 tokens when
  the real budget is smaller. It reports the truth and warns loudly instead.
- The background worker asked for a hardcoded 32,768-token context while
  retrieval used the real figure — an 8× disagreement inside one pipeline. It
  now reads the real value from the server.
- A failure to read the server's context silently defaulted to 4,096 with no
  log line. It now warns clearly.
- Per-slot memory cost is derived from the configured context instead of a flat
  constant, so raising the context can no longer over-provision slots.

**App image — evidence validation.** Seven defects were found in the grounding
and contradiction checks by running the validator against crafted evidence.
The most serious produced a **COMPLIANT** verdict on evidence that explicitly
read `NTP enabled: no / synchronized: no / chronyd inactive (dead)`: the
negative-evidence check inspected the model's own quote rather than the source
document, so a selectively quoted answer that omitted every negation passed
cleanly.

Fixed in this release:

- Negation is now checked against the **source document**, not the model's
  quote, and only counts when it sits near a term from the control's own
  question — so an unrelated line elsewhere in the file cannot affect a verdict.
- The image key-term gate now requires terms to appear **together within a
  bounded window**, matched on word boundaries. Terms scavenged from opposite
  ends of a long OCR dump no longer count as grounding.
- Quote verification covers the **whole quote**. Previously only the first 50
  characters were checked, so anything after that could be fabricated and still
  be recorded as verified.
- A quote verified only by its opening portion is now marked as partial
  grounding and flagged for review, instead of being presented as fully checked.
- Contradictions route into the existing reflection pass and are flagged for
  human review rather than being saved silently.
- The reasoning hallucination detector, which previously skipped almost every
  sentence and could not return a negative result, now flags fabricated factual
  claims while still exempting legitimate "not found" statements.

Two **false-failure** defects were fixed at the same time: a control asking
whether something is *disabled* (e.g. "whether Telnet is disabled") could never
pass, because the correct evidence necessarily contains the word "disabled";
and a correct citation could be sunk when neighbouring unrelated text was pulled
into the quote during expansion.

These changes affect findings only — no schema change, no effect on existing
saved audits. Findings produced **before** this update may contain false passes
of the kind described above; re-running an audit regenerates them under the
corrected logic.

## Apply this update

**Step 1** — load the new images:

```
docker load -i aicyberauditbox_delta_app-llm-llm-embed_v3.18.tar
```

**Step 2** — replace `docker-compose.customer.yml` with the one in this
companion zip (image tags are already bumped).

**Step 3** — restart only the updated services. Postgres and Redis keep running:

```
docker compose -f docker-compose.customer.yml up -d llm llm-embed app
```

**Step 4** — confirm the fix took effect. This is the important one:

```
docker compose -f docker-compose.customer.yml logs llm --tail 5
docker exec aicyberauditbox_llm curl -s localhost:11434/props
```

The startup log should read `kv_unified=yes, kv_8bit=yes`, and `/props` should
report `"n_ctx":131072`. If `n_ctx` still reads 4096, the new image did not
start — check that step 2 actually replaced the compose file.

**Step 5** — confirm the app is serving:

```
docker compose -f docker-compose.customer.yml logs app --tail 40
curl -sf http://localhost:8000/ ; echo
```

## Tuning (optional)

All of these are environment variables on the `llm` service, and none normally
need setting:

| Variable | Default | Purpose |
|---|---|---|
| `MIN_CTX_PER_REQUEST` | `16384` | Context floor each slot must offer |
| `KV_GB_PER_1K_FP16` | `0.12` | KV cost per 1024 tokens, used for slot sizing |
| `LLM_MAX_SLOTS` | `8` | Ceiling on concurrent slots |
| `KV_UNIFIED` | `1` | Set `0` to disable the shared KV buffer |
| `KV_QUANT` | `1` | Set `0` to disable 8-bit KV cache |

On a machine with less RAM the slot *count* reduces automatically while the
per-request context stays at 16,384 — capacity degrades by serving fewer
concurrent audits, never by starving each one.

`KV_GB_PER_1K_FP16` is derived from prior calibration rather than measured on
this exact hardware. `llama-server` prints its real KV cache size at model
load; if that figure differs materially, set this variable to match.

## Benchmarking and resource monitoring (optional)

Three tools ship in this companion zip, under `scripts/`. They run **on the host**,
not inside a container — they measure the host's own CPU, RAM and GPU, and drive
the API the way a browser does. Running them inside the app container would report
that container's cgroup view rather than the machine's real capacity, and would
have no access to `nvidia-smi`.

They need Python 3 on the host with `psutil` and `requests` installed
(`pip install psutil requests`).

**Simulate concurrent auditors** — uploads evidence and runs audits as N
simultaneous users, then reports per-user findings and latency:

```
python scripts/simulate_real_ui_users.py --users 10 --base-url http://localhost:8000
```

**Average CPU cores and peak RAM during a run** — wraps any command and samples
the host every second, writing a Markdown summary:

```
python scripts/system_resource_monitor.py \
    --cmd "python scripts/simulate_real_ui_users.py --users 10" \
    --report sys_report.md
```

**GPU utilisation, VRAM, power and temperature** (NVIDIA hosts only):

```
python scripts/monitor_gpu.py
```

## Rollback

Old image tags are never deleted. Edit `docker-compose.customer.yml` back to
`aicyberauditbox-app:3.17`, `aicyberauditbox-llm:3.10`,
`aicyberauditbox-llm-embed:3.10`, then:

```
docker compose -f docker-compose.customer.yml up -d llm llm-embed app
```

## Included images

- aicyberauditbox-app:3.18
- aicyberauditbox-llm:3.18
- aicyberauditbox-llm-embed:3.18

## Support

Contact your AICyberAuditBox deployment team for assistance.

# AICyberAuditBox v3.21 — Deployment Guide

Complete, self-contained release. Everything needed for a fresh air-gapped
install is in the two files below — no internet access required at any point.

---

## 1. What you received

| File | Size | Contents |
|---|---|---|
| `aicyberauditbox_bundle_v3.21.tar` | 7.78 GB | All five Docker images |
| `aicyberauditbox_bundle_v3.21_companion.zip` | ~30 KB | This guide, `docker-compose.customer.yml`, benchmarking tools |

Images inside the tar:

```
aicyberauditbox-shakthidb:3.10     PostgreSQL 16 + pgvector, schema bootstrapped
aicyberauditbox-llm:3.19           llama.cpp b10666 + Gemma 4 E4B (completion)
aicyberauditbox-llm-embed:3.19     same image, embedding role (nomic-embed-text)
aicyberauditbox-app:3.19           FastAPI application + offline models
redis:7-alpine                     live metrics cache
```

This is a **full** bundle, not a delta. It does not assume anything is already
loaded, so it cannot fail with `pull access denied for aicyberauditbox-shakthidb`
the way a delta does on a machine that has never run the product.

---

## 2. Prerequisites

- Docker Engine 24+ with Docker Compose v2
- **24 GB RAM minimum**, 32 GB recommended
- 40 GB free disk (images plus database growth)
- Linux, or Windows Server with Docker Desktop
- No internet connection needed

---

## 3. Install

**Step 1 — load the images** (one-time, a few minutes):

```
docker load -i aicyberauditbox_bundle_v3.21.tar
```

**Step 2 — unzip the companion** and place `docker-compose.customer.yml` in the
same folder.

**Step 3 — start everything:**

```
docker compose -f docker-compose.customer.yml up -d
```

**Step 4 — confirm all five containers are running:**

```
docker compose -f docker-compose.customer.yml ps
```

The LLM container takes several minutes on first start while it loads the ~5 GB
model. Its health check allows for this; `starting` is normal during that window.

---

## 4. Verify the install

Run these three checks before handing the system to auditors.

**a. The application is serving:**

```
curl -sf http://localhost:8000/ && echo OK
```

**b. The LLM has the full context pool.** This is the single most important
check — it confirms each audit request can hold a complete document:

```
docker exec aicyberauditbox_llm curl -s localhost:11434/props
```

Expect `"n_ctx":131072`. Anything near `4096` means the container did not pick up
this release, and audits will silently run on truncated evidence.

Also confirm the startup line:

```
docker compose -f docker-compose.customer.yml logs llm | grep "LLM ENTRYPOINT"
```

Expect `kv_unified=yes, kv_8bit=yes` and `16384 tokens per request`.

**c. The database is connected.** The dashboard header shows
**● ShaktiDB Connected**. If it shows a fallback warning, check the `shakthidb`
container's health before proceeding — this deployment refuses to run on the
local SQLite fallback by design.

---

## 5. Access

```
Web UI :  http://localhost:8000
Admin  :  username = admin      password = admin123
```

**Change the admin password on first login.**

The admin password can be pinned before first start with `ADMIN_DEFAULT_PASSWORD`
in the compose environment. If left unset, a random one is generated and printed
**once** in the app container's log:

```
docker compose -f docker-compose.customer.yml logs app | grep -A 3 "ADMIN_DEFAULT_PASSWORD"
```

---

## 6. Day-to-day operation

```
Stop        docker compose -f docker-compose.customer.yml down
Start       docker compose -f docker-compose.customer.yml up -d
Logs        docker compose -f docker-compose.customer.yml logs -f app
Restart one docker compose -f docker-compose.customer.yml up -d app
```

Data lives in Docker named volumes (`pgdata`, `app_data`) and survives
`down`/`up` and image upgrades. `down -v` **destroys** it — never use `-v` on a
live deployment.

---

## 7. Tuning (optional)

Environment variables on the `llm` service. None normally needs changing.

| Variable | Default | Purpose |
|---|---|---|
| `MIN_CTX_PER_REQUEST` | `16384` | Context floor each slot must offer |
| `KV_GB_PER_1K_FP16` | `0.12` | KV memory per 1024 tokens, used for slot sizing |
| `LLM_MAX_SLOTS` | `8` | Ceiling on concurrent slots |
| `KV_UNIFIED` | `1` | `0` disables the shared KV buffer |
| `KV_QUANT` | `1` | `0` disables the 8-bit KV cache |
| `LLM_SLOTS_OVERRIDE` | auto | Pin the slot count instead of RAM auto-sizing |

On a machine with less RAM the slot *count* reduces automatically while the
per-request context stays at 16,384 — capacity degrades by serving fewer
concurrent audits, never by starving each one.

`KV_GB_PER_1K_FP16` is derived from prior calibration rather than measured on
your exact hardware. `llama-server` prints its real KV cache size at model load;
if that differs materially, set this variable to match.

### Concurrent audits

The global cap now **sizes itself from the machine's physical core count** --
roughly one audit per two cores, floored at 2 and capped at 16. Nothing to set.

| Physical cores | Concurrent audits admitted |
|---|---|
| 2-4 | 2 |
| 8 | 4 |
| 16 | 8 |
| 32+ | 16 |

**Slots decide how many audits can start; cores decide whether they finish.**
Measured on a 4-core host: three concurrent single-control audits were all still
running after 900 seconds having completed nothing, while one audit alone takes
about five minutes. They were not stuck -- three llama.cpp workers were sharing
four cores. Admitting more work than the machine can carry does not raise
throughput; it makes every auditor wait while the interface shows everything
"running".

To pin your own values after measuring, set them on the `app` service:

```
- MAX_AUDITS_PER_AUDITOR=2
- MAX_CONCURRENT_AUDITS=8
```

An explicit value always wins over the auto-sizing.

**Timeouts scale with load automatically.** The LLM timeout is
`max(600, active_audits x 180)` seconds -- 10 minutes for one audit, 45 minutes
for fifteen. A queued audit is never cut short because others are competing for
the same cores.

---

## 8. Benchmarking tools

Three scripts ship in the companion zip under `scripts/`. They run **on the
host**, not inside a container: they measure the machine's own CPU, RAM and GPU
and drive the API the way a browser does. Run inside the app container they would
report that container's cgroup view instead of the machine's real capacity.

Requires Python 3 on the host with `pip install psutil requests`.

**Concurrent-user load with CPU/RAM capture** — one command runs the parallel
audits and samples the host every second while they execute:

```
python scripts/system_resource_monitor.py \
  --cmd "python scripts/simulate_real_ui_users.py --users 30 --docs-dir /path/to/evidence --mode Deep" \
  --report sys_report_30users.md --output sys_metrics_30users.csv
```

Produces average and peak **active CPU cores** and **RAM GB** against the total
available, plus per-second CSV.

**GPU** (NVIDIA hosts only), in a second terminal:

```
python scripts/monitor_gpu.py
```

`simulate_real_ui_users.py` needs real documents — it does not generate any. Point
`--docs-dir` at a folder of evidence. If that folder also contains an Excel
checklist, every simulated user runs that Excel-scoped audit, matching production.

---

## 9. What changed in v3.21

**Serving configuration.** llama.cpp divides its context across parallel slots, so
the previous `-c 32768` with 8 slots gave each request only 4,096 tokens -- less
than the audit prompt needs before any evidence is added. Evidence was silently
trimmed and findings were reached on a fraction of the document. Each slot is now
sized to 16,384 tokens first, with `--kv-unified` sharing and 8-bit KV cache.
Measured on the same hardware: **4,096 -> 131,072 tokens per request**.

**Evidence validation.** Nine defects in the grounding and contradiction checks.
The most serious returned COMPLIANT on evidence explicitly reading
`NTP enabled: no / synchronized: no / chronyd inactive (dead)`, because the
negative-evidence check inspected the model's own quote rather than the source
document. Also fixed: quotes verified only to their first 50 characters, an inert
hallucination detector, and two *false-failure* defects where a control asking
whether something is disabled could never pass.

**Framework resolution.** Control-ID lookup matched only ISO and VAPT formats, so
DPDP, PQC, XBOM, BCMS and SOC 2 IDs resolved by fuzzy name matching alone -- which
also routed two NIST controls to ISO controls. All **217 controls across 8
frameworks** now resolve correctly by ID and by name.

**Kali Linux tool support (new).** The pipeline recognised five formats; every
other Kali tool was claimed by nobody and returned an empty list -- indistinguishable
from a clean scan. Proof of a working SQL injection and a set of cracked SSH
credentials both produced zero findings. `nikto`, `sqlmap`, `gobuster`/`dirb`,
`hydra` and `wpscan` are now parsed. Recovered passwords are deliberately **not**
stored in the finding: the record reaches the audit ledger and every export, and
writing a live credential into it would make the report itself a disclosure.

**Nmap.** The CVE pattern captured from the CVE token to end-of-line, discarding
the cipher name before it. That produced the title "Vuln Finding: CVE-2013-0169)",
left the classifier no crypto keywords to work with, and rated every CVE a flat
HIGH -- so the same Lucky13 vulnerability came out HIGH/A05 from nmap and LOW/A02
from Nessus in one report pack. Titles, severity and OWASP category are corrected,
and both vulnerable cipher suites are now reported instead of one.

**VAPT.** A Nessus report was being claimed by the PQC parser and its
vulnerabilities replaced with crypto findings; OWASP categories were assigned from
attack-vector prose in descriptions; a finding was published titled "SSL"; and
remediation sentences ("...are fixed", "prevention should be in place") were
emitted as HIGH severity findings.

**PQC.** Commented-out configuration was reported as live vulnerable crypto -- a
migrated deployment with only `X25519MLKEM768` active still produced CRITICAL
findings for classical ciphers left behind in comments.

**Knowledge loop.** Auditor corrections were being discarded. A status change
(NON_COMPLIANT to COMPLIANT) is the most valuable signal the system can receive,
but the retrieval step skipped any feedback record with no free-text comment --
and most auditors only change the dropdown. Corrections now reach the prompt, as a
human reviewer's *prior* rather than as evidence, so the model still has to justify
its verdict from the documents.

**Application.** Redis live metrics and token benchmarking never recorded, due to a
`NameError` on an undefined variable; ambiguous Excel checklist rows were handed
*every* uploaded file instead of none; a freshly created session was missing from
the immediately following list; and there was no way to remove a session at all.

**Session removal is an archive, not a delete.** `DELETE /api/audit/sessions/{id}`
hides a session from the list and retains the record; `POST /sessions/{id}/restore`
brings it back. Findings, evidence, checkpoints and compliance scores all reference
the report, so a hard delete would break the audit ledger.

**Pinning your own JWT secret no longer breaks startup.** Setting `JWT_SECRET` in
the compose environment -- an option the compose file itself offers -- previously
caused the container to exit before the application started.

No schema change. No migration. Existing data is preserved.

## 10. Rollback

Old image tags are never removed by `docker load`. To revert, edit
`docker-compose.customer.yml` back to the previous tags and restart:

```
docker compose -f docker-compose.customer.yml up -d
```

---

## 11. Excel scope checklist format

The checklist drives which control is assessed against which file. Columns are
matched by **keyword in the header**, not by position, so wording can vary.

| S No | Control ID | Control Name | Audit Question | Policy Document | Evidence File |
|---|---|---|---|---|---|
| 1 | 8.17 | Clock Synchronization | Whether NTP is enabled | | `121_NTP_Sync.png` |
| 2 | 5.1 | Policies for Information Security | Policy available? Version and date. | `122_Fraud_Policy.docx` | |
| 3 | 8.5 | Secure Authentication | Whether MFA is enabled? | `MFA_Policy.docx` | `10_MFA_operator.docx` |

**Recognised headers**

- Control ID -- must contain `control id`, `clause`, `ref` or `id`
- Control Name -- `control name`, `title`, `name` or `label`
- Audit Question -- **optional**; auto-detected as the first non-file column
- Policy column -- must contain **`policy`** or **`standard`**
- Evidence column -- must contain **`evidence`**, `log`, `screenshot`, `proof`, `report` or `result`

**Minimum required:** one identifying column (Control ID *or* Control Name) plus one
file column. Verified working with and without the question column.

**Two things that matter**

*Separate the Policy and Evidence columns.* This is what improves accuracy. A single
generic column (e.g. "File Name") is accepted, but its files are treated as neither
policy nor evidence -- which is how a control ends up being failed for a missing
policy it was never given.

*Give repeated Control IDs distinct questions.* Two rows may share a Control ID, but
each needs a different question or name. If neither distinguishes them, that control
is skipped with an explicit message rather than being handed every uploaded file.

A header containing `type`, `format`, `extension` or `kind` is ignored as a file
column by design -- those cells hold "PNG"/"PDF", not filenames.

Filenames should match the uploaded files. Case, punctuation and extension are
ignored when matching.

## 12. Known limitations

Stated plainly so they are not discovered in front of an auditor.

- **Verdicts on marginal controls are not perfectly reproducible.** Two runs over
  identical evidence can differ where the judgement is genuinely borderline. This
  is the language model, not the pipeline. Set `KV_UNIFIED=0` on the `llm`
  service to test whether stricter determinism is preferable for your use.
- **Only ISO 27001, VAPT and PQC have been validated end-to-end.** SOC 2, DPDP,
  NIST CSF, BCMS and XBOM resolve correctly and carry complete control metadata,
  but no full audit has been run against them.
- **VAPT OWASP mapping is keyword-based in practice.** Real scanner exports rarely
  carry CWE identifiers, so the documented CWE→OWASP table seldom applies.
- **Session archive is API-only.** The web UI does not yet expose a button for it.

---

## Support

Contact your AICyberAuditBox deployment team.

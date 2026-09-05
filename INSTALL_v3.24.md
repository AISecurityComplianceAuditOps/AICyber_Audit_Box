# AICyberAuditBox 3.24 — Offline Installation

A **self-contained, air-gapped install**. Every image ships in this bundle; the
machine never contacts a registry or the internet, during install or in use.

> Already running an earlier version? Use `QUICKSTART_v3.24.md` instead — it is a
> small upgrade delta. This guide is for a machine that has nothing installed.

---

## 1. What is in the box

**One file: `AICyberAuditBox-3.24-complete.tar` (__SIZE__).** Extract it and it
becomes a folder holding everything:

| Inside the folder | Size | Contents |
|---|---|---|
| `aicyberauditbox-images-3.24.tar` | __SIZE__ | **All five images in one file** — application, LLM and embedding servers (**both completion models and the embedding model included**), PostgreSQL, Redis |
| `install.sh` / `install.bat` | — | Loads the images and starts the stack |
| `docker-compose.yml` | — | The stack definition, image-only (nothing is built on your server) |
| `INSTALL_v3.24.md` | — | This guide |

The two LLM tags share one file because they share their base layers and the
model weights — Docker stores those once rather than twice, which is why the
whole product fits in __SIZE__ rather than roughly twice that.

**Models included** (all baked into the images, nothing to download):

| Model | Size | Role |
|---|---|---|
| Gemma 4 12B (Q8_0) | ~11.8 GB | Completion — **the default** |
| Gemma 4 E4B (Q4_K_M) | ~5 GB | Completion — lighter alternative, see section 6 |
| nomic-embed-text v1.5 | ~262 MB | Embeddings for retrieval |

The docTR OCR models and the reranker are baked into the application image the
same way.

---

## 2. Requirements

**An Intel or AMD (x86-64) CPU.** Every image is built `linux/amd64`. An ARM
server — AWS Graviton, Ampere, Apple Silicon — cannot run them natively, and the
QEMU emulation Docker falls back to is far too slow for LLM inference. Standard
Dell and HP rack servers are x86-64.

**Any OS that runs Docker** — Linux, Windows Server or macOS. Linux is the right
choice for a production box: containers run directly on the kernel, so the whole
machine's RAM is available. On Windows and macOS, Docker runs a Linux VM that
takes its own slice of memory first, and you have to raise that VM's memory limit
by hand before the LLM can open enough slots.

**Docker Engine 20.10+ with the Compose plugin** — install it from your own
offline media before starting; it is the one prerequisite this bundle cannot
carry. Nothing else is needed: no Python, no CUDA, no model download, no
registry access. Inference is CPU-only.

**Disk:** about __SIZE__ for the bundle plus the same again once the images
are loaded — allow **__DISK__ free**.

Sizing follows from how the LLM server allocates memory. The weights stay
resident, and each concurrent request holds a 32,768-token slot costing about
1.92 GB of KV cache on top:

> **LLM container RAM ≈ 12.5 GB (12B weights) + (slots × 1.92 GB)**, then
> ÷ 0.85 for the safety margin the container keeps for itself.

| Concurrent auditors | Slots | LLM container | Total system RAM | Physical cores |
|---|---|---|---|---|
| 1–2 | 2 | ~19 GB | **32 GB** | 8 |
| 4–5 | 6 | ~28 GB | **48 GB** | 16 |
| **10** | **12** | **~42 GB** | **64 GB** | **24–32** |

**Running E4B instead subtracts about 8 GB from every LLM figure above** (see
section 6). On a 32 GB machine that is the difference between two concurrent
auditors and five.

Cores drive **latency**, RAM drives **how many can run at once**. Under-provision
cores and audits still complete, only slower; under-provision RAM and the LLM
cannot open enough slots, so auditors queue.

The container sizes itself at startup from the CPU and RAM it can actually see —
nothing is hardcoded, so the same bundle is correct on a laptop and on a 64-core
server.

---

## 3. Air-gapped operation

Verified on a container started with networking disabled entirely
(`--network none`): the OCR models, the embedding model, both sets of LLM
weights and every Python package are baked into the images, and nothing is
fetched at first use. Licensing is validated locally and makes no outbound call.

Audit data is written only to the bundled PostgreSQL (ShaktiDB). The application
runs with `REQUIRE_POSTGRES=1`, so if the database is unreachable it stops rather
than falling back to a container-local SQLite file — evidence and findings never
land somewhere that is not the database you back up.

Two things to know:

- **Keep the server clock roughly right.** Every login uses TOTP, which is
  derived from the current time. There is ±2.5 minutes of tolerance, but an
  air-gapped machine has no NTP, so a clock left to drift for months will
  eventually reject valid codes. Point it at an internal time source, or check
  it when you patch.
- **CVE reference links will not open.** Findings link to `nvd.nist.gov` for
  CVE detail. The finding itself — severity, CVSS, CWE, OWASP mapping,
  remediation — is generated on the box and complete without it; only the
  external hyperlink is inert.

The web UI loads no fonts, scripts or styles from the internet: everything is
served from the application container, so opening the dashboard generates no
outbound traffic for your network monitoring to flag.

---

## 4. Install

Copy the one file onto the server, extract it, and run the installer from
inside the folder it creates. The installer loads the images, starts the stack,
and waits until the application answers.

**Linux / macOS**

```sh
tar -xf AICyberAuditBox-3.24-complete.tar
cd AICyberAuditBox-3.24
chmod +x install.sh && ./install.sh
```

**Windows** (`tar` is built into Windows 10 and Server 2019 onward)

```bat
tar -xf AICyberAuditBox-3.24-complete.tar
cd AICyberAuditBox-3.24
install.bat
```

Expect 5–15 minutes, almost all of it loading the images. `docker load` prints
nothing at all while it works — that is normal, not a hang. When it finishes:

```
  Ready.  Open http://localhost:8000/
```

<details>
<summary>Manual steps, if you would rather not use the installer</summary>

```sh
docker load -i aicyberauditbox-images-3.24.tar
docker compose up -d
```

That is the whole install — one load, one up. The single images tar contains
all five images, so there is no ordering to get right.
</details>

---

## 5. Confirm it sized itself correctly

```sh
docker compose logs llm | grep "LLM ENTRYPOINT"
```

```
[LLM ENTRYPOINT] Serving Gemma 4 12B (Q8_0) from /models/gemma-4-12B-it-Q8_0.gguf.
[LLM ENTRYPOINT] Detected 64.00GB and 32 core(s), ~1.92GB per 32768-token slot -> 12 slot(s), bounded by RAM (64.00GB; 32 core(s) available).
[LLM ENTRYPOINT] Detected 32 CPU core(s) -> using 32 thread(s) for the completion server.
[LLM ENTRYPOINT] Context: -c 393216 across 12 slot(s) = 32768 tokens per request (kv_unified=yes, kv_8bit=yes).
```

Two lines matter:

- **which model it loaded** — the first line, so you can see the box is running
  the weights you meant it to;
- **32768 tokens per request** — the last line. That is the per-request budget
  the app assumes. If it reads lower, the machine has less RAM than the LLM
  container was expecting and evidence will be truncated before the model sees
  it. Add RAM, lower `LLM_MAX_SLOTS`, or switch to E4B.

---

## 6. Choosing the model

Both completion models are already in the image. One `llama-server` process
serves one model, so the choice is made in `docker-compose.yml` and takes effect
on restart — nothing is downloaded and no new image is needed:

```yaml
  llm:
    environment:
      - LLM_MODEL=12b     # or: e4b
```

```sh
docker compose up -d llm
```

The container adjusts its own memory floor to match (12.5 GB for `12b`, 4.5 GB
for `e4b`), so the slot count re-sizes itself correctly without any other edit.

> **The model dropdown in the application does not override this.** It records
> which model an auditor intended; `llama-server` serves the weights it was
> started with, so `LLM_MODEL` here is what actually runs every audit. Set it to
> match what you tell your auditors.

---

## 7. On a server with more than ~32 GB, cap the LLM

When no limit is set, the container reads the **host's** total RAM and sizes
itself as though it owned the whole machine — which starves the app, database
and embedding server. Harmless on a laptop, not on a 96 GB server. In `docker-compose.yml`:

```yaml
  llm:
    mem_limit: 42g      # 10 concurrent auditors on 12b -> 12 slots
```

Leave the remainder for the app (~8 GB plus ~0.8 GB per active session),
Postgres, Redis and the embedding server (~1 GB).

---

## 8. Settings worth knowing

| Setting | Default | Meaning |
|---|---|---|
| `LLM_MODEL` (llm) | `12b` | Which baked-in model is served: `12b` or `e4b`. |
| `MIN_CTX_PER_REQUEST` (llm) | `32768` | Tokens each request may use. |
| `LLM_NUM_CTX` (app) | `32768` | **Must equal the above.** The app budgets prompts against it. |
| `LLM_MAX_SLOTS` | detected cores | Upper bound on parallel slots. |
| `LLM_SLOTS_OVERRIDE` | — | Pins the slot count outright. |
| `RESOURCE_GUARD_FIXED_OVERHEAD_GB` | per model | The weights' resident footprint. Derived from `LLM_MODEL`; override only if you have measured your own. |
| `REQUIRE_POSTGRES` | `1` | Never silently fall back to container-local SQLite. |
| `JWT_SECRET` | auto-generated | A unique one is generated and persisted on first boot. |

Changing the context size means changing **both** `MIN_CTX_PER_REQUEST` and
`LLM_NUM_CTX` together. They are set in two places because the LLM server
reports the whole shared pool as every slot's size, so the app cannot detect the
real per-request share on its own.

---

## 9. First login

Open `http://localhost:8000/`. The first-boot administrator comes from
`ADMIN_DEFAULT_PASSWORD` and `ADMIN_TOTP_SECRET`; set both in the compose file
before first start, or register the first auditor through the UI. Every account
uses TOTP two-factor authentication — keep the secret shown at registration.

---

## 10. Day-to-day

```sh
docker compose ps        # what is running
docker compose logs app  # application log
docker compose restart   # restart everything
docker compose down      # stop (data is kept)
```

Audit data lives in the `pgdata` and `app_data` volumes and survives `down`,
restarts and upgrades. `down -v` **deletes** it — do not use it to restart.

**A stopped audit can be picked up where it left off.** Progress is checkpointed
after every control, so pressing STOP mid-scan — or losing the machine to a
restart — leaves a resumable checkpoint rather than a lost run. The auditor is
offered **Resume Scan** on that session, and the run continues from the next
unevaluated control under the same mode and evidence scoping it started with;
controls already judged are not re-run.

---

## 11. If something is wrong

| Symptom | Cause and fix |
|---|---|
| App answers 502 / not reachable | The LLM is still loading weights on first start. The 12B takes longer than the E4B — give it 3–5 minutes. |
| LLM container exits at start | It names the missing file and lists `/models`. Almost always `LLM_MODEL` set to something other than `12b`, `e4b` or an absolute path. |
| "per request" is below 32768 | Not enough RAM for the slot count. Add RAM, set `LLM_MAX_SLOTS` lower, or switch `LLM_MODEL` to `e4b`. |
| Audits queue instead of running | Slot count is the limit — see the sizing table in section 2. |
| Controls report a timeout | Cores are the limit. The finding says so explicitly rather than guessing a verdict. |
| Postgres connection refused | The database did not become healthy. `docker compose logs shakthidb`. |
| App exits complaining about Postgres | Deliberate: `REQUIRE_POSTGRES=1` stops it writing audit data to a throwaway SQLite file. Fix the database rather than unsetting it. |

Upload scanner exports in their **native format** (`.nessus`, Burp XML, Nmap
XML) rather than PDF printouts — parsers read structure, and a PDF export throws
most of it away.

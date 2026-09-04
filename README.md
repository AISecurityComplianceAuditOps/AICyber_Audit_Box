# 🛡️ AICyberAuditBox — Local AI Cyber Audit

> **Agentic RAG · ISO 27001 / VAPT / PQC Compliance Audit Intelligence**  
> Powered by **llama.cpp** (offline GGUF LLMs) · **FastAPI** · **ShaktiDB (PostgreSQL)** · **Vanilla HTML/JS UI**

---

## Tech Stack

| Layer | Technology |
|---|---|
| **LLM Engine** | llama.cpp (`llama-server.exe`) — runs GGUF models fully offline |
| **Audit LLM (Primary)** | Gemma 4 12B (`gemma-4-12B-it-Q8_0.gguf`)  |
| **Audit LLM (Fallback 1)** | Gemma 2 9B (`gemma-2-9b-it-Q8_0.gguf`) |
| **Audit LLM (Fallback 2)** | Gemma 4 E4B (`google_gemma-4-E4B-it-Q4_K_M.gguf`) — Standard |
| **Embeddings** | Nomic Embed Text v1.5 (`nomic-embed-text-v1.5.f16.gguf`) — local RAG |
| **Backend API** | FastAPI + Uvicorn |
| **Frontend UI** | Vanilla HTML + JavaScript (no frameworks) |
| **Database (Production)** | ShaktiDB — PostgreSQL Master + Slave 1 + Slave 2 (port 15234/15235/15236) |
| **Database (Local Fallback)** | SQLite (`data/sqlite/shakthidb_sqlite.db`) — auto-activated if ShaktiDB is offline |
| **Document Parsing** | pdfplumber, pypdf, python-docx, python-pptx, openpyxl, pytesseract, doctr |
| **RAG Retrieval** | Cosine similarity over local Nomic embeddings |

---

## Features

### 🔍 AI-Powered Auditing
- **ISO 27001**, **VAPT** (Nessus, Nmap, Burp Suite, Qualys, Trivy, Kali), and **PQC** (Post-Quantum Cryptography) audit modes
- **Dual evaluation**: Policy vs Evidence assessed independently — `FOUND`/`NOT_FOUND` + `COMPLIANT`/`NON_COMPLIANT`
- **Deterministic validator** (`src/core/validator.py`) overrides LLM self-reported status — no hallucinated compliance
- False positive / false negative prevention built into every prompt chain
- **Applicability scoping** — controls automatically excluded if not relevant to the uploaded documents

### 📁 Evidence Upload
| Format | Support |
|---|---|
| PDF | ✅ Native text + OCR for scanned pages |
| Word (.docx / .doc) | ✅ |
| Excel (.xlsx / .xls) | ✅ All sheets |
| Excel Scoping Sheet | ✅ Separate Policy + Evidence columns per control |
| CSV | ✅ |
| PowerPoint (.pptx / .ppt) | ✅ All slides |
| Plain Text (.txt) | ✅ |
| PNG / JPG / JPEG | ✅ OCR (pytesseract / doctr) |
| ZIP (folder upload) | ✅ Recursively extracts all supported files |

### ⚡ Crash-Resilient Checkpointing
- Progress saved to ShaktiDB / SQLite after every control batch
- On restart, a **"Resume Interrupted Audit"** banner appears automatically
- One click resumes from the last completed batch — prior results are preserved and merged

### 📊 Audit Report
- Interactive finding cards with Evidence Found badge, Evidence Snippet, Compliance Status, Auditor Reasoning, Gaps
- Filter by severity (P1 Critical / P2 High / P3 Medium / P4 Low / Compliant)
- Accept / Modify / Delete / Auditor Notes per finding
- Export to **PDF** and **DOCX** full audit reports
- Interactive **HTML Proof Sheet** for each audit run

### 🗄️ Database — ShaktiDB (PostgreSQL Master-Slave)
- **Master**: `localhost:15234` — all writes
- **Slave 1**: `localhost:15235` — synchronous replica
- **Slave 2**: `localhost:15236` — synchronous replica
- **Auto-failover**: If ShaktiDB is unreachable, app silently switches to local SQLite
- **Docker required** to run ShaktiDB (started automatically by `run_all.bat`)

---

## Quick Start (Windows)

### 1. Install dependencies
```bat
pip install -r requirements.txt
```

### 2. Run everything (API + llama.cpp LLM server + ShaktiDB)
```bat
run_all.bat
```

### 3. Or run just the API (with llama.cpp already running externally)
```bat
run_api_llamacpp.bat
```

Then open your browser at: **`http://localhost:8000`**

---

## Architecture

```
src/
├── ai/
│   ├── audit_chains.py       — LLM prompt chains (Policy + Evidence evaluation)
│   ├── audit_graph.py        — LangGraph orchestration (per-control audit pipeline)
│   ├── audit_models.py       — Pydantic models for audit findings
│   ├── scoping_engine.py     — Automatic document scope detection
│   ├── keyword_generator.py  — Keyword extraction for RAG retrieval
│   └── knowledge_loop.py     — Knowledge base query loop
├── api/
│   ├── main.py               — FastAPI app entry point (port 8000)
│   ├── endpoints/
│   │   ├── audit.py          — Audit job submission, status polling, results
│   │   ├── auth.py           — Login / JWT authentication
│   │   ├── controls.py       — ISO 27001 control definitions API
│   │   ├── license.py        — Hardware node license validation
│   │   └── logs.py           — Audit run log streaming
│   └── static/               — Vanilla HTML/JS/CSS frontend
│       ├── index.html
│       ├── app.js
│       └── style.css
├── core/
│   ├── bg_worker.py          — Background audit job executor
│   ├── validator.py          — Deterministic compliance rule engine
│   ├── retrieval.py          — RAG vector retrieval (Nomic embeddings)
│   ├── report_exporter.py    — PDF / DOCX report generation
│   ├── llm_client.py         — llama.cpp HTTP client (port 11434)
│   ├── controls_data.py      — ISO 27001 / VAPT / PQC control definitions
│   ├── excel_scoping_parser.py — Excel checklist scoping parser
│   ├── parsers/              — Document + scanner output parsers
│   │   ├── doc_parsers.py
│   │   ├── burp_parser.py
│   │   ├── nessus_parser.py
│   │   ├── nmap_parser.py
│   │   ├── qualys_parser.py
│   │   ├── trivy_parser.py
│   │   ├── kali_parser.py
│   │   └── pqc_parser.py
│   └── knowledge/            — Embedded knowledge JSON files per standard
└── db/
    └── database.py           — SQLAlchemy ORM (ShaktiDB PostgreSQL + SQLite fallback)

init.sql                      — DB schema bootstrap
config/retrieval_config.json  — RAG retrieval tuning parameters
requirements.txt
```

---

## Models Required (place in project root)

| Model file | Purpose | Size |
|---|---|---|
| `gemma-4-12B-it-Q8_0.gguf` | **Primary audit LLM** — Gemma 4 12B Champion | ~11.8 GB |
| `google_gemma-4-E4B-it-Q4_K_M.gguf` | Audit LLM — Gemma 4 E4B Standard | ~5.4 GB |
| `gemma-2-9b-it-Q8_0.gguf` | Audit LLM — Gemma 2 9B fallback | ~9.0 GB |
| `nomic-embed-text-v1.5.f16.gguf` | **Embedding model** for RAG retrieval (port 11435) | ~274 MB |

> **Model selection priority in `run_all.bat`:**  
> Gemma 4 12B → Gemma 2 9B → Gemma 4 E4B (first GGUF file found is used)

> **UI model selector:** Choose between `Gemma 4 (12B) - Champion` and `Gemma 4 (e4b) - Standard` in the web UI before starting an audit.

> Models are **not** included in this repository. Download GGUF files from HuggingFace and place them in the project root.

---

## Ports Used

| Port | Service |
|---|---|
| `8000` | FastAPI / Web UI |
| `11434` | llama.cpp LLM server (Gemma audit model) |
| `11435` | llama.cpp Embedding server (Nomic embed) |
| `15234` | ShaktiDB PostgreSQL Master |
| `15235` | ShaktiDB PostgreSQL Slave 1 |
| `15236` | ShaktiDB PostgreSQL Slave 2 |

---

## Troubleshooting

- **API not starting?** Run `pip install -r requirements.txt` first.
- **LLM not responding?** Make sure `llama-server.exe` is running on port 11434. `run_all.bat` starts it automatically.
- **No GGUF model found?** Place `gemma-4-12B-it-Q8_0.gguf` (or any supported GGUF) in the project root directory.
- **ShaktiDB unreachable?** App auto-switches to SQLite. Start Docker and re-run `run_all.bat` to restore PostgreSQL.
- **DB errors?** The schema is auto-reconciled on every startup via `init_db()`.

---

## Compliance Standards Supported

| Standard | Coverage |
|---|---|
| **ISO 27001:2022** | All Annex A controls (93 controls) |
| **VAPT** | Nessus · Nmap · Burp Suite · Qualys · Trivy · Kali Linux reports |
| **PQC** | Post-Quantum Cryptography readiness (NIST PQC algorithms) |
| **NIST CSF** | Partial coverage via control mapping |
| **SOC 2** | Partial coverage via control mapping |
| **DPDP / GDPR** | Partial coverage via control mapping |
| **BCMS** | Partial coverage via control mapping |

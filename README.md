# 🛡️ AICyberAuditBox — Local AI Cyber Audit

> **Agentic RAG · ISO 27001 / VAPT / PQC Compliance Audit Intelligence**  
> Powered by **llama.cpp** (offline GGUF LLMs) · **FastAPI** · **SQLite** · **Vanilla HTML/JS UI**

---

## Tech Stack

| Layer | Technology |
|---|---|
| **LLM Engine** | llama.cpp (`llama-server.exe`) with local GGUF models (Gemma 2/4) |
| **Embeddings** | Nomic Embed Text v1.5 (local GGUF, via llama.cpp) |
| **Backend API** | FastAPI + Uvicorn |
| **Frontend UI** | Vanilla HTML + JavaScript (no frameworks) |
| **Database** | SQLite (local file — `local_audit_app.db`) |
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
- Progress saved to SQLite after every control batch
- On restart, a **"Resume Interrupted Audit"** banner appears automatically
- One click resumes from the last completed batch — prior results are preserved and merged

### 📊 Audit Report
- Interactive finding cards with Evidence Found badge, Evidence Snippet, Compliance Status, Auditor Reasoning, Gaps
- Filter by severity (P1 Critical / P2 High / P3 Medium / P4 Low / Compliant)
- Accept / Modify / Delete / Auditor Notes per finding
- Export to **PDF** and **DOCX** full audit reports
- Interactive **HTML Proof Sheet** for each audit run

---

## Quick Start (Windows)

### 1. Install dependencies
```bat
pip install -r requirements.txt
```

### 2. Run the full stack (API + llama.cpp LLM server)
```bat
run_all.bat
```

### 3. Or run just the API (with an external llama.cpp server already running)
```bat
run_api.bat
```

### 4. Run with llama.cpp bundled
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
│   ├── main.py               — FastAPI app entry point
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
│   ├── llm_client.py         — llama.cpp HTTP client
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
    └── database.py           — SQLAlchemy ORM (SQLite)

init.sql                      — DB schema bootstrap
config/retrieval_config.json  — RAG retrieval tuning parameters
requirements.txt
```

---

## Models Required (place in project root)

| Model file | Purpose |
|---|---|
| `gemma-2-2b-it-Q4_K_M.gguf` | Fast audit LLM (lightweight) |
| `gemma-2-9b-it-Q8_0.gguf` | Deep audit LLM (high accuracy) |
| `nomic-embed-text-v1.5.f16.gguf` | Local embedding model for RAG |

> Models are **not** included in this repository. Download from HuggingFace or use `pull_models.bat`.

---

## Troubleshooting

- **API not starting?** Run `pip install -r requirements.txt` first.
- **LLM not responding?** Make sure `llama-server.exe` is running (started automatically by `run_all.bat` / `run_api_llamacpp.bat`).
- **No results appearing?** Check that GGUF model files exist in the project root directory.
- **DB errors?** Delete `local_audit_app.db` and restart — it will be recreated automatically from `init.sql`.

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

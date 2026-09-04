# 🛡️ AICyberAuditBox — Local Audit

> **Agentic RAG · ISO 27001 Compliance Audit Intelligence**  
> Powered by Ollama (offline LLM) · ShaktiDB (PostgreSQL) · Streamlit

---

## Features

### 🔍 AI-Powered ISO 27001 Auditing
- **Senior Lead Auditor logic** — relevance scoring, semantic evidence evaluation, no blind control checking
- **4-State Compliance**: Compliant · Partially Compliant · Non-Compliant · Out Of Scope
- **P1–P4 Severity Scale**: P1 Critical → P2 High → P3 Medium → P4 Low
- False positive & false negative prevention built into the LLM prompt

### 📁 Evidence Upload
| Format | Support |
|---|---|
| PDF | ✅ Native text + OCR for scanned pages |
| Word (.docx/.doc) | ✅ |
| Excel (.xlsx/.xls) | ✅ All sheets |
| CSV | ✅ |
| PowerPoint (.pptx/.ppt) | ✅ All slides |
| Plain Text (.txt) | ✅ |
| PNG / JPG / JPEG | ✅ OCR (EasyOCR) |
| **ZIP (folder upload)** | ✅ Recursively extracts all supported files |

> **Folder upload:** Zip your folder → upload the `.zip` file. All files inside are automatically extracted, processed and combined as evidence.

### ⚡ Crash-Resilient Checkpointing
If the app crashes or shuts down mid-audit:
1. Progress is saved to ShaktiDB after **every batch** (~10 controls)
2. On restart, a **"Resume Interrupted Audit"** banner appears automatically
3. One click resumes from the last completed batch — prior results are preserved and merged

### 📊 Audit Report
- Interactive finding cards with Relevance Score, Evidence Found badge, Evidence Snippet, Compliance Status, Auditor Reasoning
- Severity filter cards (P1/P2/P3/P4 + Compliant)
- Accept / Modify / Delete / Auditor Notes per finding
- Export full CSV: Control ID · Relevance Score · Evidence Found · Evidence Snippet · Compliance Status · Severity · Finding · Recommendation · Reasoning

### 🗄️ Database
- **Primary**: ShaktiDB PostgreSQL Master (on `localhost:15234`)
- **Replicas**: ShaktiDB PostgreSQL Slave 1 & Slave 2 (synchronously replicated)

---

## Quick Start

```bat
.\run_demo.bat
```

Or manually:

```bat
docker-compose up -d
streamlit run src/ui/app.py
```

---

## Architecture

``
src/ui/app.py       — Main Streamlit application
database.py         — SQLAlchemy ORM (Master-Slave, 6 Normalized Tables, RoutingSession)
auth.py             — Login gate / role management
controls_data.py    — ISO 27001 control definitions
scoping_engine.py   — Automatic document scope detection
```

---

## Troubleshooting

- **ShaktiDB not reachable?** App auto-switches to SQLite local DB.
- **Ollama not running?** Start with `docker-compose up -d`, then pull models with `.\pull_models.bat`.
- **Schema upgrade?** On first restart after an update, `audit_findings` and `audit_checkpoints` tables are automatically recreated.

```bat
## Useful commands
docker-compose up -d
.\pull_models.bat
python -m py_compile src/ui/app.py   # syntax check
```

## 
cd "C:\Users\HP\Desktop\llama,cpp\au"
run_llamacpp_demo.bat

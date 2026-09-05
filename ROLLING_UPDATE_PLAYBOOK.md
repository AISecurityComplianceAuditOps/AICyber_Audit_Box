# AICyberAuditBox v3.10 — Rolling Update & Maintenance Playbook

## Overview & Scope
How to ship application updates, bug fixes, prompt changes, or database schema modifications to a running customer deployment **without rebuilding all 5 images** or taking the entire service offline.

- **Target Environment**: Air-gapped customer deployments running `docker-compose.customer.yml`.
- **Core Automation Tools**: `update_bundle.ps1`, `src/db/database.py` (`reconcile_schemas()`).
- **Primary Goal**: Zero downtime for core AI LLM & PostgreSQL services during routine updates.

---

## 1. Core Architecture Principles

### A. Automatic Schema Self-Healing (`reconcile_schemas`)
On every application container boot, `src/db/database.py` automatically inspects the live PostgreSQL schema against SQLAlchemy model definitions and issues `ALTER TABLE ... ADD COLUMN` for any missing columns. No manual SQL scripts are required for additive database changes.

### B. Layer-Cached Docker Builds (`Dockerfile.app`)
PyPI dependencies (`requirements.txt`, PyTorch, OpenCV) are installed in a separate Docker layer before `src/` is copied. Code-only changes rebuild in seconds without re-downloading PyPI packages.

### C. Scoped Image Exports (`update_bundle.ps1 -DeltaOnly`)
Using the `-DeltaOnly` flag exports ONLY the updated container image (`aicyberauditbox_delta_app_v3.10.tar`, ~50 MB) rather than re-exporting the full 12.3 GB 5-image bundle.

### D. Persistent Data Storage
All PostgreSQL database state (`pgdata`) and application upload data (`app_data`) are stored in named Docker volumes, ensuring zero data loss during container updates.

---

## 2. Three Update Scenarios

| Scenario | Scope & Trigger | Affected Containers | Downtime / Impact |
| :--- | :--- | :--- | :--- |
| **A. Application Code Change** | Bug fixes, UI updates, prompt tweaks, endpoint additions | `app` container only | **Zero DB/LLM downtime**. Only `app` restarts (~5s). |
| **B. Additive Database Change** | New database columns or new tables | `app` container only | **Zero DB/LLM downtime**. Auto-healed on `app` boot via `reconcile_schemas()`. |
| **C. Structural Database Change** | Renaming/dropping columns, retyping data types | `shakthidb` + `app` | **Scheduled Maintenance**. Pre-migration backup required. |

---

## 3. Standard Operating Procedure (Scenarios A & B)

This is the standard procedure used for 95% of routine customer software updates.

### Step 1: Build & Export Delta Bundle (Developer Machine)
Execute the scoped delta exporter in PowerShell:

```powershell
.\update_bundle.ps1 -Version 3.10 -Services app -DeltaOnly
```

**Output Artifacts Generated**:
1. `aicyberauditbox_delta_app_v3.10.tar` (~50 MB)
2. `aicyberauditbox_delta_app_v3.10_companion.zip` (contains `docker-compose.customer.yml`)

### Step 2: Load Updated Delta Image (Customer Machine)
Transfer the 50 MB tarball to the air-gapped customer machine and load the new image:

```bash
docker load -i aicyberauditbox_delta_app_v3.10.tar
```

### Step 3: Replace Compose File & Perform Rolling Restart
Extract `docker-compose.customer.yml` from the companion zip and restart **only the app container**:

```bash
docker compose -f docker-compose.customer.yml up -d app
```

*(PostgreSQL `shakthidb`, `redis`, `llm`, and `llm-embed` stay online throughout this entire process).*

### Step 4: Verify Schema Reconciliation & App Health
Confirm the application booted cleanly and reconciled any new schema columns:

```bash
# Check container logs for schema reconciliation confirmation
docker compose -f docker-compose.customer.yml logs app --tail 40

# Verify HTTP API health
curl -sf http://localhost:8000/health ; echo "OK"
```

---

## 4. Maintenance Procedure (Scenario C: Structural DB Changes)

For rare structural database modifications (e.g., column renaming or type changes):

1. **Pre-Migration Database Backup**: Take a manual snapshot of `shakthidb_master` using `pg_dump` prior to applying updates.
2. **Execute Migration Script**: Apply the one-off Python or SQL migration script directly against PostgreSQL on port `15234`.
3. **Deploy Updated App Code**: Deploy the updated application image using Step 3 above.

---

## 5. Rollback Procedure

All Docker image tags are versioned explicitly. Reverting to a previous software version takes under 10 seconds:

```bash
# Edit docker-compose.customer.yml: set app image tag back to previous version (e.g., 3.9)
docker compose -f docker-compose.customer.yml up -d app
```

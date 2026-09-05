# AICyberAuditBox v3.12 — Customer Setup & Operations Guide

## Overview
This document provides simple instructions for installing, operating, and applying routine software updates for **AICyberAuditBox v3.12** on your local PC or server. The system operates **100% offline (air-gapped)** with zero internet dependency.

---

## 1. System Hardware Requirements

| Hardware / Software | Minimum Requirement | Notes |
| :--- | :--- | :--- |
| **System RAM** | **32 GB RAM** | **Required** for 128k context pool and 8 parallel audit evaluation slots |
| **Processor (CPU)** | **8 Cores** (x86_64) | 64-bit multi-core CPU |
| **Free Storage** | **30 GB Free SSD** | High-speed SSD recommended for optimal performance |
| **Operating System** | **Windows 10/11, Windows Server, or Linux** | Requires Docker installed |
| **Prerequisites** | **Docker Desktop (Windows)** or **Docker Engine (Linux)** | Must include Docker Compose v2+ |
| **Network** | **None (Air-Gapped)** | Zero internet access needed |

---

## 2. Package Types Delivered to You

Depending on whether you are doing a **First-Time Setup** or a **Routine App Update**, you will receive one of two packages:

* **Type A: Full Air-Gapped Package (First-Time / Disaster Recovery Install)**
  - `aicyberauditbox_bundle_v3.10.tar` (Full offline images bundle)
  - `aicyberauditbox_bundle_v3.10_companion.zip` (Configuration & Compose file)

* **Type B: Routine Delta Update Package (App Code / Bug Fix Updates)**
  - `aicyberauditbox_delta_app_v3.12.tar` (~50–100 MB small update file)
  - `aicyberauditbox_delta_app_v3.12_companion.zip` (~5 KB configuration update)

---

## 3. First-Time Installation (Full Setup)

Follow these **3 steps** for a new installation:

```bash
# Step 1: Transfer both files to your target PC folder (e.g. C:\AICyberAuditBox)

# Step 2: Load all offline software images (One-time step)
docker load -i aicyberauditbox_bundle_v3.10.tar

# Step 3: Extract configuration file and start the system
unzip aicyberauditbox_bundle_v3.10_companion.zip
docker compose -f docker-compose.customer.yml up -d
```

---

## 4. Applying Routine Software Updates (Delta Updates)

When you receive a **Routine Delta Update Package** (e.g., `v3.12` code fixes or prompt enhancements), follow these **2 fast steps**:

```bash
# Step 1: Load ONLY the updated app image (Takes ~5 seconds)
docker load -i aicyberauditbox_delta_app_v3.12.tar

# Step 2: Replace compose file & restart ONLY the app container
unzip -o aicyberauditbox_delta_app_v3.12_companion.zip
docker compose -f docker-compose.customer.yml up -d app
```

### Why Delta Updates are Fast & Safe:
- **Zero Database Downtime**: PostgreSQL (`shakthidb`), Redis, and LLM servers stay **100% online and running**.
- **Zero Data Loss**: All existing audit records, database state, and uploaded evidence files remain completely untouched.
- **Auto Schema Migration**: Any new database columns are automatically created when the updated app boots up.
- **Completion Time**: Under 10 seconds total on your PC.

---

## 5. Accessing the System

Open your web browser (Chrome, Edge, Brave, or Firefox) and navigate to:

- **Web Portal URL**: `http://localhost:8000`
- **Default Username**: `admin`
- **Default Password**: `admin123` *(Change on first login)*

---

## 6. Daily Operations & Verification

### Check Service Status
```bash
docker compose -f docker-compose.customer.yml ps
```

### Useful Commands

| Action | Command |
| :--- | :--- |
| **View Live App Logs** | `docker compose -f docker-compose.customer.yml logs -f app` |
| **Stop All Services** | `docker compose -f docker-compose.customer.yml down` |
| **Start / Restart Services** | `docker compose -f docker-compose.customer.yml up -d` |

---

## 7. Support
For technical assistance, please contact your **AICyberAuditBox Deployment Support Team**.

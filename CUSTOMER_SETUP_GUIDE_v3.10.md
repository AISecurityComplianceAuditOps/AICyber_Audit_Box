# AICyberAuditBox v3.10 — Customer PC Setup Guide

## Overview
This document provides simple, step-by-step instructions for installing and running **AICyberAuditBox v3.10** on your local PC or server. The entire system operates **100% offline (air-gapped)** with zero internet dependency.

---

## 1. System Requirements

| Hardware / Software | Minimum Requirement | Notes |
| :--- | :--- | :--- |
| **System RAM** | **32 GB RAM** | **Required** for 128k context pool and 8 parallel audit evaluation slots |
| **Processor (CPU)** | **8 Cores** (x86_64) | 64-bit multi-core CPU |
| **Free Storage** | **30 GB Free SSD** | High-speed SSD recommended for optimal performance |
| **Operating System** | **Windows 10/11, Windows Server, or Linux** | Requires Docker installed |
| **Prerequisites** | **Docker Desktop (Windows)** or **Docker Engine (Linux)** | Must include Docker Compose v2+ |
| **Network** | **None (Air-Gapped)** | Zero internet access needed |

---

## 2. Delivery Package Files

Your delivery package contains **two files**:

1. **`aicyberauditbox_bundle_v3.10.tar`** (~12.3 GB) — All pre-packaged offline system images.
2. **`aicyberauditbox_bundle_v3.10_companion.zip`** (~6.7 KB) — Configuration file (`docker-compose.customer.yml`) and setup guide.

---

## 3. Step-by-Step Installation Guide

Follow these **3 simple steps** on your target PC or server:

### Step 1: Copy Files to Your Target PC
Copy both `aicyberauditbox_bundle_v3.10.tar` and `aicyberauditbox_bundle_v3.10_companion.zip` into a dedicated folder on your computer (e.g., `C:\AICyberAuditBox` or `/opt/aicyberauditbox`).

### Step 2: Load the Offline Software Images
Open **Command Prompt**, **PowerShell**, or **Linux Terminal** in that folder, and execute:

```bash
docker load -i aicyberauditbox_bundle_v3.10.tar
```

*(This loads the pre-built PostgreSQL database, LLM engine, and application images into Docker. Takes ~1 to 2 minutes).*

### Step 3: Extract Configuration & Start System
Extract the companion zip and launch the application:

```bash
# Extract configuration file
unzip aicyberauditbox_bundle_v3.10_companion.zip

# Launch all system services
docker compose -f docker-compose.customer.yml up -d
```

---

## 4. Accessing the System

Once the containers start up, open your web browser (Chrome, Edge, Brave, or Firefox) and navigate to:

- **Web Portal URL**: `http://localhost:8000`
- **Default Username**: `admin`
- **Default Password**: `admin123`

*(You will be prompted to change your password and set up TOTP Multi-Factor Authentication on your first login).*

---

## 5. Verification & Daily Operations

### Check Service Status
To verify that all system services are running cleanly:

```bash
docker compose -f docker-compose.customer.yml ps
```

All 5 services (`shakthidb_service`, `vaptiso_redis`, `aicyberauditbox_llm`, `aicyberauditbox_llm_embed`, `aicyberauditbox_app`) should report state **Running** or **Healthy**.

### Useful Daily Commands

| Task | Command |
| :--- | :--- |
| **View Live Logs** | `docker compose -f docker-compose.customer.yml logs -f app` |
| **Stop System** | `docker compose -f docker-compose.customer.yml down` |
| **Restart System** | `docker compose -f docker-compose.customer.yml up -d` |

---

## 6. Support
For technical assistance or questions, please contact your **AICyberAuditBox Deployment Support Team**.

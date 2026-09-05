# AICyberAuditBox v3.17 — Customer Setup & Operations Guide

## Overview
This document provides simple, step-by-step instructions for installing, operating, and applying software updates for **AICyberAuditBox v3.17** on your local PC or server. The system operates **100% offline (air-gapped)** with zero internet dependency.

---

## 1. System Hardware Requirements

| Hardware / Component | Minimum Requirement | Recommended (Enterprise Production) |
| :--- | :--- | :--- |
| **Processor (CPU)** | **8 Cores** (x86_64) | **16+ Cores** (e.g. AMD EPYC / Intel Xeon) |
| **System RAM** | **24 GB RAM** | **32 GB – 64 GB RAM** |
| **GPU (Optional)** | **NVIDIA GPU (8 GB VRAM)** | **NVIDIA GPU (12 GB – 48 GB VRAM)** |
| **Free Storage** | **30 GB SSD** | **100 GB NVMe SSD** |
| **Operating System** | **Linux (Ubuntu/RHEL/Debian) or Windows 10/11 / Windows Server** |
| **Prerequisites** | **Docker Engine 24+** & **Docker Compose v2+** |
| **Network** | **None (Air-Gapped)** — 100% offline operation |

---

## 2. Delivered Package Files

You have received two files for **AICyberAuditBox v3.17**:

1. 📦 **`aicyberauditbox_bundle_v3.17.tar`** (~8.36 GB)
   - Contains all pre-built offline Docker container images (`app`, `shakthidb` PostgreSQL vector DB, Gemma 4B LLM server, Nomic embedding server, Redis cache).

2. 📄 **`aicyberauditbox_bundle_v3.17_companion.zip`** (~6.8 KB)
   - Contains `docker-compose.customer.yml` (orchestration configuration) and setup documentation.

---

## 3. First-Time Air-Gapped Installation

Follow these **3 simple steps** on your target server:

### Step 1: Place Files in Deployment Folder
Create a deployment directory and place both received files into it:
```bash
mkdir -p /opt/aicyberauditbox && cd /opt/aicyberauditbox
# Copy aicyberauditbox_bundle_v3.17.tar and aicyberauditbox_bundle_v3.17_companion.zip here
```

### Step 2: Load Offline Software Images (One-Time)
Run `docker load` to import all container images into your local Docker registry (no internet connection required):
```bash
docker load -i aicyberauditbox_bundle_v3.17.tar
```

### Step 3: Extract Configuration & Start System
Unzip the companion package and launch all services with Docker Compose:
```bash
# Extract configuration file
unzip aicyberauditbox_bundle_v3.17_companion.zip

# Launch all 5 microservices in background
docker compose -f docker-compose.customer.yml up -d
```

---

## 4. Verifying Installation & Accessing System

### 1. Check Container Health
Run the following command to verify all containers are running and healthy:
```bash
docker compose -f docker-compose.customer.yml ps
```
*Expected status for all containers: `Up` or `Up (healthy)`.*

### 2. Access Web Portal
Open your web browser (Chrome, Edge, Brave, or Firefox) and navigate to:

- **Web Portal URL**: `http://<SERVER_IP>:8000` (or `http://localhost:8000`)
- **Default Username**: `admin`
- **Default Password**: `admin123` *(Change on first login)*

---

## 5. Applying Routine Software Updates (Delta Updates)

When you receive a **Routine App Patch Package** (e.g. `aicyberauditbox_delta_app_v3.17.tar.gz`), update your system in under 10 seconds:

### Windows:
```cmd
apply_patch.bat
```

### Linux:
```bash
bash apply_patch.sh
```

### Why Delta Updates are Fast & Safe:
- **Zero Database Downtime**: PostgreSQL (`shakthidb`), Redis, and LLM servers stay **100% online and running**.
- **Zero Data Loss**: All existing audit records, database state, and uploaded evidence files remain completely untouched.
- **Completion Time**: Under 10 seconds total.

---

## 6. Helpful Operational Commands

| Action | Command |
| :--- | :--- |
| **View Live Application Logs** | `docker compose -f docker-compose.customer.yml logs -f app` |
| **View LLM Inference Logs** | `docker compose -f docker-compose.customer.yml logs -f llm` |
| **Check Active Container Status** | `docker compose -f docker-compose.customer.yml ps` |
| **Restart Application Container** | `docker compose -f docker-compose.customer.yml restart app` |
| **Stop Entire System** | `docker compose -f docker-compose.customer.yml down` |
| **Start System** | `docker compose -f docker-compose.customer.yml up -d` |

---

## 7. Technical Support
For technical assistance, please contact your **AICyberAuditBox Deployment Support Team**.

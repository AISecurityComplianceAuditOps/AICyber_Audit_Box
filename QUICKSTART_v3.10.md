# AICyberAuditBox v3.10 - Customer Quickstart

## What's in your delivery
You received two files:
  1. aicyberauditbox_bundle_v3.10.tar      -- All Docker images (~7 GB, air-gapped)
  2. aicyberauditbox_bundle_v3.10_companion.zip -- This guide + docker-compose.customer.yml

## Prerequisites
- Docker Engine 24+ and Docker Compose v2+
- Minimum 24 GB RAM (32 GB recommended for full 8-slot LLM concurrency)
- Linux or Windows Server with Docker Desktop

## Deploy (offline / air-gapped)

  Step 1 - Load all images (one-time, no internet needed):
    docker load -i aicyberauditbox_bundle_v3.10.tar

  Step 2 - Start all services:
    docker compose -f docker-compose.customer.yml up -d

  Step 3 - Verify all containers are running:
    docker compose -f docker-compose.customer.yml ps

## Access
  Web UI  : http://localhost:8000
  Admin   : username=admin  password=admin123  (change on first login)

## Day-to-day commands
  Stop:     docker compose -f docker-compose.customer.yml down
  Logs:     docker compose -f docker-compose.customer.yml logs -f app
  Restart:  docker compose -f docker-compose.customer.yml up -d

## Upgrading to a new version
  Routine app-only update? Use a -DeltaOnly bundle instead of this full one --
  see UPDATE_v<version>.md in that delivery. Only re-run the full install below
  for first-time setup or disaster recovery.
  1. docker load -i aicyberauditbox_bundle_vNEW.tar
  2. Replace docker-compose.customer.yml with the new one from the companion zip
  3. docker compose -f docker-compose.customer.yml up -d
  (Your database and uploaded data are preserved in Docker volumes: pgdata, app_data)

## Included images
- aicyberauditbox-shakthidb:3.10
- aicyberauditbox-llm:3.10
- aicyberauditbox-llm-embed:3.10
- aicyberauditbox-app:3.10
- redis:7-alpine

## Support
Contact your AICyberAuditBox deployment team for assistance.

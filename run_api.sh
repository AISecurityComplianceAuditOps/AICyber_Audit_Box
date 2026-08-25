#!/bin/bash
echo "=========================================="
echo "   AICyberAuditBox - Local Web Dashboard (macOS)"
echo "=========================================="

# 1. Check local LLM
echo "[1/3] Checking Offline LLM Engine..."
nc -z -w 1 127.0.0.1 11434 >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[WARNING] Ollama/llama.cpp LLM server is not detected on port 11434!"
    echo "          Please start Ollama or run your local llama-server first."
    sleep 3
else
    echo "[v] OK: Local LLM service is active."
fi

# 2. Check Docker for ShaktiDB
echo ""
echo "[2/3] Checking Docker Database Service (ShaktiDB)..."
retry_count=0

while ! docker info >/dev/null 2>&1; do
    retry_count=$((retry_count+1))
    if [ $retry_count -ge 12 ]; then
        echo "[ERROR] Docker is not running or Docker Desktop is not detected!"
        echo "        ShaktiDB PostgreSQL is required for database operations."
        echo "        Please start Docker Desktop and run this script again."
        exit 1
    fi
    echo "[i] Waiting for Docker service to start (Attempt $retry_count/12)..."
    sleep 5
done

echo "[v] OK: Docker is running. Starting ShaktiDB container..."
docker-compose up -d

# 3. Launching FastAPI & browser
echo ""
echo "[3/3] Launching Local API Dashboard..."
open http://127.0.0.1:8000/
python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000

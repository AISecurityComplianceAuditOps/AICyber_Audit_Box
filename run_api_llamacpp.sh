#!/bin/bash
echo "=========================================="
echo "   AICyberAuditBox - Local Web Dashboard (llama.cpp/macOS)"
echo "=========================================="

# 1. Check local LLM & Embeddings
echo "[1/3] Checking llama.cpp GGUF Servers..."
nc -z -w 1 127.0.0.1 11434 >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[ERROR] llama.cpp LLM server is not detected on port 11434!"
    echo "        Please start the LLM server."
    exit 1
fi

nc -z -w 1 127.0.0.1 11435 >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[ERROR] llama.cpp Embedding server is not detected on port 11435!"
    echo "        Please start the Embedding server."
    exit 1
fi

echo "[v] OK: llama.cpp LLM & Embedding services are active."

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
docker rm -f shakthidb_service >/dev/null 2>&1
docker-compose up -d

# 3. Launching FastAPI & browser
echo ""
echo "[3/3] Launching Local API Dashboard..."
export LLM_BACKEND=llama.cpp
export EMBEDDING_HOST=http://127.0.0.1:11435

open http://127.0.0.1:8000/
python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000

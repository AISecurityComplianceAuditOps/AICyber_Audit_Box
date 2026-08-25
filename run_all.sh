#!/bin/bash
echo "=================================================="
echo "  AICyberAuditBox: Unified Single-Click Launcher"
echo "=================================================="

# Stop any running instances
echo "[1/5] Stopping any existing backend server instances..."
pkill -f llama-server >/dev/null 2>&1
pkill -f uvicorn >/dev/null 2>&1

# Resolve llama-server location (checks local, downloads, desktop)
LLAMA_SERVER_EXE="llama-server"
if [ -f "$HOME/Desktop/llama/llama-server" ]; then
    LLAMA_SERVER_EXE="$HOME/Desktop/llama/llama-server"
elif [ -f "./llama-server" ]; then
    LLAMA_SERVER_EXE="./llama-server"
fi

echo ""
echo "[2/5] Starting llama.cpp LLM Server (Port 11434, 128k fluid shared pool, 8-bit KV cache, $CPU_CORES slots)..."
CPU_CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
# -c 131072       : 128k fluid shared token pool (PagedAttention via --cont-batching)
# -np $CPU_CORES  : one slot per physical core — full CPU utilisation, no thrashing
# -ctk/ctv q8_0   : 8-bit KV-cache compression (~9 GB vs ~18 GB FP16, 0% accuracy loss)
nohup "$LLAMA_SERVER_EXE" --port 11434 -m "./google_gemma-4-E4B-it-Q4_K_M.gguf" \
  -c 131072 -np $CPU_CORES -t $CPU_CORES \
  -b 2048 -ub 512 \
  --flash-attn on --cont-batching \
  -ctk q8_0 -ctv q8_0 > /dev/null 2>&1 &


echo ""
echo "[3/5] Starting llama.cpp Embedding Server (Port 11435)..."
nohup "$LLAMA_SERVER_EXE" --port 11435 -m "./nomic-embed-text-v1.5.f16.gguf" -t 2 --embedding > /dev/null 2>&1 &

echo ""
echo "[4/5] Starting Docker Database Service (ShaktiDB)..."
docker start shakthidb_service >/dev/null 2>&1 || docker-compose -f docker-compose.yml -f docker-compose.local-db.yml up -d shakthidb

echo ""
echo "Waiting 12 seconds for models to load in RAM..."
sleep 12

echo ""
echo "[5/5] Launching Local API Server & Web Dashboard..."
export LLM_BACKEND=llama.cpp
export EMBEDDING_HOST=http://127.0.0.1:11435
export OLLAMA_KEEP_ALIVE=24h
export OLLAMA_NUM_PARALLEL=4
export OLLAMA_MAX_LOADED_MODELS=3

open http://127.0.0.1:8000/
python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000

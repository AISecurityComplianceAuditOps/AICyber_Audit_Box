#!/bin/bash
# AICyberAuditBox 1-Click macOS Application Launcher
# Works natively on Apple Silicon (M1/M2/M3/M4) and Intel Macs

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "==================================================="
echo "  🚀 Starting AICyberAuditBox macOS Engine..."
echo "==================================================="
echo ""

# 1. Start Python API Backend in background
echo "[1/2] Launching API Server on http://localhost:8000 ..."
export LLM_BACKEND=llama.cpp
python3 -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 > /dev/null 2>&1 &
API_PID=$!

sleep 3

# 2. Open Web Dashboard in Default Browser
echo "[2/2] Opening Web Dashboard in default browser..."
open http://localhost:8000

echo ""
echo "✅ System is running natively on macOS! Press Ctrl+C to close."
wait $API_PID

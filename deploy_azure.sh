#!/bin/bash
# ==============================================================================
# AICyber_Audit_Box - Automated Azure VM Deployment Script
# Target Public IP: 20.41.233.247
# ==============================================================================
set -e

echo "=========================================================="
echo "  Deploying AICyber_Audit_Box to Azure VM (20.41.233.247)"
echo "=========================================================="

APP_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$APP_DIR"

# 1. Update system packages
echo "[1/6] Updating system packages & installing prerequisites..."
sudo apt-get update -y
sudo apt-get install -y python3 python3-pip python3-venv git curl docker.io ufw build-essential libpq-dev

# 2. Configure Docker
echo "[2/6] Configuring Docker service..."
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER" || true

# Start or restart PostgreSQL (ShaktiDB) Docker container on port 15234
echo "[3/6] Starting PostgreSQL Database container (Port 15234)..."
sudo docker rm -f shakthidb_service 2>/dev/null || true
sudo docker run -d \
  --name shakthidb_service \
  -e POSTGRES_PASSWORD=ShakthiDB@2026 \
  -e POSTGRES_DB=shakthidb \
  -p 15234:5432 \
  -v audittest_box_pgdata:/var/lib/postgresql/data \
  --restart always \
  postgres:15-alpine

# 3. Setup Python Virtual Environment
echo "[4/6] Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 4. Create local directories
mkdir -p data/inventory data/evidence data/reports logs

# 5. Configure Firewall / UFW
echo "[5/6] Ensuring port 8000 and 22 are open on OS firewall..."
sudo ufw allow 22/tcp || true
sudo ufw allow 8000/tcp || true
sudo ufw --force enable || true

# 6. Configure Systemd Service
echo "[6/6] Creating systemd service for 24/7 background operation..."
CURRENT_USER="$USER"
SERVICE_FILE="/etc/systemd/system/aicyberauditbox.service"

sudo bash -c "cat <<EOF > $SERVICE_FILE
[Unit]
Description=AICyber_Audit_Box Web Service
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$APP_DIR
Environment=\"PATH=$APP_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"
Environment=\"PYTHONPATH=$APP_DIR\"
Environment=\"REQUIRE_POSTGRES=true\"
ExecStart=$APP_DIR/venv/bin/uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF"

sudo systemctl daemon-reload
sudo systemctl enable aicyberauditbox.service
sudo systemctl restart aicyberauditbox.service

echo "=========================================================="
echo "  DEPLOYMENT COMPLETE!"
echo "  Status: active"
echo "  Public URL: http://20.41.233.247:8000/"
echo "=========================================================="
echo "To check live logs: sudo journalctl -u aicyberauditbox -f"

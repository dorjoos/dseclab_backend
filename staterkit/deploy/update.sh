#!/bin/bash
# D-SECLAB Update Script
# Run as root: sudo bash deploy/update.sh
set -e

APP_DIR="/opt/dseclab"
APP_USER="dseclab"

echo "=== Updating D-SECLAB ==="

cd "$APP_DIR"

# Pull latest
echo "[1/4] Pulling latest code..."
sudo -u "$APP_USER" git pull

# Update dependencies
echo "[2/4] Updating dependencies..."
sudo -u "$APP_USER" venv/bin/pip install -r requirements.txt -q

# Run migrations
echo "[3/4] Running migrations..."
sudo -u "$APP_USER" bash -c "source /opt/dseclab/.env && cd /opt/dseclab && venv/bin/flask db upgrade"

# Restart
echo "[4/4] Restarting service..."
systemctl restart dseclab

echo ""
echo "=== Update Complete ==="
systemctl status dseclab --no-pager -l

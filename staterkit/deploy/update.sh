#!/bin/bash
# D-SECLAB Update Script
# Run as root: sudo bash /opt/dseclab/deploy/update.sh
set -e

REPO_DIR="/opt/dseclab-repo"
APP_DIR="/opt/dseclab"
APP_USER="dseclab"

echo "=== Updating D-SECLAB ==="

# Pull latest from repo root
cd "$REPO_DIR"

echo "[1/4] Pulling latest code..."
sudo -u "$APP_USER" git pull

# Update dependencies
echo "[2/4] Updating dependencies..."
cd "$APP_DIR"
sudo -u "$APP_USER" venv/bin/pip install -r requirements.txt -q

# Run migrations
echo "[3/4] Running migrations..."
sudo -u "$APP_USER" bash -c "set -a && source $APP_DIR/.env && set +a && cd $APP_DIR && venv/bin/flask db upgrade"

# Restart
echo "[4/4] Restarting service..."
systemctl restart dseclab

echo ""
echo "=== Update Complete ==="
systemctl status dseclab --no-pager -l

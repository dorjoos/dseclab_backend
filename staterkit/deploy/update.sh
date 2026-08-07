#!/bin/bash
# D-SECLAB Update Script
# Run as root: sudo bash /opt/dseclab/deploy/update.sh
set -e

REPO_DIR="/opt/dseclab-repo"
APP_DIR="/opt/dseclab"
APP_USER="dseclab"

# Run a command as the app user with .env loaded, from the app directory.
as_app() {
    sudo -u "$APP_USER" bash -c "set -a && source $APP_DIR/.env && set +a && cd $APP_DIR && $1"
}

echo "=== Updating D-SECLAB ==="

# Pull latest from repo root
cd "$REPO_DIR"

echo "[1/5] Pulling latest code..."
sudo -u "$APP_USER" git pull

# Update dependencies
echo "[2/5] Updating dependencies..."
cd "$APP_DIR"
sudo -u "$APP_USER" venv/bin/pip install -r requirements.txt -q

# Alembic revisions, when the server has any. `flask db upgrade` applies
# revisions but never generates them, so a new model column reaches no server
# through this step alone — that is what ensure-schema below is for.
echo "[3/5] Running migrations..."
if [ -d "$APP_DIR/migrations" ]; then
    as_app "venv/bin/flask db upgrade"
else
    echo "  no migrations/ directory; skipping alembic"
fi

# Additive schema changes: creates missing tables and adds missing columns.
# Idempotent, and never drops or alters anything that already exists, so it is
# safe to run on every deploy.
echo "[4/5] Ensuring schema is current..."
as_app "venv/bin/flask dseclab ensure-schema"

# Restart
echo "[5/5] Restarting service..."
systemctl restart dseclab

echo ""
echo "=== Update Complete ==="
systemctl status dseclab --no-pager -l

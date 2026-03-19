#!/bin/bash
# D-SECLAB Production Setup Script for Ubuntu 24.04
# Run as root: sudo bash deploy/setup.sh
set -e

REPO_DIR="/opt/dseclab-repo"
APP_DIR="/opt/dseclab"
APP_USER="dseclab"
REPO_URL="https://github.com/dorjoos/dseclab_backend.git"

echo "=== D-SECLAB Production Setup ==="

# 1. System packages
echo "[1/9] Installing system packages..."
apt update && apt upgrade -y
apt install -y python3 python3-pip python3-venv python3-dev \
    postgresql postgresql-contrib \
    nginx certbot python3-certbot-nginx \
    git curl build-essential libpq-dev

# 2. Create app user
echo "[2/9] Creating app user..."
if ! id "$APP_USER" &>/dev/null; then
    useradd -r -m -s /bin/bash "$APP_USER"
fi

# 3. PostgreSQL setup
echo "[3/9] Setting up PostgreSQL..."
sudo -u postgres psql -c "CREATE USER dseclab WITH PASSWORD 'CHANGE_ME_DB_PASSWORD';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE dseclab OWNER dseclab;" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE dseclab TO dseclab;" 2>/dev/null || true

# 4. Set up app directory
echo "[4/9] Setting up application..."
if [ ! -d "$REPO_DIR" ]; then
    git clone "$REPO_URL" "$REPO_DIR"
fi
chown -R "$APP_USER":"$APP_USER" "$REPO_DIR"

# Symlink staterkit/ as the app directory
ln -sfn "$REPO_DIR/staterkit" "$APP_DIR"

# 5. Python environment
echo "[5/9] Setting up Python environment..."
cd "$APP_DIR"
sudo -u "$APP_USER" python3 -m venv venv
sudo -u "$APP_USER" venv/bin/pip install --upgrade pip
sudo -u "$APP_USER" venv/bin/pip install -r requirements.txt
sudo -u "$APP_USER" venv/bin/pip install gunicorn eventlet

# 6. Environment file
echo "[6/9] Setting up environment..."
if [ ! -f "$APP_DIR/.env" ]; then
    cp deploy/.env.production "$APP_DIR/.env"
    chown "$APP_USER":"$APP_USER" "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    echo ">>> IMPORTANT: Edit $APP_DIR/.env with your actual secrets!"
fi

# 7. Database migration
echo "[7/9] Running database migrations..."
cd "$APP_DIR"
sudo -u "$APP_USER" bash -c "set -a && source $APP_DIR/.env && set +a && cd $APP_DIR && venv/bin/flask db upgrade"

# 8. Log directory
mkdir -p /var/log/dseclab
chown "$APP_USER":"$APP_USER" /var/log/dseclab

# 9. Systemd service
echo "[8/9] Setting up systemd service..."
cp deploy/dseclab.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable dseclab
systemctl start dseclab

# 10. Nginx
echo "[9/9] Setting up Nginx..."
cp deploy/nginx.conf /etc/nginx/sites-available/dseclab
ln -sf /etc/nginx/sites-available/dseclab /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit $APP_DIR/.env with your actual secrets"
echo "  2. Run: sudo systemctl restart dseclab"
echo "  3. Test: curl http://YOUR_SERVER_IP"
echo ""

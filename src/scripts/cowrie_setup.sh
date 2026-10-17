#!/bin/bash
# ===================================================================
# UniSec-Edge: Bare Metal Cowrie Honeypot Setup Script
# ===================================================================
# Run once on the Raspberry Pi as root:
#   sudo bash src/scripts/cowrie_setup.sh
# ===================================================================

set -e

COWRIE_USER="cowrie-runner"
COWRIE_HOME="/opt/cowrie"
LOG_DIR="/var/log/cowrie"
PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

echo "======================================================"
echo "  UniSec-Edge  |  Cowrie Bare Metal Setup"
echo "======================================================"

# ── Guard: must be root ──────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root: sudo bash $0"
    exit 1
fi

echo "[*] Step 1: Installing system dependencies..."
apt-get update -qq
apt-get install -y \
    git python3 python3-pip python3-venv \
    libssl-dev libffi-dev build-essential \
    libpython3-dev python3-minimal \
    authbind virtualenv 2>/dev/null || true
echo "[+] Dependencies installed."

echo "[*] Step 2: Creating restricted 'cowrie-runner' user..."
if id "$COWRIE_USER" &>/dev/null; then
    echo "[i] User '$COWRIE_USER' already exists. Skipping."
else
    useradd -r -s /bin/false -d $COWRIE_HOME -m $COWRIE_USER
    echo "[+] User '$COWRIE_USER' created with no shell and no sudo."
fi

echo "[*] Step 3: Setting up Cowrie directory..."
if [ ! -d "$COWRIE_HOME/cowrie-git" ]; then
    git clone --depth=1 https://github.com/cowrie/cowrie.git $COWRIE_HOME/cowrie-git
    echo "[+] Cowrie cloned to $COWRIE_HOME/cowrie-git"
else
    echo "[i] Cowrie already cloned. Skipping."
fi

echo "[*] Step 4: Setting up Python virtual environment..."
if [ ! -d "$COWRIE_HOME/cowrie-env" ]; then
    python3 -m venv $COWRIE_HOME/cowrie-env
    $COWRIE_HOME/cowrie-env/bin/pip install --upgrade pip -q
    $COWRIE_HOME/cowrie-env/bin/pip install -r $COWRIE_HOME/cowrie-git/requirements.txt -q
    echo "[+] Python venv created and dependencies installed."
else
    echo "[i] Virtual environment already exists. Skipping."
fi

echo "[*] Step 5: Setting up log directory..."
mkdir -p $LOG_DIR
# Create symlink so GUI parser can find logs at expected path
ln -sf $LOG_DIR $PROJECT_DIR/docker/cowrie/log 2>/dev/null || true
echo "[+] Log directory: $LOG_DIR"

echo "[*] Step 6: Writing Cowrie configuration..."
mkdir -p $COWRIE_HOME/cowrie-git/etc

cat > $COWRIE_HOME/cowrie-git/etc/cowrie.cfg << 'COWRIE_CFG'
[honeypot]
hostname = SOHO-Router
listen_endpoints = tcp:2200:interface=0.0.0.0

[ssh]
enabled = true
version = SSH-2.0-OpenSSH_8.4p1 Debian-5
auth_class = UserDB

[output_jsonlog]
enabled = true
logfile = /var/log/cowrie/cowrie.json

[output_textlog]
enabled = true
logfile = /var/log/cowrie/cowrie.log
COWRIE_CFG

echo "[*] Step 7: Writing userdb (specific credentials for demo)..."
cat > $COWRIE_HOME/cowrie-git/etc/userdb.txt << 'USERDB'
admin:0:administrator
root:x:!
USERDB

echo "[*] Step 8: Setting ownership — cowrie-runner owns everything..."
chown -R $COWRIE_USER:$COWRIE_USER $COWRIE_HOME
chown -R $COWRIE_USER:$COWRIE_USER $LOG_DIR
# GUI (running as pi/kali) needs to READ the logs
chmod 755 $LOG_DIR
chmod 644 $LOG_DIR/*.json 2>/dev/null || true

echo "[*] Step 9: Allowing cowrie-runner to bind port 2200 (authbind)..."
touch /etc/authbind/byport/2200
chown $COWRIE_USER /etc/authbind/byport/2200
chmod 500 /etc/authbind/byport/2200

echo "[*] Step 10: Creating systemd service..."
cat > /etc/systemd/system/cowrie.service << SYSTEMD_UNIT
[Unit]
Description=UniSec-Edge Cowrie Honeypot (Bare Metal)
After=network.target
Documentation=https://github.com/JUST-CyberSec-UniSec-Edge/UniSec-Edge

[Service]
Type=simple
User=$COWRIE_USER
Group=$COWRIE_USER
WorkingDirectory=$COWRIE_HOME/cowrie-git
ExecStart=$COWRIE_HOME/cowrie-env/bin/python3 bin/cowrie start -n
ExecStop=$COWRIE_HOME/cowrie-env/bin/python3 bin/cowrie stop
Restart=on-failure
RestartSec=5s

# ── Security Hardening ──────────────────────────────────
# These settings enforce the least-privilege model:
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$COWRIE_HOME $LOG_DIR
PrivateTmp=true
PrivateDevices=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
SYSTEMD_UNIT

echo "[*] Step 11: Enabling and starting Cowrie service..."
systemctl daemon-reload
systemctl enable cowrie
systemctl start cowrie
sleep 3

echo ""
echo "======================================================"
if systemctl is-active --quiet cowrie; then
    echo "[✔] Cowrie is RUNNING as restricted user '$COWRIE_USER'"
    echo "[✔] SSH Honeypot listening on port 2200"
    echo "[✔] Logs: $LOG_DIR/cowrie.json"
    echo "[✔] systemctl status cowrie"
else
    echo "[!] Cowrie failed to start. Check: journalctl -u cowrie -n 30"
fi
echo "======================================================"
echo ""
echo "Test with: ssh root@localhost -p 2200"
echo "View logs: sudo tail -f $LOG_DIR/cowrie.json"
echo "GUI reads: $PROJECT_DIR/docker/cowrie/log/cowrie.json"
echo "======================================================"

#!/bin/bash
# ===================================================================
# UniSec-Edge: Auto-Start on Boot Setup (systemd)
# ===================================================================
# Run once: sudo bash src/scripts/autostart_setup.sh
# ===================================================================

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CURRENT_USER=$(logname 2>/dev/null || echo "${SUDO_USER:-pi}")

echo "======================================================"
echo "  UniSec-Edge  |  Auto-Start Setup"
echo "  Project: $PROJECT_DIR"
echo "  User:    $CURRENT_USER"
echo "======================================================"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root: sudo bash $0"
    exit 1
fi

# ── 1. Docker infrastructure service ─────────────────────
echo "[*] Creating Docker infrastructure service..."
cat > /etc/systemd/system/unisec-docker.service << DOCKER_UNIT
[Unit]
Description=UniSec-Edge Docker Infrastructure
After=docker.service network-online.target
Requires=docker.service
Documentation=https://github.com/JUST-CyberSec-UniSec-Edge/UniSec-Edge

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$PROJECT_DIR/docker
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
DOCKER_UNIT

# ── 2. Bridge setup service ───────────────────────────────
echo "[*] Creating network bridge service..."
cat > /etc/systemd/system/unisec-bridge.service << BRIDGE_UNIT
[Unit]
Description=UniSec-Edge Network Bridge Setup
After=network.target
Before=unisec-docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash $PROJECT_DIR/src/scripts/bridge_setup.sh

[Install]
WantedBy=multi-user.target
BRIDGE_UNIT

# ── 3. Enable all services ────────────────────────────────
echo "[*] Enabling services..."
systemctl daemon-reload
systemctl enable cowrie
systemctl enable unisec-docker
systemctl enable unisec-bridge

echo ""
echo "======================================================"
echo "[✔] Auto-start configured! Services enabled:"
echo "    cowrie         → Honeypot (bare metal)"
echo "    unisec-docker  → Suricata + Tor + ClamAV"
echo "    unisec-bridge  → Network bridge + iptables"
echo ""
echo "[✔] On next boot everything starts automatically."
echo ""
echo "Manual control:"
echo "  sudo systemctl start|stop|status cowrie"
echo "  sudo systemctl start|stop|status unisec-docker"
echo "======================================================"

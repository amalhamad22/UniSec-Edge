#!/bin/bash
# ===================================================================
# UniSec-Edge: Network Bridging & Firewall (Iptables) Setup
# ===================================================================
# Run on boot: sudo bash src/scripts/bridge_setup.sh
# ===================================================================

set -e

WAN_IF="eth0"       # Built-in Pi port  (WAN / ISP side)
LAN_IF="eth0"       # USB adapter       (LAN / SOHO router side)
BRIDGE_NAME="br0"

echo "======================================================"
echo "  UniSec-Edge  |  Bridge & Firewall Initialisation"
echo "======================================================"

# ── Guard: must be root ──────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root."
    exit 1
fi

# ── 1. IP Forwarding ────────────────────────────────────
sysctl -w net.ipv4.ip_forward=1 > /dev/null
echo "[+] IP Forwarding enabled."

# ── 2. Create Bridge ────────────────────────────────────
# Destroy any existing bridge to start clean
if ip link show $BRIDGE_NAME &>/dev/null; then
    ip link set dev $BRIDGE_NAME down
    ip link delete $BRIDGE_NAME type bridge
fi

ip link add name $BRIDGE_NAME type bridge
ip link set dev $WAN_IF master $BRIDGE_NAME
ip link set dev $LAN_IF master $BRIDGE_NAME
ip link set dev $WAN_IF up
ip link set dev $LAN_IF up
ip link set dev $BRIDGE_NAME up
dhclient $BRIDGE_NAME &
echo "[+] Bridge ($BRIDGE_NAME) created: $WAN_IF <-> $LAN_IF"

# ── 3. Flush existing iptables rules ────────────────────
iptables -F
iptables -t nat -F
iptables -t mangle -F
echo "[+] Existing iptables rules flushed."

# ── 4. Base firewall rules ──────────────────────────────

# Allow established/related connections
iptables -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH to the dashboard (management)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow Tor SOCKS proxy (Docker manages port 9050)
iptables -A INPUT -p tcp --dport 9050 -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Forward traffic across the bridge
iptables -A FORWARD -i $BRIDGE_NAME -j ACCEPT

echo "[+] Base firewall rules applied."

# ── 5. Tor selective routing template ──────────────────
# The Python GUI will dynamically add rules like:
#   iptables -t nat -A PREROUTING -m mac --mac-source <MAC> -p tcp -j REDIRECT --to-ports 9050
echo "[i] Tor routing rules are managed dynamically by the GUI."

# ── 6. Panic-button / IDS block template ───────────────
# The Python GUI can block a hacker with:
#   iptables -I FORWARD -m mac --mac-source <HACKER_MAC> -j DROP
echo "[i] Dynamic threat blocking ready (managed by IDS tab)."

echo ""
echo "[✔] UniSec-Edge is armed and routing traffic!"
echo "======================================================"

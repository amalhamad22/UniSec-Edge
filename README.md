# 🛡️ UniSec-Edge

**Unified Edge-Based Security Framework for SOHO Networks**

> Jordan University of Science and Technology (JUST) — Capstone Project 2025/2026
> Team Glitch | Supervisor: Dr. Hala Hamadeh

---

## 🏗️ System Architecture

UniSec-Edge runs on a **Raspberry Pi 5** acting as a transparent network bridge between the ISP modem and the SOHO router. It integrates four security layers:

| Layer | Tool | Deployment | Function |
|---|---|---|---|
| Intrusion Detection | Suricata | Docker | Deep Packet Inspection & Threat Detection |
| Active Deception | Cowrie Honeypot | **Bare Metal** | SSH Brute-force logging & malware capture |
| Privacy Maintenance | Tor SOCKS5 Gateway | Docker | Selective per-device anonymization |
| Physical Security | ClamAV | Docker | Automated USB malware sanitization |

> **Security Design:** Cowrie runs as a restricted `cowrie-runner` system user with no shell, no sudo, and strict systemd sandboxing. If an attacker escapes the honeypot emulator, they become a powerless system user — not root.

A custom Python GUI (CustomTkinter) allows administrators to monitor all services, view live attack logs, route devices through Tor, and scan USB drives — all from a single dashboard with auto-refresh.

---

## 🚀 Installation & Setup

### Prerequisites (Raspberry Pi OS / Kali Linux ARM64)

```bash
sudo apt update
sudo apt install -y docker.io docker-compose git python3-pip python3-venv
sudo systemctl enable docker --now
sudo usermod -aG docker $USER
newgrp docker
```

### 1. Clone the Repository

```bash
git clone https://github.com/JUST-CyberSec-UniSec-Edge/UniSec-Edge.git
cd UniSec-Edge
```

### 2. Install Cowrie Honeypot (Bare Metal — One Time Only)

```bash
sudo bash src/scripts/cowrie_setup.sh
```

This script:
- Creates a restricted `cowrie-runner` Linux user (no shell, no sudo)
- Installs Cowrie in an isolated Python virtual environment at `/opt/cowrie/`
- Configures a specific credential database for demo (`admin123`)
- Registers Cowrie as a systemd service that starts on boot
- Applies strict systemd security: `NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`

Verify Cowrie is running:
```bash
sudo systemctl status cowrie
ssh root@localhost -p 2200
```

### 3. Deploy Docker Security Infrastructure

```bash
cd docker/
docker-compose up -d
docker ps
```

Starts: Suricata IDS, Tor Gateway, ClamAV USB Sanitizer.

### 4. Configure Network Bridge (run on every boot)

```bash
sudo bash src/scripts/bridge_setup.sh
```

To make it permanent (auto-run on boot):
```bash
sudo bash src/scripts/autostart_setup.sh
```

### 5. Install Python Dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

### 6. Launch the GUI Dashboard

```bash
cd ~/UniSec-Edge
sudo python3 src/gui/main.py
```

> Run with `sudo` so the Tor Gateway tab can apply iptables rules.

---

## 📖 User Operating Manual

### Phase 1: Starting the System

Cowrie and Docker services start automatically on boot after running `autostart_setup.sh`. To start manually:

```bash
# Start Docker services
cd ~/UniSec-Edge/docker
docker-compose up -d

# Start Cowrie (if not running)
sudo systemctl start cowrie

# Launch dashboard
cd ~/UniSec-Edge
sudo python3 src/gui/main.py
```

### Phase 2: Dashboard Tab Guide

| Tab | Description |
|---|---|
| **Overview** | Live health monitor — all services with auto-refresh every 10 seconds |
| **IDS Alerts** | Suricata network alerts with severity filter (High / Medium / Low) |
| **Tor Gateway** | Route any device through Tor by entering its MAC address |
| **Honeypot** | Live SSH login attempts — attacker IP, credentials, success/fail |
| **USB Sanitizer** | Trigger ClamAV scan, view quarantined threats |
| **⚙ Settings** | Configure email alerts for real-time attack notifications |

### Phase 3: Shutting Down

```bash
# Stop Docker services
cd ~/UniSec-Edge/docker
docker-compose down

# Stop Cowrie
sudo systemctl stop cowrie
```

---

## 🧪 Attack Simulation & Testing

### Test 1 — Honeypot SSH Brute Force

```bash
# From attacker machine
hydra -l root -P /tmp/passwords.txt ssh://<PI_IP>:2200 -t 1 -V -I
```

View results in **Honeypot tab** → Refresh Logins.

### Test 2 — IDS Ping Sweep Detection

```bash
nmap -sn <PI_IP>/24
ping -c 20 -i 0.1 <PI_IP>
```

View results in **IDS Alerts tab**.

### Test 3 — USB Malware Detection

```bash
# Create EICAR test virus (harmless industry standard)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | sudo tee /media/pi/testvirus.txt
```

Click **Trigger USB Scan** in USB Sanitizer tab.

### Test 4 — Tor Anonymization

```bash
# Verify Tor is active
curl --socks5-hostname 127.0.0.1:9050 --max-time 30 https://check.torproject.org/api/ip
```

Click **Check Tor Status** in Tor Gateway tab.

---

## ⚙️ Host Configuration Notes

### SSH Port
Cowrie occupies port **2200**. Your real SSH remains on port 22. To connect to the Pi itself: `ssh user@<PI_IP>`.

### Network Interface
- **Raspberry Pi (WiFi):** Suricata monitors `wlan0`
- **Raspberry Pi (Ethernet bridge):** Change to `eth0` in `docker/suricata/etc/suricata.yaml` and `docker/docker-compose.yml`

### USB Scanning
- **Raspberry Pi:** USB drives mount at `/media/pi` (configured in docker-compose.yml)
- **VM/Testing:** Change mount to `/tmp/usb:/mnt/usb:rw`

### Internet Requirement
- Tor Gateway requires internet to connect to the Tor network
- ClamAV requires internet for daily virus signature updates

### Cowrie Log Location
- Bare metal: `/var/log/cowrie/cowrie.json`
- GUI reads from: `docker/cowrie/log/cowrie.json` (symlinked by setup script)

---

## 📁 Project Structure

```
UniSec-Edge/
├── .gitignore
├── README.md
├── requirements.txt
│
├── docker/                          # Docker Infrastructure
│   ├── docker-compose.yml           # Suricata + Tor + ClamAV
│   ├── cowrie/
│   │   ├── etc/cowrie.cfg           # Honeypot config (reference)
│   │   ├── etc/userdb.txt           # Demo credentials
│   │   └── log/                     # Symlinked to /var/log/cowrie
│   ├── suricata/
│   │   ├── etc/suricata.yaml        # IDS configuration
│   │   └── etc/custom.rules         # Custom detection rules
│   ├── tor/
│   │   └── torrc                    # Tor privacy configuration
│   └── clamav/
│       └── log/                     # Scan results
│
├── src/
│   ├── backend/
│   │   ├── parser.py                # JSON log parser for GUI
│   │   └── alerter.py               # Email alert system
│   ├── gui/
│   │   └── main.py                  # CustomTkinter dashboard
│   └── scripts/
│       ├── cowrie_setup.sh          # Bare metal Cowrie installer
│       ├── autostart_setup.sh       # systemd auto-start setup
│       ├── bridge_setup.sh          # Network bridge + iptables
│       └── usb-scan.sh              # ClamAV USB automation
│
├── tests/
│   ├── README.md                    # Attack simulation guide
│   ├── attack_sims/                 # Attack scripts
│   └── stress_tests/                # Load testing
│
└── docs/
    └── user_manual/                 # Academic documentation
```

---

## 👥 Team

| Name | ID | Role |
|---|---|---|
| Bader Alzoubi | 164364 | Lead Developer — GUI & Tor Gateway |
| Heider Musamih | 160267 | Infrastructure — Docker & Networking |
| Ahmad Hamdan | 165910 | Testing & Attack Simulations |
| Amro Alhamad | 162207 | IDS Rules & Documentation |

**Supervisor:** Dr. Hala Hamadeh

---

## 🔗 Original Repository

This project was built by **Team Glitch** at Jordan University of Science and Technology. See the original team repository and all team members here:

**[JUST-CyberSec-UniSec-Edge/UniSec-Edge](https://github.com/JUST-CyberSec-UniSec-Edge/UniSec-Edge)**

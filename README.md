# 🛡️ UniSec-Edge

**Unified Edge-Based Security Framework for SOHO Networks**

Capstone Project, B.Sc. Cybersecurity, Jordan University of Science and Technology (JUST), 2025/2026<br>
Team Glitch · Supervisor: Dr. Hala Hamadeh

> 📦 Source code: [JUST-CyberSec-UniSec-Edge/UniSec-Edge](https://github.com/JUST-CyberSec-UniSec-Edge/UniSec-Edge)<br>
> This repository is my project showcase: overview, architecture, and my contribution.

---

## 📌 The Problem

Small offices and home offices (SOHO) rarely have enterprise-grade protection. A typical consumer router offers basic NAT and a firewall, with no intrusion detection, no threat visibility, no privacy controls, and no protection against infected USB drives. Enterprise tools exist, but they are too expensive and too complex for these environments.

## 💡 The Solution

UniSec-Edge turns a **Raspberry Pi 5** into a low-cost, all-in-one security appliance. It sits as a **transparent network bridge** between the ISP modem and the SOHO router, so every packet passes through it, with no changes needed on the user's devices.

```
[ Internet ] ──> [ ISP Modem ] ──> [ Raspberry Pi 5: UniSec-Edge ] ──> [ SOHO Router ] ──> [ Devices ]
```

## 🏗️ Architecture: Four Security Layers

| Layer | Tool | Deployment | Function |
|---|---|---|---|
| Intrusion Detection | Suricata | Docker | Deep packet inspection and threat detection with custom rules |
| Active Deception | Cowrie Honeypot | Bare metal | Logs SSH brute-force attempts and captures malware |
| Privacy | Tor SOCKS5 Gateway | Docker | Selective, per-device anonymization (by MAC address) |
| Physical Security | ClamAV | Docker | Automated USB malware scanning and quarantine |

### 🔒 Security by Design

- **Honeypot isolation:** Cowrie runs as a restricted `cowrie-runner` system user with no shell and no sudo, under strict systemd sandboxing (`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`). An attacker who escapes the emulator lands as a powerless user, not root.
- **Container isolation:** Suricata, Tor, and ClamAV each run in their own Docker container.
- **Separation of real and fake SSH:** the honeypot listens on port 2200, while real administration stays on port 22.

## 🖥️ Admin Dashboard

A custom Python GUI built with **CustomTkinter** lets an administrator manage the whole system from one screen:

| Tab | What it does |
|---|---|
| Overview | Live health monitor for all services, auto-refreshing every 10 seconds |
| IDS Alerts | Suricata alerts with severity filtering (High / Medium / Low) |
| Tor Gateway | Route any device through Tor by entering its MAC address |
| Honeypot | Live SSH login attempts: attacker IP, credentials tried, success/fail |
| USB Sanitizer | Trigger ClamAV scans and view quarantined threats |
| Settings | Email alerts for real-time attack notifications |

## 🧪 Testing and Attack Simulation

Each layer is tested with a simulated attack:

| Test | Method | Verified in |
|---|---|---|
| SSH brute force | Hydra against the honeypot | Honeypot tab: attacker IP and credentials logged |
| Network reconnaissance | Nmap ping sweep and rapid ICMP | IDS Alerts tab: Suricata custom rules |
| USB malware | EICAR standard test file | USB Sanitizer tab: ClamAV detection and quarantine |
| Anonymization | Tor check API via SOCKS5 | Tor Gateway tab: Tor status check |

## 🛠️ Tech Stack

- **Hardware:** Raspberry Pi 5
- **OS:** Raspberry Pi OS / Kali Linux ARM64
- **Security:** Suricata, Cowrie, Tor, ClamAV, iptables
- **Infrastructure:** Docker, Docker Compose, systemd, Linux bridge networking
- **Software:** Python, CustomTkinter, Bash

## 👤 My Role: IDS Rules and Documentation

- Developed the **custom Suricata detection rules** used to flag reconnaissance and attack traffic on the network
- Authored the project **documentation and user operating manual**: installation, operation, dashboard guide, and testing procedures

## 👥 Team Glitch

| Name | Role |
|---|---|
| Bader Alzoubi | Lead Developer: GUI and Tor Gateway |
| Heider Musamih | Infrastructure: Docker and Networking |
| Ahmad Hamdan | Testing and Attack Simulations |
| **Amro Alhamad** | IDS Rules and Documentation |

Supervisor: **Dr. Hala Hamadeh**, Jordan University of Science and Technology

---

📫 Interested in the project? See the [full source repository](https://github.com/JUST-CyberSec-UniSec-Edge/UniSec-Edge) or reach out through my GitHub profile.

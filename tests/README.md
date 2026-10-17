# UniSec-Edge — Tests & Attack Simulations

This directory is **Ahmad's playground** for validating all security layers.

## 🧪 How to Run Each Test

### Test 1 — Suricata IDS (Ping Sweep)
From any machine on the same network as the Pi:
```bash
nmap -sn 192.168.1.0/24
```
Expected: Suricata fires `ICMP Ping Sweep Detected` in `docker/suricata/log/eve.json`

---

### Test 2 — Cowrie Honeypot (SSH Brute Force)
```bash
# Install hydra first
sudo apt install hydra -y

# Run a brute force against the Pi's port 22 (goes to Cowrie)
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<PI_IP_ADDRESS>
```
Expected: Login attempts logged in `docker/cowrie/log/cowrie.json`

---

### Test 3 — Tor Gateway Verification
On the Pi, after starting the Tor container:
```bash
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
```
Expected: `{"IsTor": true, "IP": "<tor_exit_ip>"}`

---

### Test 4 — ClamAV USB Scan
```bash
# Download a harmless test virus signature (EICAR standard test file)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /media/pi/test_virus.txt

# Trigger scan
sudo bash src/scripts/usb-scan.sh
```
Expected: `test_virus.txt` detected and moved to `QUARANTINE_AREA/`

---

### Test 5 — Network Bridge Transparency
```bash
# Verify bridge is active
brctl show
ip addr show br0
```
Expected: `br0` bridge listed with `eth0` and `eth1` as ports.

---

## 📋 Test Checklist

| Test | Tool Used | Expected Result | Status |
|------|-----------|-----------------|--------|
| Ping Sweep Detection | nmap | Suricata alert in eve.json | ⬜ |
| SSH Brute Force Logging | hydra | Login entries in cowrie.json | ⬜ |
| Tor Anonymisation | curl + check.torproject.org | IsTor: true | ⬜ |
| USB Malware Detection | EICAR test file | File quarantined | ⬜ |
| Bridge Transparency | brctl / ip | br0 bridge active | ⬜ |
| GUI Dashboard | Python | All tabs display live data | ⬜ |

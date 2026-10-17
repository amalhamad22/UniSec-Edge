"""
UniSec-Edge Log Parser
======================
Reads JSON logs from:
  - Cowrie Honeypot  (bare metal at /var/log/cowrie/ OR docker mount)
  - Suricata IDS     (Docker volume at docker/suricata/log/eve.json)
  - ClamAV           (Docker volume at docker/clamav/log/usb_scan.log)
"""

import json
import os
import re


class LogParser:
    def __init__(self):
        base_dir     = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(base_dir, "..", ".."))

        # ── Cowrie: bare metal path takes priority over docker mount ──
        BARE_METAL_COWRIE = "/opt/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
        DOCKER_COWRIE     = os.path.join(
            project_root, "docker", "cowrie", "log", "cowrie.json"
        )
        if os.path.exists(BARE_METAL_COWRIE):
            self.cowrie_log = BARE_METAL_COWRIE
        else:
            self.cowrie_log = DOCKER_COWRIE

        # ── Suricata: Docker volume ───────────────────────────────────
        self.suricata_log = os.path.join(
            project_root, "docker", "suricata", "log", "eve.json"
        )

        # ── ClamAV: Docker volume ─────────────────────────────────────
        self.clamav_log = os.path.join(
            project_root, "docker", "clamav", "log", "usb_scan.log"
        )

    # ------------------------------------------------------------------
    # Cowrie (Honeypot) — SSH login attempts
    # ------------------------------------------------------------------
    def parse_cowrie_logs(self) -> list[dict]:
        """
        Returns list of SSH login attempt dicts:
        {timestamp, attacker_ip, username_used, password_used,
         is_success, session}
        """
        attacks = []
        if not os.path.exists(self.cowrie_log):
            return attacks

        with open(self.cowrie_log, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    eid   = event.get("eventid", "")
                    if eid in ("cowrie.login.failed", "cowrie.login.success"):
                        attacks.append({
                            "timestamp":     event.get("timestamp", ""),
                            "attacker_ip":   event.get("src_ip", "unknown"),
                            "username_used": event.get("username", ""),
                            "password_used": event.get("password", ""),
                            "is_success":    eid == "cowrie.login.success",
                            "session":       event.get("session", ""),
                        })
                except (json.JSONDecodeError, KeyError):
                    continue

        return attacks

    # ------------------------------------------------------------------
    # Suricata (IDS) — Network alerts
    # ------------------------------------------------------------------
    def parse_suricata_logs(self) -> list[dict]:
        """
        Returns list of alert dicts:
        {timestamp, attacker_ip, target_ip, signature, severity,
         src_port, dest_port, proto, action, sid}
        Severity: 1=High, 2=Medium, 3=Low
        """
        alerts = []
        if not os.path.exists(self.suricata_log):
            return alerts

        with open(self.suricata_log, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") != "alert":
                        continue
                    alert_data = event.get("alert", {})
                    alerts.append({
                        "timestamp":   event.get("timestamp", ""),
                        "attacker_ip": event.get("src_ip", "unknown"),
                        "target_ip":   event.get("dest_ip", "unknown"),
                        "src_port":    event.get("src_port", ""),
                        "dest_port":   event.get("dest_port", ""),
                        "proto":       event.get("proto", ""),
                        "signature":   alert_data.get("signature", "Unknown"),
                        "category":    alert_data.get("category", ""),
                        "severity":    int(alert_data.get("severity", 3)),
                        "action":      alert_data.get("action", "allowed"),
                        "sid":         alert_data.get("signature_id", ""),
                    })
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

        return alerts

    # ------------------------------------------------------------------
    # ClamAV — USB scan summary
    # ------------------------------------------------------------------
    def parse_clamav_log(self) -> dict:
        """
        Returns summary dict from last clamscan log:
        {raw, scanned_files, infected_files, data_read, scan_time, threats}
        """
        result = {
            "raw":           "",
            "scanned_files": "—",
            "infected_files":"—",
            "data_read":     "—",
            "scan_time":     "—",
            "threats":       [],
        }
        if not os.path.exists(self.clamav_log):
            return result

        with open(self.clamav_log, "r", errors="replace") as f:
            content = f.read()
        result["raw"] = content

        patterns = {
            "scanned_files":  r"Scanned files:\s*(\d+)",
            "infected_files": r"Infected files:\s*(\d+)",
            "data_read":      r"Data scanned:\s*([\d.]+ \w+)",
            "scan_time":      r"Time:\s*([\d.]+ sec)",
        }
        for key, pattern in patterns.items():
            m = re.search(pattern, content, re.IGNORECASE)
            if m:
                result[key] = m.group(1)

        result["threats"] = [
            line.strip()
            for line in content.splitlines()
            if "FOUND" in line
        ]
        return result

    # ------------------------------------------------------------------
    # Info
    # ------------------------------------------------------------------
    def get_log_paths(self) -> dict:
        """Returns current log paths for debugging."""
        return {
            "cowrie":   self.cowrie_log,
            "suricata": self.suricata_log,
            "clamav":   self.clamav_log,
        }


# ------------------------------------------------------------------
# Self-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    parser = LogParser()
    paths  = parser.get_log_paths()
    print("[*] Log paths:")
    for k, v in paths.items():
        exists = "✔ EXISTS" if os.path.exists(v) else "✘ NOT FOUND"
        print(f"    {k:<12}: {v}  [{exists}]")

    print("\n[*] Testing Cowrie Parser…")
    attacks = parser.parse_cowrie_logs()
    print(f"    Found {len(attacks)} login attempts.")
    if attacks:
        print(f"    Latest: {attacks[-1]}")

    print("\n[*] Testing Suricata Parser…")
    alerts = parser.parse_suricata_logs()
    print(f"    Found {len(alerts)} alerts.")
    if alerts:
        print(f"    Latest: {alerts[-1]}")

    print("\n[*] Testing ClamAV Parser…")
    clamav = parser.parse_clamav_log()
    print(f"    Scanned: {clamav['scanned_files']}  "
          f"Infected: {clamav['infected_files']}")

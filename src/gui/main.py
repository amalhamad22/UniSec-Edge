import customtkinter as ctk
import tkinter as tk
import sys
import os
import subprocess
import threading
import json
from datetime import datetime
from collections import Counter

# ---------------------------------------------------------
# Dynamic Path Linking: Connect GUI to Backend
# ---------------------------------------------------------
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..', '..'))
sys.path.append(project_root)

try:
    from src.backend.parser import LogParser
except ImportError:
    print("[!] Error: Could not import LogParser. Ensure src/backend/parser.py exists.")
    sys.exit(1)

# ---------------------------------------------------------
# Helper: Run shell commands safely and return output
# ---------------------------------------------------------
def run_cmd(cmd: str) -> tuple[int, str]:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        out = (result.stdout + result.stderr).strip()
        return result.returncode, out
    except subprocess.TimeoutExpired:
        return -1, "[!] Command timed out."
    except Exception as e:
        return -1, f"[!] Error: {e}"


def docker_status(container_name: str) -> str:
    """Returns 'running', 'stopped', or 'not found'."""
    code, out = run_cmd(
        f"docker ps --filter name={container_name} --filter status=running "
        f"--format '{{{{.Names}}}}' 2>/dev/null"
    )
    if code == 0 and container_name in out:
        return "running"
    # Fallback: check if container exists but stopped
    code2, out2 = run_cmd(
        f"docker inspect --format='{{{{.State.Status}}}}' {container_name} 2>/dev/null"
    )
    if code2 == 0 and out2:
        return out2.strip().strip("'")
    return "not found"


# ---------------------------------------------------------
# GUI Application Class
# ---------------------------------------------------------
class UniSecGUI(ctk.CTk):
    CONTAINERS = {
        "Suricata IDS":     "unisec-ids",
        "Cowrie Honeypot":  "unisec-honeypot",
        "Tor SOCKS Proxy":  "unisec-tor",
        "ClamAV Sanitizer": "unisec-usb-sanitizer",
    }

    # Color palette
    CLR_GREEN  = "#00FF00"
    CLR_YELLOW = "#FFD700"
    CLR_RED    = "#FF4500"
    CLR_BLUE   = "#00BFFF"
    CLR_GREY   = "#888888"
    CLR_BTN    = "#2B2B2B"
    CLR_BTN_H  = "#3D3D3D"

    def __init__(self):
        super().__init__()

        self.title("UniSec-Edge | Unified Security Dashboard")
        self.geometry("1280x820")
        self.minsize(1100, 700)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.parser = LogParser()
        self._tor_routing_log: list[str] = []

        # Counters for smart refresh (only redraw when new data arrives)
        self._last_ids_count = -1
        self._last_hp_count  = -1

        self._build_header()
        self._build_tabs()
        self._build_overview_tab()
        self._build_ids_tab()
        self._build_tor_tab()
        self._build_honeypot_tab()
        self._build_usb_tab()
        self._build_footer()

        # Start auto-refresh loop
        self._schedule_refresh()

    # =========================================================
    # LAYOUT HELPERS
    # =========================================================
    def _btn(self, parent, text, cmd, fg=None, hv=None, **kw):
        return ctk.CTkButton(
            parent, text=text, command=cmd,
            fg_color=fg or self.CLR_BTN,
            hover_color=hv or self.CLR_BTN_H,
            **kw
        )

    def _log_box(self, parent, fg=None):
        box = tk.Text(
            parent, bg="#141414", fg=fg or self.CLR_GREEN,
            font=("Consolas", 10), bd=0, insertbackground="white",
            selectbackground="#333333"
        )
        scroll = tk.Scrollbar(parent, command=box.yview)
        box.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        box.pack(fill="both", expand=True, padx=(5, 0), pady=5)
        box.configure(state="disabled")
        return box

    def _write(self, box: tk.Text, text: str, clear=False):
        box.configure(state="normal")
        if clear:
            box.delete("1.0", tk.END)
        box.insert(tk.END, text)
        box.see(tk.END)
        box.configure(state="disabled")

    # =========================================================
    # HEADER
    # =========================================================
    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color="#0D0D0D", height=55)
        hdr.pack(fill="x", padx=0, pady=0)
        hdr.pack_propagate(False)

        ctk.CTkLabel(
            hdr, text="🛡️  UniSec-Edge  |  Unified Security Dashboard",
            font=ctk.CTkFont(size=20, weight="bold"), text_color=self.CLR_GREEN
        ).pack(side="left", padx=20, pady=10)

        # Auto-refresh indicator
        self.refresh_lbl = ctk.CTkLabel(
            hdr, text="🔄 Auto-refresh: 10s",
            font=ctk.CTkFont(size=11), text_color="#555555"
        )
        self.refresh_lbl.pack(side="right", padx=10)

        # Live clock
        self.clock_lbl = ctk.CTkLabel(
            hdr, text="", font=ctk.CTkFont(size=12), text_color=self.CLR_GREY
        )
        self.clock_lbl.pack(side="right", padx=20)
        self._tick_clock()

    def _tick_clock(self):
        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self.clock_lbl.configure(text=now)
        self.after(1000, self._tick_clock)

    # =========================================================
    # TABS
    # =========================================================
    def _build_tabs(self):
        self.tabview = ctk.CTkTabview(
            self, width=1240, height=720,
            segmented_button_fg_color="#1A1A1A",
            segmented_button_selected_color="#006400",
            segmented_button_selected_hover_color="#008000"
        )
        self.tabview.pack(padx=20, pady=(5, 0), fill="both", expand=True)
        for name in ["Overview", "IDS Alerts", "Tor Gateway", "Honeypot", "USB Sanitizer"]:
            self.tabview.add(name)
        self.tabview.set("Overview")

    # =========================================================
    # TAB 1 – OVERVIEW
    # =========================================================
    def _build_overview_tab(self):
        tab = self.tabview.tab("Overview")

        ctk.CTkLabel(
            tab, text="Live Service Health Monitor",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(15, 5))

        # Status grid
        grid = ctk.CTkFrame(tab, fg_color="#1A1A1A", corner_radius=8)
        grid.pack(fill="x", padx=20, pady=5)

        headers = ["Service", "Container", "Status", "Action"]
        for col, h in enumerate(headers):
            ctk.CTkLabel(
                grid, text=h,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=self.CLR_YELLOW
            ).grid(row=0, column=col, padx=20, pady=8, sticky="w")

        self._status_labels: dict[str, ctk.CTkLabel] = {}

        for row_idx, (svc, ctr) in enumerate(self.CONTAINERS.items(), start=1):
            ctk.CTkLabel(grid, text=svc, font=ctk.CTkFont(size=12)).grid(
                row=row_idx, column=0, padx=20, pady=6, sticky="w"
            )
            ctk.CTkLabel(grid, text=ctr, font=ctk.CTkFont(size=11),
                         text_color=self.CLR_GREY).grid(
                row=row_idx, column=1, padx=20, sticky="w"
            )
            lbl = ctk.CTkLabel(grid, text="Checking…", font=ctk.CTkFont(size=12))
            lbl.grid(row=row_idx, column=2, padx=20, sticky="w")
            self._status_labels[ctr] = lbl

            self._btn(
                grid, "▶ Start",
                lambda c=ctr: self._docker_action("start", c),
                width=90
            ).grid(row=row_idx, column=3, padx=5, pady=4)

            self._btn(
                grid, "■ Stop",
                lambda c=ctr: self._docker_action("stop", c),
                width=90
            ).grid(row=row_idx, column=4, padx=5, pady=4)

        self._btn(
            tab, "🔄  Refresh All Statuses", self._refresh_statuses,
            fg="#004d00", hv="#006600", width=220
        ).pack(pady=10)

        # Summary log
        ctk.CTkLabel(
            tab, text="System Event Log",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", padx=25)

        log_frame = ctk.CTkFrame(tab, fg_color="#141414", corner_radius=6)
        log_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self.overview_log = self._log_box(log_frame)
        self._write(self.overview_log, "[*] UniSec-Edge dashboard started.\n")

    def _docker_action(self, action: str, container: str):
        def _run():
            self._write(
                self.overview_log,
                f"[{datetime.now().strftime('%H:%M:%S')}] Running: docker {action} {container}\n"
            )
            code, out = run_cmd(f"docker {action} {container}")
            msg = f"[{'OK' if code == 0 else 'ERR'}] {out or 'Done.'}\n"
            self._write(self.overview_log, msg)
            self._refresh_statuses()
        threading.Thread(target=_run, daemon=True).start()

    def _refresh_statuses(self):
        def _run():
            for svc, ctr in self.CONTAINERS.items():
                status = docker_status(ctr)
                if status == "running":
                    color, badge = self.CLR_GREEN, "● RUNNING"
                elif status in ("exited", "stopped"):
                    color, badge = self.CLR_RED, "● STOPPED"
                else:
                    color, badge = self.CLR_YELLOW, "⚠ NOT FOUND"
                lbl = self._status_labels[ctr]
                lbl.configure(text=badge, text_color=color)

            # Show security summary in overview log
            alerts  = self.parser.parse_suricata_logs()
            attacks = self.parser.parse_cowrie_logs()
            ts = datetime.now().strftime("%H:%M:%S")
            summary = (
                f"[{ts}] Security Summary → "
                f"IDS Alerts: {len(alerts)} | "
                f"Honeypot Attempts: {len(attacks)}\n"
            )
            self._write(self.overview_log, summary)
        threading.Thread(target=_run, daemon=True).start()

    # =========================================================
    # AUTO-REFRESH SCHEDULER
    # =========================================================
    def _schedule_refresh(self):
        # Flash the refresh indicator
        self.refresh_lbl.configure(text="🔄 Refreshing...", text_color=self.CLR_GREEN)
        self.after(1000, lambda: self.refresh_lbl.configure(
            text="🔄 Auto-refresh: 10s", text_color="#555555"
        ))
        # Run all refreshes
        self._refresh_statuses()
        self._silent_ids_refresh()
        self._silent_honeypot_refresh()
        # Schedule next refresh in 10 seconds
        self.after(10000, self._schedule_refresh)

    # =========================================================
    # SILENT AUTO-REFRESH METHODS (only redraw on new data)
    # =========================================================
    def _silent_ids_refresh(self):
        def _run():
            alerts = self.parser.parse_suricata_logs()
            counts = {}
            for a in alerts:
                sev = a.get("severity", 3)
                counts[sev] = counts.get(sev, 0) + 1

            self.ids_total_lbl.configure(text=f"Total: {len(alerts)}")
            self.ids_high_lbl.configure(text=f"🔴 High: {counts.get(1, 0)}")
            self.ids_med_lbl.configure(text=f"🟠 Med: {counts.get(2, 0)}")
            self.ids_low_lbl.configure(text=f"🟡 Low: {counts.get(3, 0)}")

            # Only redraw log box if new alerts arrived
            if len(alerts) != self._last_ids_count:
                self._last_ids_count = len(alerts)
                sev_icons = {1: "🔴 HIGH", 2: "🟠 MED ", 3: "🟡 LOW "}
                self.ids_box.configure(state="normal")
                self.ids_box.delete("1.0", tk.END)
                if not alerts:
                    self.ids_box.insert(tk.END, "[*] No Suricata alerts yet.\n")
                else:
                    for a in alerts[-100:]:
                        icon = sev_icons.get(a.get("severity", 3), "⚪ INFO")
                        line = (
                            f"[{a['timestamp']}]  {icon}  "
                            f"{a['signature']}\n"
                            f"    SRC: {a['attacker_ip']:<18}  "
                            f"DST: {a['target_ip']}\n\n"
                        )
                        self.ids_box.insert(tk.END, line)
                self.ids_box.see(tk.END)
                self.ids_box.configure(state="disabled")
        threading.Thread(target=_run, daemon=True).start()

    def _silent_honeypot_refresh(self):
        def _run():
            attacks = self.parser.parse_cowrie_logs()

            # Only redraw if new attacks arrived
            if len(attacks) != self._last_hp_count:
                self._last_hp_count = len(attacks)
                success    = [a for a in attacks if a["is_success"]]
                failed     = [a for a in attacks if not a["is_success"]]
                unique_ips = len({a["attacker_ip"] for a in attacks if a.get("attacker_ip")})

                self.hp_total_lbl.configure(text=f"Total Attempts: {len(attacks)}")
                self.hp_succ_lbl.configure(text=f"✅ Success: {len(success)}")
                self.hp_fail_lbl.configure(text=f"❌ Failed: {len(failed)}")
                self.hp_uniq_lbl.configure(text=f"🌐 Unique IPs: {unique_ips}")

                self.hp_box.configure(state="normal")
                self.hp_box.delete("1.0", tk.END)

                if not attacks:
                    self.hp_box.insert(tk.END, "[*] No honeypot attacks logged yet.\n")
                else:
                    ip_counts = Counter(
                        a["attacker_ip"] for a in attacks if a.get("attacker_ip")
                    )
                    top5 = ip_counts.most_common(5)
                    self.hp_box.insert(
                        tk.END, "── Top Attacking IPs ─────────────────────────\n"
                    )
                    for ip, cnt in top5:
                        self.hp_box.insert(tk.END, f"  {ip:<20}  {cnt} attempts\n")
                    self.hp_box.insert(
                        tk.END, "\n── Last 50 Login Attempts ───────────────────\n"
                    )
                    for atk in attacks[-50:]:
                        status = "✅ SUCCESS" if atk["is_success"] else "❌ FAILED "
                        line = (
                            f"[{atk['timestamp']}]  {status}\n"
                            f"    IP:   {atk['attacker_ip']}\n"
                            f"    Cred: {atk['username_used']} / {atk['password_used']}\n\n"
                        )
                        self.hp_box.insert(tk.END, line)

                self.hp_box.see(tk.END)
                self.hp_box.configure(state="disabled")
        threading.Thread(target=_run, daemon=True).start()

    # =========================================================
    # TAB 2 – IDS ALERTS (Suricata)
    # =========================================================
    def _build_ids_tab(self):
        tab = self.tabview.tab("IDS Alerts")

        tb = ctk.CTkFrame(tab, fg_color="transparent")
        tb.pack(fill="x", padx=10, pady=8)

        self._btn(tb, "▶ Start IDS",
                  lambda: self._docker_action("start", "unisec-ids")).pack(side="left", padx=4)
        self._btn(tb, "■ Stop IDS",
                  lambda: self._docker_action("stop", "unisec-ids")).pack(side="left", padx=4)
        self._btn(tb, "🔄 Refresh Alerts", self._refresh_ids,
                  fg="#1a3a5c", hv="#1f4a73").pack(side="left", padx=4)
        self._btn(tb, "🗑 Clear View",
                  lambda: self._write(self.ids_box, "", clear=True)).pack(side="left", padx=4)

        # Severity filter
        self.ids_filter_var = ctk.StringVar(value="All")
        ctk.CTkLabel(tb, text="Filter:").pack(side="left", padx=(20, 4))
        ctk.CTkOptionMenu(
            tb, variable=self.ids_filter_var,
            values=["All", "High (1)", "Medium (2)", "Low (3)"],
            command=lambda _: self._refresh_ids(), width=130
        ).pack(side="left")

        # Stats bar
        stats_bar = ctk.CTkFrame(tab, fg_color="#1A1A1A", corner_radius=6)
        stats_bar.pack(fill="x", padx=10, pady=(0, 6))
        self.ids_total_lbl = ctk.CTkLabel(stats_bar, text="Total: 0",   text_color=self.CLR_GREY)
        self.ids_high_lbl  = ctk.CTkLabel(stats_bar, text="🔴 High: 0", text_color=self.CLR_RED)
        self.ids_med_lbl   = ctk.CTkLabel(stats_bar, text="🟠 Med: 0",  text_color=self.CLR_YELLOW)
        self.ids_low_lbl   = ctk.CTkLabel(stats_bar, text="🟡 Low: 0",  text_color=self.CLR_GREEN)
        for w in (self.ids_total_lbl, self.ids_high_lbl, self.ids_med_lbl, self.ids_low_lbl):
            w.pack(side="left", padx=15, pady=6)

        log_frame = ctk.CTkFrame(tab, fg_color="#141414", corner_radius=6)
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.ids_box = self._log_box(log_frame)
        self._write(self.ids_box, "[*] Auto-refresh active. Or click 'Refresh Alerts' manually.\n")

    def _refresh_ids(self):
        def _run():
            self._write(self.ids_box, "", clear=True)
            alerts = self.parser.parse_suricata_logs()
            fil = self.ids_filter_var.get()

            counts = {}
            filtered = []
            for a in alerts:
                sev = a.get("severity", 3)
                counts[sev] = counts.get(sev, 0) + 1
                if fil == "All":
                    filtered.append(a)
                elif fil.startswith("High") and sev == 1:
                    filtered.append(a)
                elif fil.startswith("Medium") and sev == 2:
                    filtered.append(a)
                elif fil.startswith("Low") and sev == 3:
                    filtered.append(a)

            self.ids_total_lbl.configure(text=f"Total: {len(alerts)}")
            self.ids_high_lbl.configure(text=f"🔴 High: {counts.get(1, 0)}")
            self.ids_med_lbl.configure(text=f"🟠 Med: {counts.get(2, 0)}")
            self.ids_low_lbl.configure(text=f"🟡 Low: {counts.get(3, 0)}")

            if not filtered:
                self._write(self.ids_box, "[*] No alerts match the current filter.\n")
                return

            sev_icons = {1: "🔴 HIGH", 2: "🟠 MED ", 3: "🟡 LOW "}
            for a in filtered[-100:]:
                icon = sev_icons.get(a.get("severity", 3), "⚪ INFO")
                line = (
                    f"[{a['timestamp']}]  {icon}  "
                    f"{a['signature']}\n"
                    f"    SRC: {a['attacker_ip']:<18}  DST: {a['target_ip']}\n\n"
                )
                self._write(self.ids_box, line)
        threading.Thread(target=_run, daemon=True).start()

    # =========================================================
    # TAB 3 – TOR GATEWAY
    # =========================================================
    def _build_tor_tab(self):
        tab = self.tabview.tab("Tor Gateway")

        tb = ctk.CTkFrame(tab, fg_color="transparent")
        tb.pack(fill="x", padx=10, pady=8)
        self._btn(tb, "▶ Start Tor",
                  lambda: self._docker_action("start", "unisec-tor")).pack(side="left", padx=4)
        self._btn(tb, "■ Stop Tor",
                  lambda: self._docker_action("stop", "unisec-tor")).pack(side="left", padx=4)
        self._btn(tb, "🔄 Check Tor Status", self._check_tor_status,
                  fg="#4a1a5c", hv="#5c1f73").pack(side="left", padx=4)

        # Route panel
        route_card = ctk.CTkFrame(tab, fg_color="#1A1A1A", corner_radius=8)
        route_card.pack(fill="x", padx=10, pady=8)

        ctk.CTkLabel(
            route_card,
            text="🔒  Route Device Traffic Through Tor (SOCKS5 Proxy on :9050)",
            font=ctk.CTkFont(size=13, weight="bold"), text_color=self.CLR_BLUE
        ).grid(row=0, column=0, columnspan=4, padx=15, pady=(12, 4), sticky="w")

        ctk.CTkLabel(route_card, text="MAC Address:").grid(
            row=1, column=0, padx=15, pady=8, sticky="w"
        )
        self.mac_entry = ctk.CTkEntry(
            route_card, placeholder_text="aa:bb:cc:dd:ee:ff", width=220
        )
        self.mac_entry.grid(row=1, column=1, padx=10, pady=8)

        self._btn(route_card, "➕ Add Tor Route", self._add_tor_route,
                  fg="#4a007a", hv="#5c0099", width=150).grid(row=1, column=2, padx=5)
        self._btn(route_card, "➖ Remove Tor Route", self._remove_tor_route,
                  fg="#7a004a", hv="#990059", width=160).grid(row=1, column=3, padx=5)

        ctk.CTkLabel(route_card, text="Active Tor Routes (iptables):").grid(
            row=2, column=0, columnspan=4, padx=15, pady=(8, 2), sticky="w"
        )
        self.tor_routes_box = tk.Text(
            route_card, bg="#141414", fg=self.CLR_BLUE,
            font=("Consolas", 10), height=5, bd=0
        )
        self.tor_routes_box.grid(
            row=3, column=0, columnspan=4, padx=15, pady=(0, 12), sticky="ew"
        )
        self.tor_routes_box.configure(state="disabled")
        route_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(tab, text="Tor Gateway Event Log",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=14)
        log_frame = ctk.CTkFrame(tab, fg_color="#141414", corner_radius=6)
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.tor_log = self._log_box(log_frame, fg=self.CLR_BLUE)
        self._write(
            self.tor_log,
            "[*] Tor Gateway ready. Enter a device MAC to route its traffic anonymously.\n"
        )

    def _add_tor_route(self):
        mac = self.mac_entry.get().strip()
        if not mac:
            self._write(self.tor_log, "[!] Please enter a valid MAC address.\n")
            return
        cmd = (
            f"sudo iptables -t nat -A PREROUTING "
            f"-m mac --mac-source {mac} -p tcp -j REDIRECT --to-ports 9040"
        )
        ts = datetime.now().strftime("%H:%M:%S")
        self._write(self.tor_log, f"[{ts}] Executing: {cmd}\n")
        code, out = run_cmd(cmd)
        if code == 0:
            entry = f"  ✔ {mac}  →  Tor :9050  [{ts}]"
            self._tor_routing_log.append(entry)
            self._write(self.tor_log, f"[OK] Route added for {mac}\n")
        else:
            self._write(self.tor_log,
                        f"[ERR] {out}\n[i] iptables requires root. Run with sudo.\n")
        self._refresh_tor_routes()
        self.mac_entry.delete(0, tk.END)

    def _remove_tor_route(self):
        mac = self.mac_entry.get().strip()
        if not mac:
            self._write(self.tor_log, "[!] Enter the MAC address to remove.\n")
            return
        cmd = (
            f"sudo iptables -t nat -D PREROUTING "
            f"-m mac --mac-source {mac} -p tcp -j REDIRECT --to-ports 9040"
        )
        ts = datetime.now().strftime("%H:%M:%S")
        self._write(self.tor_log, f"[{ts}] Removing route for {mac}…\n")
        code, out = run_cmd(cmd)
        status = "[OK] Route removed." if code == 0 else f"[ERR] {out}"
        self._write(self.tor_log, f"{status}\n")
        self._tor_routing_log = [r for r in self._tor_routing_log if mac not in r]
        self._refresh_tor_routes()
        self.mac_entry.delete(0, tk.END)

    def _refresh_tor_routes(self):
        self.tor_routes_box.configure(state="normal")
        self.tor_routes_box.delete("1.0", tk.END)
        if self._tor_routing_log:
            self.tor_routes_box.insert(tk.END, "\n".join(self._tor_routing_log))
        else:
            self.tor_routes_box.insert(tk.END, "  (no active routes this session)")
        self.tor_routes_box.configure(state="disabled")

    def _check_tor_status(self):
        def _run():
            self._write(self.tor_log, "[*] Checking Tor container status…\n")
            status = docker_status("unisec-tor")
            self._write(self.tor_log, f"[i] Container: unisec-tor  →  {status.upper()}\n")
            code, out = run_cmd(
                "curl --socks5 127.0.0.1:9050 --max-time 10 "
                "https://check.torproject.org/api/ip 2>&1"
            )
            if code == 0 and "IsTor" in out:
                try:
                    data   = json.loads(out)
                    is_tor = data.get("IsTor", False)
                    ip     = data.get("IP", "unknown")
                    msg    = f"[✔] Tor is active.  Exit IP: {ip}  |  IsTor: {is_tor}\n"
                except Exception:
                    msg = f"[✔] Tor responded.  Raw: {out[:120]}\n"
            else:
                msg = "[!] Could not reach Tor SOCKS proxy. Is the container running?\n"
            self._write(self.tor_log, msg)
        threading.Thread(target=_run, daemon=True).start()

    # =========================================================
    # TAB 4 – HONEYPOT (Cowrie)
    # =========================================================
    def _build_honeypot_tab(self):
        tab = self.tabview.tab("Honeypot")

        tb = ctk.CTkFrame(tab, fg_color="transparent")
        tb.pack(fill="x", padx=10, pady=8)
        self._btn(tb, "▶ Start Cowrie",
                  lambda: self._docker_action("start", "unisec-honeypot")).pack(side="left", padx=4)
        self._btn(tb, "■ Stop Cowrie",
                  lambda: self._docker_action("stop", "unisec-honeypot")).pack(side="left", padx=4)
        self._btn(tb, "🔄 Refresh Logins", self._refresh_honeypot,
                  fg="#5c1a00", hv="#7a2200").pack(side="left", padx=4)
        self._btn(tb, "🗑 Clear View",
                  lambda: self._write(self.hp_box, "", clear=True)).pack(side="left", padx=4)

        # Stats bar
        stats_bar = ctk.CTkFrame(tab, fg_color="#1A1A1A", corner_radius=6)
        stats_bar.pack(fill="x", padx=10, pady=(0, 6))
        self.hp_total_lbl = ctk.CTkLabel(stats_bar, text="Total Attempts: 0",
                                          text_color=self.CLR_GREY)
        self.hp_succ_lbl  = ctk.CTkLabel(stats_bar, text="✅ Success: 0",
                                          text_color=self.CLR_GREEN)
        self.hp_fail_lbl  = ctk.CTkLabel(stats_bar, text="❌ Failed: 0",
                                          text_color=self.CLR_RED)
        self.hp_uniq_lbl  = ctk.CTkLabel(stats_bar, text="🌐 Unique IPs: 0",
                                          text_color=self.CLR_YELLOW)
        for w in (self.hp_total_lbl, self.hp_succ_lbl, self.hp_fail_lbl, self.hp_uniq_lbl):
            w.pack(side="left", padx=15, pady=6)

        log_frame = ctk.CTkFrame(tab, fg_color="#141414", corner_radius=6)
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.hp_box = self._log_box(log_frame, fg=self.CLR_RED)
        self._write(self.hp_box, "[*] Auto-refresh active. Or click 'Refresh Logins' manually.\n")

    def _refresh_honeypot(self):
        def _run():
            self._write(self.hp_box, "", clear=True)
            attacks = self.parser.parse_cowrie_logs()

            if not attacks:
                self._write(self.hp_box, "[*] No honeypot attacks logged yet.\n")
                return

            success    = [a for a in attacks if a["is_success"]]
            failed     = [a for a in attacks if not a["is_success"]]
            unique_ips = len({a["attacker_ip"] for a in attacks if a.get("attacker_ip")})

            self.hp_total_lbl.configure(text=f"Total Attempts: {len(attacks)}")
            self.hp_succ_lbl.configure(text=f"✅ Success: {len(success)}")
            self.hp_fail_lbl.configure(text=f"❌ Failed: {len(failed)}")
            self.hp_uniq_lbl.configure(text=f"🌐 Unique IPs: {unique_ips}")

            ip_counts = Counter(a["attacker_ip"] for a in attacks if a.get("attacker_ip"))
            top5 = ip_counts.most_common(5)
            self._write(self.hp_box, "── Top Attacking IPs ─────────────────────────\n")
            for ip, cnt in top5:
                self._write(self.hp_box, f"  {ip:<20}  {cnt} attempts\n")
            self._write(self.hp_box, "\n── Last 50 Login Attempts ───────────────────\n")

            for atk in attacks[-50:]:
                status = "✅ SUCCESS" if atk["is_success"] else "❌ FAILED "
                line = (
                    f"[{atk['timestamp']}]  {status}\n"
                    f"    IP:   {atk['attacker_ip']}\n"
                    f"    Cred: {atk['username_used']} / {atk['password_used']}\n\n"
                )
                self._write(self.hp_box, line)
        threading.Thread(target=_run, daemon=True).start()

    # =========================================================
    # TAB 5 – USB SANITIZER (ClamAV)
    # =========================================================
    def _build_usb_tab(self):
        tab = self.tabview.tab("USB Sanitizer")

        tb = ctk.CTkFrame(tab, fg_color="transparent")
        tb.pack(fill="x", padx=10, pady=8)
        self._btn(tb, "▶ Start ClamAV",
                  lambda: self._docker_action("start", "unisec-usb-sanitizer")).pack(side="left", padx=4)
        self._btn(tb, "■ Stop ClamAV",
                  lambda: self._docker_action("stop", "unisec-usb-sanitizer")).pack(side="left", padx=4)
        self._btn(tb, "🔍 Trigger USB Scan", self._trigger_usb_scan,
                  fg="#8B0000", hv="#A52A2A").pack(side="left", padx=4)
        self._btn(tb, "📋 Load Last Log", self._load_usb_log,
                  fg="#1a3a00", hv="#254d00").pack(side="left", padx=4)

        # Stats bar
        stats_bar = ctk.CTkFrame(tab, fg_color="#1A1A1A", corner_radius=6)
        stats_bar.pack(fill="x", padx=10, pady=(0, 6))
        self.usb_status_lbl  = ctk.CTkLabel(stats_bar, text="Last Scan: —",
                                              text_color=self.CLR_GREY)
        self.usb_scanned_lbl = ctk.CTkLabel(stats_bar, text="Files Scanned: —",
                                              text_color=self.CLR_YELLOW)
        self.usb_threat_lbl  = ctk.CTkLabel(stats_bar, text="Threats Found: —",
                                              text_color=self.CLR_RED)
        for w in (self.usb_status_lbl, self.usb_scanned_lbl, self.usb_threat_lbl):
            w.pack(side="left", padx=15, pady=6)

        ctk.CTkLabel(
            tab,
            text="ClamAV Scan Output  (docker/clamav/log/usb_scan.log)",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(anchor="w", padx=14)

        log_frame = ctk.CTkFrame(tab, fg_color="#141414", corner_radius=6)
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.usb_box = self._log_box(log_frame)
        self._write(self.usb_box, "[*] Insert a USB drive, then click 'Trigger USB Scan'.\n")

    def _trigger_usb_scan(self):
        def _run():
            self._write(self.usb_box,
                        "[*] Starting ClamAV scan inside Docker container…\n", clear=True)
            script = os.path.join(project_root, "src", "scripts", "usb-scan.sh")
            code, out = run_cmd(f"sudo bash {script}")
            self._write(self.usb_box, out + "\n")
            self.after(2000, self._load_usb_log)  # Wait 2s then load the log
        threading.Thread(target=_run, daemon=True).start()

    def _load_usb_log(self):
        log_path = os.path.join(
            project_root, "docker", "clamav", "log", "usb_scan.log"
        )
        if not os.path.exists(log_path):
            self._write(
                self.usb_box,
                "[!] Log file not found yet.\n    Run a scan first.\n", clear=True
            )
            return
            
        with open(log_path, "r") as f:
            content = f.read()
            
        # 1. Print the log to the text box
        self._write(self.usb_box, content, clear=True)
        
        # 2. Parse the text to update the top stats bar
        import re
        scanned_match = re.search(r"Scanned files:\s*(\d+)", content)
        infected_match = re.search(r"Infected files:\s*(\d+)", content)
        time_match = re.search(r"Time:\s*(.*)", content)
        
        if time_match:
            self.usb_status_lbl.configure(text=f"Last Scan: {time_match.group(1)}")
            
        if scanned_match:
            self.usb_scanned_lbl.configure(text=f"Files Scanned: {scanned_match.group(1)}")
            
        if infected_match:
            threats = int(infected_match.group(1))
            if threats > 0:
                # Make it visibly red for the video if threats are found
                self.usb_threat_lbl.configure(text=f"Threats Found: {threats}", text_color="#FF0000") 
            else:
                # Green if clean
                self.usb_threat_lbl.configure(text=f"Threats Found: {threats}", text_color="#00FF00")

    # =========================================================
    # FOOTER
    # =========================================================
    def _build_footer(self):
        ftr = ctk.CTkFrame(self, height=28, fg_color="#0D0D0D")
        ftr.pack(fill="x", side="bottom")
        ftr.pack_propagate(False)
        ctk.CTkLabel(
            ftr,
            text="UniSec-Edge v1.0  |  Jordan University of Science and Technology  |  Team Glitch",
            font=ctk.CTkFont(size=10), text_color=self.CLR_GREY
        ).pack(side="left", padx=15)
        ctk.CTkLabel(
            ftr, text="Supervisor: Dr. Hala Hamadeh",
            font=ctk.CTkFont(size=10), text_color=self.CLR_GREY
        ).pack(side="right", padx=15)


# ---------------------------------------------------------
# Entry Point
# ---------------------------------------------------------
if __name__ == "__main__":
    app = UniSecGUI()
    app.mainloop()

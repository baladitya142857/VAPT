"""
Module 2 – Scanning
Network & service scanning:
  • TCP Port Scanner (common / full / custom range)
  • UDP Port Scanner
  • Service/Banner Detection
  • OS Fingerprinting (TTL-based)
  • Web directory brute-force
  • Default credential check (FTP, SSH hints)
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import socket
import ssl
import time
import struct
import re
import urllib.request
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from gui.theme import COLORS, FONTS
from gui.widgets import (
    TerminalOutput, make_button, make_entry, section_header,
)
from utils.session import session

# ── Well-known ports ──────────────────────────────────────────────────────────
TOP_100_PORTS = [
    21,22,23,25,53,80,81,110,111,119,135,139,143,194,443,
    445,500,512,513,514,993,995,1080,1194,1433,1521,1723,
    2049,2181,2375,3306,3389,3690,4369,5432,5672,5900,
    6379,6443,7077,7180,8080,8081,8443,8888,9000,9090,
    9200,10000,11211,27017,27018,50070,50075,
]

KNOWN_SERVICES = {
    21: "FTP",       22: "SSH",       23: "Telnet",   25: "SMTP",
    53: "DNS",       80: "HTTP",      110: "POP3",    111: "RPC",
    135: "MSRPC",   139: "NetBIOS",  143: "IMAP",    389: "LDAP",
    443: "HTTPS",   445: "SMB",      993: "IMAPS",   995: "POP3S",
    1433: "MSSQL", 1521: "Oracle",  2375: "Docker",  3306: "MySQL",
    3389: "RDP",   4369: "AMQP",    5432: "PostgreSQL", 5672: "RabbitMQ",
    5900: "VNC",   6379: "Redis",   6443: "K8s API", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 50070: "Hadoop NN",
}


class ScanningModule:
    def __init__(self, parent, update_status, refresh_sidebar):
        self.update_status   = update_status
        self.refresh_sidebar = refresh_sidebar
        self.frame = tk.Frame(parent, bg=COLORS["bg_dark"])
        self._running = False
        self._build()

    # ─────────────────────────── BUILD UI ────────────────────────────────────

    def _build(self):
        hdr = tk.Frame(self.frame, bg=COLORS["bg_panel"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="📡  Scanning",
                 bg=COLORS["bg_panel"], fg=COLORS["accent_cyan"],
                 font=FONTS["heading"]).pack(side="left", padx=18, pady=12)
        tk.Label(hdr, text="Network & Service Discovery",
                 bg=COLORS["bg_panel"], fg=COLORS["text_secondary"],
                 font=FONTS["small"]).pack(side="left")

        body = tk.Frame(self.frame, bg=COLORS["bg_dark"])
        body.pack(fill="both", expand=True, padx=10, pady=8)

        left = tk.Frame(body, bg=COLORS["bg_panel"], width=320)
        left.pack(side="left", fill="y", padx=(0, 6))
        left.pack_propagate(False)

        right = tk.Frame(body, bg=COLORS["bg_dark"])
        right.pack(side="left", fill="both", expand=True)

        self._build_controls(left)
        self._build_right(right)

    def _build_controls(self, parent):
        pad = {"padx": 14, "pady": 3, "anchor": "w"}

        section_header(parent, "Target").pack(fill="x", padx=10, pady=(12, 4))
        self.target_var = tk.StringVar(value=session.target or "")
        make_entry(parent, textvariable=self.target_var, width=32).pack(**pad)

        section_header(parent, "Scan Type").pack(fill="x", padx=10, pady=(12, 4))
        self.scan_type = tk.StringVar(value="top100")
        for label, val in [
            ("Top 100 Ports",   "top100"),
            ("Full TCP (1–1024)","full1024"),
            ("Extended (1–10000)","full10k"),
            ("Custom Range",     "custom"),
            ("Common Web Ports", "web"),
        ]:
            tk.Radiobutton(
                parent, text=label, variable=self.scan_type, value=val,
                bg=COLORS["bg_panel"], fg=COLORS["text_primary"],
                selectcolor=COLORS["accent_blue"],
                activebackground=COLORS["bg_panel"],
                font=FONTS["body"],
            ).pack(fill="x", padx=14, pady=1)

        tk.Label(parent, text="Custom range (e.g. 8000-9000):",
                 bg=COLORS["bg_panel"], fg=COLORS["text_secondary"],
                 font=FONTS["small"]).pack(padx=14, pady=(8,1), anchor="w")
        self.custom_range = tk.StringVar(value="8000-9000")
        make_entry(parent, textvariable=self.custom_range, width=22).pack(**pad)

        section_header(parent, "Scan Options").pack(fill="x", padx=10, pady=(10, 4))
        self.banner_var  = tk.BooleanVar(value=True)
        self.os_var      = tk.BooleanVar(value=True)
        self.web_dir_var = tk.BooleanVar(value=False)
        self.threads_var = tk.IntVar(value=100)

        for text, var in [
            ("Banner / Service Grabbing", self.banner_var),
            ("OS Fingerprinting (TTL)",   self.os_var),
            ("Web Directory Brute-Force", self.web_dir_var),
        ]:
            tk.Checkbutton(parent, text=text, variable=var,
                           bg=COLORS["bg_panel"], fg=COLORS["text_primary"],
                           selectcolor=COLORS["bg_input"],
                           activebackground=COLORS["bg_panel"],
                           font=FONTS["body"]).pack(fill="x", padx=14, pady=1)

        tk.Label(parent, text="Threads:", bg=COLORS["bg_panel"],
                 fg=COLORS["text_secondary"], font=FONTS["small"]).pack(padx=14, pady=(8,0), anchor="w")
        tk.Scale(parent, from_=10, to=500, orient="horizontal",
                 variable=self.threads_var,
                 bg=COLORS["bg_panel"], fg=COLORS["text_primary"],
                 troughcolor=COLORS["bg_input"],
                 font=FONTS["small"]).pack(fill="x", padx=14)

        tk.Frame(parent, bg=COLORS["border"], height=1).pack(fill="x", padx=10, pady=8)

        make_button(parent, "▶  Start Scan", self._start_scan,
                    color=COLORS["accent_green"]).pack(fill="x", padx=14, pady=2)
        make_button(parent, "⬛  Stop", self._stop,
                    color=COLORS["accent_red"]).pack(fill="x", padx=14, pady=2)
        make_button(parent, "🗑  Clear", self._clear,
                    color=COLORS["bg_hover"]).pack(fill="x", padx=14, pady=2)

        # Open-port summary
        section_header(parent, "Open Ports").pack(fill="x", padx=10, pady=(10, 2))
        self.open_list = tk.Listbox(
            parent, bg=COLORS["bg_card"], fg=COLORS["accent_green"],
            font=FONTS["mono_small"], selectbackground=COLORS["accent_blue"],
            relief="flat", height=10,
        )
        self.open_list.pack(fill="x", padx=14, pady=2)

    def _build_right(self, parent):
        section_header(parent, "Scan Output").pack(fill="x")
        self.terminal = TerminalOutput(parent)
        self.terminal.pack(fill="both", expand=True, pady=4)
        self.terminal.write("VAPT Pro – Scanning Module", "info")
        self.terminal.write("Configure options and click Start Scan.", "dim")
        self.terminal.separator()

    # ─────────────────────────── ACTIONS ─────────────────────────────────────

    def _start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Target Required", "Enter a target host/IP.")
            return
        session.target = target
        if self._running:
            messagebox.showinfo("Running", "Scan already in progress.")
            return
        self._running = True
        self.open_list.delete(0, "end")
        self.terminal.clear()
        t = threading.Thread(target=self._run_scan, args=(target,), daemon=True)
        t.start()
        self.update_status(f"Scanning {target}…")

    def _stop(self):
        self._running = False
        self.terminal.warn("Scan stopped by user.")

    def _clear(self):
        self.terminal.clear()
        self.open_list.delete(0, "end")

    # ─────────────────────────── SCAN ENGINE ─────────────────────────────────

    def _run_scan(self, target: str):
        domain = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        # Resolve IP
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            self.terminal.error(f"Cannot resolve {domain}")
            self._running = False
            return

        self.terminal.write(f"{'═'*70}", "dim")
        self.terminal.write(
            f"  VAPT Pro – Port Scanner  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "info")
        self.terminal.write(f"  Host  : {domain}", "info")
        self.terminal.write(f"  IP    : {ip}", "info")
        self.terminal.write(f"{'═'*70}", "dim")

        # OS fingerprint via TTL
        if self.os_var.get():
            self._os_fingerprint(ip)

        # Build port list
        ports = self._build_portlist()
        self.terminal.info(f"Scanning {len(ports)} ports with {self.threads_var.get()} threads…")
        self.terminal.separator()

        open_ports = []
        start = time.time()

        with ThreadPoolExecutor(max_workers=self.threads_var.get()) as pool:
            futures = {pool.submit(self._check_port, ip, p): p for p in ports}
            for fut in as_completed(futures):
                if not self._running:
                    break
                port, is_open, banner = fut.result()
                if is_open:
                    open_ports.append((port, banner))
                    svc = KNOWN_SERVICES.get(port, "Unknown")
                    line = f"  {port:<6} {svc:<18} {banner[:40] if banner else ''}"
                    self.terminal.ok(line)
                    self.open_list.insert("end", f"{port}/{svc}")
                    self._flag_dangerous(port, svc, banner)

        elapsed = time.time() - start
        self.terminal.separator()
        self.terminal.ok(f"Scan complete – {len(open_ports)} open ports in {elapsed:.1f}s")

        # Save to session
        session.scan_results = {
            "target": target, "ip": ip,
            "open_ports": [{"port": p, "banner": b} for p, b in open_ports],
        }
        self._running = False
        self.update_status(f"Scan done – {len(open_ports)} open on {domain}")
        self.refresh_sidebar()

        if self.web_dir_var.get() and any(p in [80, 443, 8080, 8443] for p, _ in open_ports):
            self._web_dir_bruteforce(f"http://{ip}")

    def _check_port(self, ip: str, port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            r = s.connect_ex((ip, port))
            banner = ""
            if r == 0 and self.banner_var.get():
                banner = self._grab_banner(s, port)
            s.close()
            return port, r == 0, banner
        except:
            return port, False, ""

    def _grab_banner(self, sock, port: int) -> str:
        try:
            if port == 80:
                sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner immediately
            elif port == 22:
                pass  # SSH sends banner immediately
            sock.settimeout(1.0)
            return sock.recv(256).decode("utf-8", errors="replace").strip()[:80]
        except:
            return ""

    def _os_fingerprint(self, ip: str):
        self.terminal.separator()
        self.terminal.prompt("OS Fingerprinting (TTL-based)")
        try:
            import subprocess
            r = subprocess.run(["ping", "-c", "1", "-W", "2", ip],
                               capture_output=True, text=True, timeout=5)
            output = r.stdout
            m = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
            if m:
                ttl = int(m.group(1))
                if ttl <= 64:
                    os_guess = "Linux / Unix / macOS"
                elif ttl <= 128:
                    os_guess = "Windows"
                else:
                    os_guess = "Cisco / Network Device"
                self.terminal.ok(f"  TTL={ttl} → Likely OS: {os_guess}")
            else:
                self.terminal.warn("  Could not determine TTL (ping may be blocked).")
        except Exception as e:
            self.terminal.warn(f"  OS fingerprint error: {e}")

    def _build_portlist(self) -> list:
        t = self.scan_type.get()
        if t == "top100":
            return TOP_100_PORTS
        elif t == "full1024":
            return list(range(1, 1025))
        elif t == "full10k":
            return list(range(1, 10001))
        elif t == "custom":
            try:
                lo, hi = map(int, self.custom_range.get().split("-"))
                return list(range(lo, hi + 1))
            except:
                return TOP_100_PORTS
        elif t == "web":
            return [80, 443, 8080, 8081, 8443, 8888, 3000, 4000, 5000, 7000, 9000]
        return TOP_100_PORTS

    def _flag_dangerous(self, port: int, service: str, banner: str):
        dangerous = {
            23:    ("CRITICAL", "Telnet", "Telnet is unencrypted.", "Disable Telnet; use SSH."),
            21:    ("HIGH",     "FTP",    "FTP transmits credentials in cleartext.",
                                          "Use SFTP or FTPS instead."),
            3389:  ("HIGH",     "RDP",    "RDP exposed to network.",
                                          "Restrict RDP behind VPN; enable NLA."),
            5900:  ("HIGH",     "VNC",    "VNC exposed to network.",
                                          "Disable or restrict VNC access."),
            6379:  ("CRITICAL", "Redis",  "Redis exposed without auth.",
                                          "Bind to localhost; enable authentication."),
            27017: ("HIGH",     "MongoDB","MongoDB may be unauthenticated.",
                                          "Enable auth; bind to localhost."),
            2375:  ("CRITICAL", "Docker", "Docker API exposed unauthenticated.",
                                          "Never expose Docker API; use TLS."),
            11211: ("HIGH",     "Memcached","Memcached accessible remotely.",
                                            "Bind to localhost; firewall port 11211."),
            9200:  ("HIGH",     "Elasticsearch", "Elasticsearch exposed.",
                                                  "Enable X-Pack security; firewall."),
        }
        if port in dangerous:
            sev, name, desc, rem = dangerous[port]
            session.add_finding(
                title=f"Dangerous port open: {port}/{name}",
                severity=sev,
                description=desc,
                remediation=rem,
                module="Scanning",
            )
            self.terminal.warn(f"  ⚠ FINDING: {sev} – {desc}")
            self.refresh_sidebar()

    def _web_dir_bruteforce(self, base_url: str):
        self.terminal.separator()
        self.terminal.prompt(f"Web Directory Brute-Force – {base_url}")
        wordlist = [
            "admin", "login", "dashboard", "api", "backup", "config",
            "wp-admin", "wp-login.php", "phpmyadmin", "phpinfo.php",
            "test", "debug", ".git", ".env", "uploads", "files",
            "static", "assets", "robots.txt", "sitemap.xml",
            "server-status", "web.config", ".htaccess", "readme.md",
        ]
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for path in wordlist:
            if not self._running:
                break
            url = f"{base_url}/{path}"
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "VAPTPro/1.0"})
                with urllib.request.urlopen(req, timeout=3, context=ctx) as r:
                    code = r.status
                    if code < 400:
                        self.terminal.ok(f"  [{code}] {url}")
                        if path in (".git", ".env", "backup", "config"):
                            session.add_finding(
                                title=f"Sensitive path accessible: /{path}",
                                severity="HIGH",
                                description=f"The path /{path} is publicly accessible (HTTP {code}).",
                                remediation=f"Remove or restrict access to /{path}.",
                                module="Scanning",
                            )
                            self.refresh_sidebar()
            except urllib.error.HTTPError as e:
                if e.code not in (403, 404):
                    self.terminal.dim(f"  [{e.code}] {url}")
            except:
                pass

    def on_show(self):
        self.target_var.set(session.target or "")

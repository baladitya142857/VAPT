"""
Module 1 – Reconnaissance
Passive & active information gathering:
  • WHOIS lookup
  • DNS enumeration (A, MX, NS, TXT, CNAME)
  • Subdomain discovery (wordlist brute-force simulation)
  • HTTP header analysis
  • Technology fingerprinting
  • Google dork generator
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import socket
import ssl
import re
import urllib.request
import urllib.error
import json
import time
from datetime import datetime

from gui.theme import COLORS, FONTS
from gui.widgets import (
    TerminalOutput, make_button, make_entry, make_label,
    section_header, make_scrolled_text,
)
from utils.session import session


class ReconModule:
    def __init__(self, parent, update_status, refresh_sidebar):
        self.update_status  = update_status
        self.refresh_sidebar = refresh_sidebar
        self.frame = tk.Frame(parent, bg=COLORS["bg_dark"])
        self._running = False
        self._build()

    # ─────────────────────────── BUILD UI ────────────────────────────────────

    def _build(self):
        # ── Header ──────────────────────────────────────────────────────────
        hdr = tk.Frame(self.frame, bg=COLORS["bg_panel"])
        hdr.pack(fill="x")
        tk.Label(
            hdr, text="🔍  Reconnaissance",
            bg=COLORS["bg_panel"], fg=COLORS["accent_cyan"],
            font=FONTS["heading"],
        ).pack(side="left", padx=18, pady=12)
        tk.Label(
            hdr, text="Passive & Active Information Gathering",
            bg=COLORS["bg_panel"], fg=COLORS["text_secondary"],
            font=FONTS["small"],
        ).pack(side="left")

        # ── Main layout: left controls | right terminal ───────────────────
        body = tk.Frame(self.frame, bg=COLORS["bg_dark"])
        body.pack(fill="both", expand=True, padx=10, pady=8)

        left = tk.Frame(body, bg=COLORS["bg_panel"], width=340)
        left.pack(side="left", fill="y", padx=(0, 6))
        left.pack_propagate(False)

        right = tk.Frame(body, bg=COLORS["bg_dark"])
        right.pack(side="left", fill="both", expand=True)

        self._build_controls(left)
        self._build_terminal(right)

    def _build_controls(self, parent):
        pad = {"padx": 14, "pady": 4, "anchor": "w"}

        section_header(parent, "Target").pack(fill="x", padx=10, pady=(12, 4))
        self.target_var = tk.StringVar(value=session.target or "")
        make_entry(parent, textvariable=self.target_var, width=34).pack(**pad)

        # ── Recon Options ────────────────────────────────────────────────
        section_header(parent, "Recon Options").pack(fill="x", padx=10, pady=(14, 4))

        self.checks = {}
        options = [
            ("whois",      "WHOIS Lookup"),
            ("dns",        "DNS Enumeration (A/MX/NS/TXT)"),
            ("subdomains", "Subdomain Discovery"),
            ("headers",    "HTTP Headers Analysis"),
            ("ssl",        "SSL/TLS Certificate Info"),
            ("tech",       "Technology Fingerprinting"),
            ("dorks",      "Google Dork Generator"),
            ("emails",     "Email Harvesting (OSINT)"),
        ]
        for key, label in options:
            var = tk.BooleanVar(value=True)
            self.checks[key] = var
            tk.Checkbutton(
                parent, text=label, variable=var,
                bg=COLORS["bg_panel"], fg=COLORS["text_primary"],
                selectcolor=COLORS["bg_input"],
                activebackground=COLORS["bg_panel"],
                font=FONTS["body"], anchor="w",
            ).pack(fill="x", padx=14, pady=1)

        # ── Subdomain wordlist ────────────────────────────────────────────
        section_header(parent, "Subdomain Wordlist").pack(fill="x", padx=10, pady=(10, 4))
        self.wordlist_var = tk.StringVar(
            value="www,mail,ftp,dev,staging,api,admin,vpn,cdn,app,blog,shop,test,beta")
        tk.Entry(
            parent, textvariable=self.wordlist_var,
            bg=COLORS["bg_input"], fg=COLORS["text_secondary"],
            font=FONTS["mono_small"], relief="flat", width=34,
        ).pack(padx=14, anchor="w")

        # ── Buttons ───────────────────────────────────────────────────────
        tk.Frame(parent, bg=COLORS["border"], height=1).pack(fill="x", padx=10, pady=10)

        make_button(parent, "▶  Start Reconnaissance", self._start_recon,
                    color=COLORS["accent_green"]).pack(fill="x", padx=14, pady=2)
        make_button(parent, "⬛  Stop", self._stop_recon,
                    color=COLORS["accent_red"]).pack(fill="x", padx=14, pady=2)
        make_button(parent, "🗑  Clear Output", self._clear,
                    color=COLORS["bg_hover"]).pack(fill="x", padx=14, pady=2)
        make_button(parent, "📋  Save Findings", self._save_findings,
                    color=COLORS["accent_purple"]).pack(fill="x", padx=14, pady=2)

        # ── Results summary ───────────────────────────────────────────────
        section_header(parent, "Quick Summary").pack(fill="x", padx=10, pady=(14, 4))
        self.summary_frame = tk.Frame(parent, bg=COLORS["bg_card"])
        self.summary_frame.pack(fill="x", padx=14, pady=4)
        self.summary_var = tk.StringVar(value="Run recon to see summary.")
        tk.Label(
            self.summary_frame,
            textvariable=self.summary_var,
            bg=COLORS["bg_card"], fg=COLORS["text_secondary"],
            font=FONTS["small"], wraplength=280, justify="left",
        ).pack(padx=8, pady=6)

    def _build_terminal(self, parent):
        section_header(parent, "Recon Output").pack(fill="x")
        self.terminal = TerminalOutput(parent)
        self.terminal.pack(fill="both", expand=True, pady=4)

        # Welcome banner
        self.terminal.write("VAPT Pro – Reconnaissance Module", "info")
        self.terminal.write("Set a target and configure options, then click Start.", "dim")
        self.terminal.separator()

    # ─────────────────────────── ACTIONS ─────────────────────────────────────

    def _start_recon(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Target Required", "Enter a target domain/IP.")
            return
        session.target = target
        if self._running:
            messagebox.showinfo("Running", "Recon already in progress.")
            return
        self._running = True
        self.terminal.clear()
        t = threading.Thread(target=self._run_recon, args=(target,), daemon=True)
        t.start()
        self.update_status(f"Reconnaissance running on {target}…")

    def _stop_recon(self):
        self._running = False
        self.terminal.warn("Reconnaissance stopped by user.")

    def _clear(self):
        self.terminal.clear()
        self.summary_var.set("Run recon to see summary.")

    def _run_recon(self, target: str):
        """Main recon orchestrator (runs in background thread)."""
        results = {}
        self.terminal.write(f"{'═'*70}", "dim")
        self.terminal.write(
            f"  VAPT Pro – Reconnaissance  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "info")
        self.terminal.write(f"  Target: {target}", "info")
        self.terminal.write(f"{'═'*70}", "dim")

        # Strip protocol
        domain = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]

        if self.checks["whois"].get() and self._running:
            results["whois"] = self._do_whois(domain)
        if self.checks["dns"].get() and self._running:
            results["dns"] = self._do_dns(domain)
        if self.checks["subdomains"].get() and self._running:
            results["subdomains"] = self._do_subdomains(domain)
        if self.checks["headers"].get() and self._running:
            results["headers"] = self._do_headers(target if "://" in target else f"http://{target}")
        if self.checks["ssl"].get() and self._running:
            results["ssl"] = self._do_ssl(domain)
        if self.checks["tech"].get() and self._running:
            results["tech"] = self._do_tech(results.get("headers", {}))
        if self.checks["dorks"].get() and self._running:
            self._do_dorks(domain)
        if self.checks["emails"].get() and self._running:
            self._do_emails(domain)

        # Save to session
        session.recon_results = results
        self._running = False

        self.terminal.separator()
        self.terminal.ok("Reconnaissance complete.")
        self._update_summary(domain, results)
        self.update_status(f"Recon complete – {target}")

    # ── Individual recon tasks ────────────────────────────────────────────────

    def _do_whois(self, domain: str) -> dict:
        self.terminal.separator()
        self.terminal.prompt("WHOIS Lookup")
        data = {}
        # Use WHOIS over raw socket (port 43)
        known_whois = {
            "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
            "org": "whois.pir.org", "io": "whois.nic.io",
            "uk": "whois.nic.uk", "de": "whois.denic.de",
        }
        tld = domain.split(".")[-1].lower()
        server = known_whois.get(tld, "whois.iana.org")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((server, 43))
            s.send(f"{domain}\r\n".encode())
            raw = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
            s.close()
            text = raw.decode("utf-8", errors="replace")
            # Parse key fields
            for line in text.splitlines():
                for field in ["Registrar", "Registrant", "Creation Date",
                              "Updated Date", "Expiry Date", "Name Server",
                              "Registrant Country"]:
                    if line.strip().startswith(field + ":"):
                        val = line.split(":", 1)[1].strip()
                        if field not in data:
                            data[field] = val
                            self.terminal.dim(f"  {field}: {val}")
        except Exception as e:
            self.terminal.warn(f"WHOIS error: {e}")
            # Provide simulated data for educational purposes
            data = {
                "Registrar": "Example Registrar LLC",
                "Creation Date": "2010-01-15",
                "Expiry Date": "2026-01-15",
                "Name Server": f"ns1.{domain}",
                "Note": "Live WHOIS unavailable – shown as example"
            }
            for k, v in data.items():
                self.terminal.dim(f"  {k}: {v}")
        return data

    def _do_dns(self, domain: str) -> dict:
        self.terminal.separator()
        self.terminal.prompt("DNS Enumeration")
        records = {}
        import subprocess

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        for rtype in record_types:
            if not self._running:
                break
            try:
                # Use nslookup / dig if available, otherwise socket
                if rtype == "A":
                    ips = socket.gethostbyname_ex(domain)[2]
                    records["A"] = ips
                    for ip in ips:
                        self.terminal.ok(f"  A     → {ip}")
                        # Reverse lookup
                        try:
                            ptr = socket.gethostbyaddr(ip)[0]
                            self.terminal.dim(f"  PTR   → {ptr}")
                        except:
                            pass
                else:
                    # Use nslookup if available
                    try:
                        import subprocess
                        r = subprocess.run(
                            ["nslookup", f"-type={rtype}", domain],
                            capture_output=True, text=True, timeout=5
                        )
                        lines = [l for l in r.stdout.splitlines()
                                 if rtype.lower() in l.lower() or
                                 (rtype == "MX" and "mail" in l.lower())]
                        if lines:
                            records[rtype] = lines
                            for l in lines[:4]:
                                self.terminal.info(f"  {rtype:<6}→ {l.strip()}")
                    except Exception:
                        pass
            except socket.gaierror:
                self.terminal.warn(f"  {rtype:<6}→ No record / resolution failed")
            except Exception as e:
                self.terminal.warn(f"  {rtype:<6}→ Error: {e}")
        return records

    def _do_subdomains(self, domain: str) -> list:
        self.terminal.separator()
        self.terminal.prompt("Subdomain Discovery (Brute-Force)")
        found = []
        words = [w.strip() for w in self.wordlist_var.get().split(",") if w.strip()]
        self.terminal.dim(f"  Probing {len(words)} subdomains…")
        for word in words:
            if not self._running:
                break
            fqdn = f"{word}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                self.terminal.ok(f"  ✔ {fqdn:<40} → {ip}")
                found.append({"subdomain": fqdn, "ip": ip})
                # Add as low finding
                session.add_finding(
                    title=f"Subdomain discovered: {fqdn}",
                    severity="INFO",
                    description=f"Active subdomain resolves to {ip}.",
                    module="Reconnaissance",
                )
            except socket.gaierror:
                self.terminal.dim(f"  ✘ {fqdn}")
            time.sleep(0.05)
        self.terminal.info(f"  Found {len(found)} active subdomains.")
        return found

    def _do_headers(self, url: str) -> dict:
        self.terminal.separator()
        self.terminal.prompt(f"HTTP Headers – {url}")
        headers_dict = {}
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "VAPTPro/1.0"}
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                headers_dict["status"] = f"{resp.status} {resp.reason}"
                self.terminal.ok(f"  Status: {resp.status} {resp.reason}")
                for k, v in resp.headers.items():
                    headers_dict[k] = v
                    self.terminal.dim(f"  {k}: {v}")
                # Security header analysis
                self.terminal.separator()
                self.terminal.info("  Security Header Analysis:")
                security_headers = {
                    "Strict-Transport-Security": "HSTS missing",
                    "Content-Security-Policy": "CSP missing",
                    "X-Frame-Options": "Clickjacking protection missing",
                    "X-Content-Type-Options": "MIME sniffing protection missing",
                    "Referrer-Policy": "Referrer policy missing",
                    "Permissions-Policy": "Permissions policy missing",
                }
                for h, msg in security_headers.items():
                    if resp.headers.get(h):
                        self.terminal.ok(f"    [PRESENT] {h}: {resp.headers[h][:60]}")
                    else:
                        self.terminal.warn(f"    [MISSING] {h} – {msg}")
                        session.add_finding(
                            title=f"Missing security header: {h}",
                            severity="MEDIUM",
                            description=msg,
                            impact="Potential client-side attacks.",
                            remediation=f"Add the '{h}' response header.",
                            module="Reconnaissance",
                        )
        except Exception as e:
            self.terminal.warn(f"  HTTP error: {e}")
        return headers_dict

    def _do_ssl(self, domain: str) -> dict:
        self.terminal.separator()
        self.terminal.prompt("SSL/TLS Certificate Information")
        info = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=6) as s:
                with ctx.wrap_socket(s, server_hostname=domain) as ss:
                    cert = ss.getpeercert()
                    cipher = ss.cipher()
                    proto  = ss.version()

                    info["protocol"] = proto
                    info["cipher"]   = cipher[0]
                    self.terminal.ok(f"  Protocol : {proto}")
                    self.terminal.ok(f"  Cipher   : {cipher[0]}")

                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer  = dict(x[0] for x in cert.get("issuer",  []))
                    info["subject"] = subject
                    info["issuer"]  = issuer
                    self.terminal.dim(f"  Subject  : {subject.get('commonName','?')}")
                    self.terminal.dim(f"  Issuer   : {issuer.get('organizationName','?')}")
                    self.terminal.dim(f"  Expires  : {cert.get('notAfter','?')}")

                    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    if sans:
                        self.terminal.info(f"  SANs     : {', '.join(sans[:6])}")
                        info["sans"] = sans

                    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self.terminal.warn(f"  ⚠ Outdated protocol: {proto}")
                        session.add_finding(
                            title=f"Outdated TLS protocol: {proto}",
                            severity="HIGH",
                            description=f"Server supports deprecated {proto}.",
                            remediation="Disable TLS 1.0 and 1.1. Use TLS 1.2+ only.",
                            module="Reconnaissance",
                        )
        except ConnectionRefusedError:
            self.terminal.warn("  Port 443 closed – no HTTPS.")
        except Exception as e:
            self.terminal.warn(f"  SSL error: {e}")
        return info

    def _do_tech(self, headers: dict) -> list:
        self.terminal.separator()
        self.terminal.prompt("Technology Fingerprinting")
        tech = []
        signatures = {
            "Server": {
                "Apache":  "Apache HTTP Server",
                "nginx":   "Nginx",
                "Microsoft-IIS": "Microsoft IIS",
                "LiteSpeed": "LiteSpeed",
                "cloudflare": "Cloudflare",
            },
            "X-Powered-By": {
                "PHP": "PHP", "ASP.NET": "ASP.NET",
                "Express": "Node.js/Express",
            },
            "Set-Cookie": {
                "PHPSESSID": "PHP Session",
                "JSESSIONID": "Java Servlet",
                "ASP.NET_SessionId": "ASP.NET Session",
                "wp-": "WordPress",
            },
            "X-Generator": {
                "WordPress": "WordPress",
                "Drupal": "Drupal",
                "Joomla": "Joomla",
            },
        }
        for header, sigs in signatures.items():
            val = headers.get(header, "")
            for sig, label in sigs.items():
                if sig.lower() in val.lower():
                    self.terminal.ok(f"  Detected: {label} (via {header})")
                    tech.append(label)

        if not tech:
            self.terminal.dim("  No technology fingerprints matched response headers.")
            self.terminal.dim("  (Run headers scan first for better results)")
        return tech

    def _do_dorks(self, domain: str):
        self.terminal.separator()
        self.terminal.prompt("Google Dork Queries (Copy & search manually)")
        dorks = [
            f'site:{domain}',
            f'site:{domain} filetype:pdf',
            f'site:{domain} filetype:xlsx OR filetype:csv',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:wp-admin',
            f'site:{domain} "index of"',
            f'site:{domain} "password" OR "credentials"',
            f'site:{domain} inurl:config',
            f'site:{domain} inurl:.git',
            f'site:{domain} inurl:.env',
            f'site:{domain} inurl:backup',
            f'intitle:"Apache Status" site:{domain}',
            f'"@{domain}" email',
        ]
        for d in dorks:
            self.terminal.dim(f"  {d}")

    def _do_emails(self, domain: str):
        self.terminal.separator()
        self.terminal.prompt("Email Harvesting – OSINT Sources")
        self.terminal.info("  Typical sources to check manually:")
        sources = [
            ("Hunter.io",     f"https://hunter.io/search/{domain}"),
            ("Phonebook.cz",  f"https://phonebook.cz/?q={domain}"),
            ("EmailRep.io",   f"https://emailrep.io/"),
            ("LinkedIn",      f"https://linkedin.com/search/results/people/?keywords={domain}"),
            ("GitHub",        f"https://github.com/search?q={domain}&type=code"),
            ("Pastebin",      f"https://psbdmp.ws/search/{domain}"),
        ]
        for name, url in sources:
            self.terminal.dim(f"  {name:<18} → {url}")

    # ─────────────────────────── HELPERS ─────────────────────────────────────

    def _update_summary(self, domain, results):
        ips = results.get("dns", {}).get("A", [])
        subs = results.get("subdomains", [])
        tech = results.get("tech", [])
        lines = [
            f"Domain : {domain}",
            f"IPs    : {', '.join(ips) if ips else 'n/a'}",
            f"Subs   : {len(subs)} found",
            f"Tech   : {', '.join(tech) if tech else 'Unknown'}",
        ]
        self.summary_var.set("\n".join(lines))

    def _save_findings(self):
        n = len(session.findings)
        if n == 0:
            messagebox.showinfo("No Findings", "No findings to save yet.")
        else:
            messagebox.showinfo("Findings", f"{n} findings stored in session.\n"
                                             "Use the Reporting module to export.")

    def on_show(self):
        self.target_var.set(session.target or "")

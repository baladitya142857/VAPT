"""
Module 3 – Vulnerability Assessment
Analyses scan results and checks for known vulnerabilities:
  • CVE lookup by service/version
  • SQL Injection detection
  • XSS detection
  • Open redirect
  • Directory traversal
  • Sensitive file exposure
  • Default credentials check
  • SSL/TLS weakness
  • CORS misconfiguration
  • CSRF detection
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
import re
import time
from datetime import datetime

from gui.theme import COLORS, FONTS
from gui.widgets import TerminalOutput, make_button, make_entry, section_header
from utils.session import session

# ── Known vulnerable service versions ────────────────────────────────────────
CVE_DB = {
    "Apache": [
        {"version_pattern": "2.4.4[0-9]", "cve": "CVE-2021-41773",
         "severity": "CRITICAL", "desc": "Path traversal and RCE in Apache 2.4.49/50"},
        {"version_pattern": "2.4.4[89]", "cve": "CVE-2021-42013",
         "severity": "CRITICAL", "desc": "Path traversal bypass in Apache 2.4.49-50"},
    ],
    "OpenSSH": [
        {"version_pattern": "7\\.[0-6]", "cve": "CVE-2023-38408",
         "severity": "CRITICAL", "desc": "Remote code execution in OpenSSH ssh-agent"},
        {"version_pattern": "[3-6]\\.", "cve": "CVE-2016-6515",
         "severity": "HIGH", "desc": "DoS via long password in OpenSSH"},
    ],
    "nginx": [
        {"version_pattern": "1\\.(1[0-7]|[0-9])\\.", "cve": "CVE-2021-23017",
         "severity": "HIGH", "desc": "Off-by-one heap write in nginx resolver"},
    ],
    "ProFTPD": [
        {"version_pattern": "1\\.[0-3]", "cve": "CVE-2019-12815",
         "severity": "CRITICAL", "desc": "Arbitrary file copy via mod_copy module"},
    ],
    "MySQL": [
        {"version_pattern": "5\\.[0-6]", "cve": "CVE-2012-2122",
         "severity": "HIGH", "desc": "Authentication bypass in MySQL 5.x"},
    ],
    "WordPress": [
        {"version_pattern": "5\\.[0-7]", "cve": "CVE-2021-29447",
         "severity": "HIGH", "desc": "XXE via Media Library in WordPress"},
    ],
}

# ── Payloads ──────────────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    ("'", "SQLi Quote"),
    ("' OR '1'='1", "SQLi OR-bypass"),
    ("' OR 1=1--", "SQLi comment-bypass"),
    ("\" OR \"1\"=\"1", "SQLi double-quote"),
    ("'; DROP TABLE users; --", "SQLi drop (Bobby Tables)"),
    ("1 UNION SELECT NULL,NULL,NULL--", "SQLi UNION"),
    ("1 AND SLEEP(5)--", "SQLi time-based blind"),
]

XSS_PAYLOADS = [
    ("<script>alert(1)</script>",           "XSS basic script"),
    ("<img src=x onerror=alert(1)>",        "XSS img-onerror"),
    ("'\"><script>alert(1)</script>",       "XSS break-out"),
    ("<svg onload=alert(1)>",               "XSS SVG"),
    ("javascript:alert(1)",                  "XSS javascript-proto"),
]

TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd",    "etc/passwd"),
    ("....//....//etc/passwd", "Encoded traversal"),
    ("%2e%2e%2fetc%2fpasswd",  "URL-encoded traversal"),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows hosts"),
]

DEFAULT_CREDS = [
    ("admin", "admin"),    ("admin", "password"), ("admin", "12345"),
    ("root",  "root"),     ("root",  "toor"),      ("admin", ""),
    ("user",  "user"),     ("guest", "guest"),
]

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/backup.zip", "/backup.sql",
    "/config.php", "/wp-config.php", "/web.config",
    "/.htpasswd", "/composer.json", "/package.json",
    "/phpinfo.php", "/test.php", "/info.php",
    "/server-status", "/.DS_Store", "/Thumbs.db",
    "/readme.txt", "/CHANGELOG.txt", "/install.php",
]


class VulnAssessModule:
    def __init__(self, parent, update_status, refresh_sidebar):
        self.update_status   = update_status
        self.refresh_sidebar = refresh_sidebar
        self.frame = tk.Frame(parent, bg=COLORS["bg_dark"])
        self._running = False
        self._build()

    def _build(self):
        hdr = tk.Frame(self.frame, bg=COLORS["bg_panel"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="⚠️  Vulnerability Assessment",
                 bg=COLORS["bg_panel"], fg=COLORS["accent_cyan"],
                 font=FONTS["heading"]).pack(side="left", padx=18, pady=12)
        tk.Label(hdr, text="Automated vulnerability detection & CVE matching",
                 bg=COLORS["bg_panel"], fg=COLORS["text_secondary"],
                 font=FONTS["small"]).pack(side="left")

        body = tk.Frame(self.frame, bg=COLORS["bg_dark"])
        body.pack(fill="both", expand=True, padx=10, pady=8)

        left = tk.Frame(body, bg=COLORS["bg_panel"], width=310)
        left.pack(side="left", fill="y", padx=(0, 6))
        left.pack_propagate(False)

        right = tk.Frame(body, bg=COLORS["bg_dark"])
        right.pack(side="left", fill="both", expand=True)

        self._build_controls(left)
        self._build_right(right)

    def _build_controls(self, parent):
        pad = {"padx": 14, "pady": 3, "anchor": "w"}

        section_header(parent, "Target URL / Host").pack(fill="x", padx=10, pady=(12, 4))
        self.target_var = tk.StringVar(value=session.target or "")
        make_entry(parent, textvariable=self.target_var, width=32).pack(**pad)

        section_header(parent, "Check Categories").pack(fill="x", padx=10, pady=(10, 4))

        self.checks = {}
        options = [
            ("cve",       "CVE / Banner Version Match"),
            ("sqli",      "SQL Injection (GET params)"),
            ("xss",       "Cross-Site Scripting (XSS)"),
            ("traversal", "Directory Traversal / LFI"),
            ("sensitive", "Sensitive File Exposure"),
            ("cors",      "CORS Misconfiguration"),
            ("csrf",      "CSRF Token Absence"),
            ("ssl",       "SSL/TLS Weaknesses"),
            ("defcreds",  "Default Credentials (HTTP Basic)"),
            ("redirect",  "Open Redirect"),
        ]
        for key, label in options:
            var = tk.BooleanVar(value=True)
            self.checks[key] = var
            tk.Checkbutton(parent, text=label, variable=var,
                           bg=COLORS["bg_panel"], fg=COLORS["text_primary"],
                           selectcolor=COLORS["bg_input"],
                           activebackground=COLORS["bg_panel"],
                           font=FONTS["body"]).pack(fill="x", padx=14, pady=1)

        section_header(parent, "Extra Parameters").pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(parent, text="Test URL with params (SQLi/XSS):",
                 bg=COLORS["bg_panel"], fg=COLORS["text_secondary"],
                 font=FONTS["small"]).pack(**pad)
        self.param_url_var = tk.StringVar(
            value="http://target.com/page?id=1")
        make_entry(parent, textvariable=self.param_url_var, width=32).pack(**pad)

        tk.Frame(parent, bg=COLORS["border"], height=1).pack(fill="x", padx=10, pady=8)

        make_button(parent, "▶  Start Assessment", self._start,
                    color=COLORS["accent_orange"]).pack(fill="x", padx=14, pady=2)
        make_button(parent, "⬛  Stop", self._stop,
                    color=COLORS["accent_red"]).pack(fill="x", padx=14, pady=2)
        make_button(parent, "🗑  Clear", self._clear,
                    color=COLORS["bg_hover"]).pack(fill="x", padx=14, pady=2)

        # Severity counter
        section_header(parent, "Findings Summary").pack(fill="x", padx=10, pady=(10, 2))
        self.severity_vars = {}
        for sev, color in [("CRITICAL", COLORS["critical"]),
                            ("HIGH",     COLORS["high"]),
                            ("MEDIUM",   COLORS["medium"]),
                            ("LOW",      COLORS["low"])]:
            row = tk.Frame(parent, bg=COLORS["bg_panel"])
            row.pack(fill="x", padx=14, pady=1)
            tk.Label(row, text=f"{sev:<10}", bg=COLORS["bg_panel"],
                     fg=color, font=FONTS["small"]).pack(side="left")
            v = tk.StringVar(value="0")
            self.severity_vars[sev] = v
            tk.Label(row, textvariable=v, bg=COLORS["bg_panel"],
                     fg=color, font=FONTS["small"]).pack(side="left")

    def _build_right(self, parent):
        section_header(parent, "Assessment Output").pack(fill="x")
        self.terminal = TerminalOutput(parent)
        self.terminal.pack(fill="both", expand=True, pady=4)
        self.terminal.write("VAPT Pro – Vulnerability Assessment Module", "info")
        self.terminal.write("Load scan results or enter a target URL to begin.", "dim")
        self.terminal.separator()

    # ─────────────────────────── ACTIONS ─────────────────────────────────────

    def _start(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Target Required", "Enter a target.")
            return
        session.target = target
        if self._running:
            return
        self._running = True
        self.terminal.clear()
        threading.Thread(target=self._run_assessment, args=(target,), daemon=True).start()
        self.update_status(f"Vulnerability assessment on {target}…")

    def _stop(self):
        self._running = False
        self.terminal.warn("Assessment stopped by user.")

    def _clear(self):
        self.terminal.clear()
        for v in self.severity_vars.values():
            v.set("0")

    # ─────────────────────────── ENGINE ──────────────────────────────────────

    def _run_assessment(self, target: str):
        url = target if "://" in target else f"http://{target}"
        domain = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        findings_before = len(session.findings)

        self.terminal.write(f"{'═'*70}", "dim")
        self.terminal.write(
            f"  VAPT Pro – Vulnerability Assessment  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "info")
        self.terminal.write(f"  Target: {target}", "info")
        self.terminal.write(f"{'═'*70}", "dim")

        if self.checks["cve"].get() and self._running:
            self._check_cve()
        if self.checks["sensitive"].get() and self._running:
            self._check_sensitive(url)
        if self.checks["cors"].get() and self._running:
            self._check_cors(url)
        if self.checks["csrf"].get() and self._running:
            self._check_csrf(url)
        if self.checks["ssl"].get() and self._running:
            self._check_ssl(domain)
        if self.checks["sqli"].get() and self._running:
            self._check_sqli()
        if self.checks["xss"].get() and self._running:
            self._check_xss()
        if self.checks["traversal"].get() and self._running:
            self._check_traversal(url)
        if self.checks["defcreds"].get() and self._running:
            self._check_defcreds(url)
        if self.checks["redirect"].get() and self._running:
            self._check_redirect(url)

        self.terminal.separator()
        new_findings = len(session.findings) - findings_before
        self.terminal.ok(f"Assessment complete. {new_findings} new findings recorded.")
        self._running = False
        self._update_counters()
        self.refresh_sidebar()
        self.update_status(f"Vuln assessment done – {new_findings} findings")

    def _ctx(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _fetch(self, url, timeout=5, headers=None, method="GET"):
        hdrs = {"User-Agent": "VAPTPro/1.0"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx()) as r:
                return r.status, dict(r.headers), r.read(4096).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, {}, ""
        except Exception:
            return 0, {}, ""

    # ── Individual checks ─────────────────────────────────────────────────────

    def _check_cve(self):
        self.terminal.separator()
        self.terminal.prompt("CVE / Version Matching (from scan banners)")
        scan = session.scan_results
        if not scan:
            self.terminal.warn("No scan results in session. Run Scanning module first.")
            return
        ports = scan.get("open_ports", [])
        matched = 0
        for entry in ports:
            banner = entry.get("banner", "")
            for product, cves in CVE_DB.items():
                if product.lower() in banner.lower():
                    for cve in cves:
                        if re.search(cve["version_pattern"], banner):
                            self.terminal.warn(
                                f"  ⚠ {cve['cve']} ({cve['severity']}) – {cve['desc'][:60]}")
                            session.add_finding(
                                title=cve["cve"],
                                severity=cve["severity"],
                                description=cve["desc"],
                                remediation="Apply vendor patches immediately.",
                                module="Vulnerability Assessment",
                            )
                            matched += 1
        if matched == 0:
            self.terminal.info("  No exact CVE version matches. Patch banners and try again.")
        else:
            self.terminal.warn(f"  {matched} CVE match(es) found!")

    def _check_sensitive(self, base_url: str):
        self.terminal.separator()
        self.terminal.prompt("Sensitive File Exposure")
        for path in SENSITIVE_PATHS:
            if not self._running:
                break
            url = base_url.rstrip("/") + path
            code, hdrs, body = self._fetch(url, timeout=4)
            if code == 200:
                self.terminal.warn(f"  ⚠ FOUND ({code}) {url}")
                session.add_finding(
                    title=f"Sensitive file exposed: {path}",
                    severity="HIGH",
                    description=f"The file {path} is publicly accessible (HTTP 200).",
                    impact="May expose credentials, source code, or configuration.",
                    remediation=f"Remove or block access to {path}.",
                    module="Vulnerability Assessment",
                )
            elif code in (301, 302, 403):
                self.terminal.dim(f"  [{code}] {url}")

    def _check_cors(self, url: str):
        self.terminal.separator()
        self.terminal.prompt("CORS Misconfiguration")
        code, hdrs, _ = self._fetch(url, headers={"Origin": "https://evil.com"})
        acao = hdrs.get("Access-Control-Allow-Origin", "")
        acac = hdrs.get("Access-Control-Allow-Credentials", "")
        if acao == "*":
            self.terminal.warn("  ⚠ ACAO: * (wildcard – public data exposed)")
            session.add_finding(
                title="CORS: Wildcard Access-Control-Allow-Origin",
                severity="MEDIUM",
                description="Server returns Access-Control-Allow-Origin: * allowing any origin.",
                remediation="Restrict ACAO to specific trusted origins.",
                module="Vulnerability Assessment",
            )
        elif "evil.com" in acao:
            self.terminal.warn("  ⚠ ACAO reflects attacker origin!")
            if "true" in acac.lower():
                self.terminal.warn("  ⚠ ACAC: true → credentials also shared! CRITICAL")
                session.add_finding(
                    title="CORS: Reflected origin with credentials",
                    severity="CRITICAL",
                    description="Server reflects arbitrary origins and allows credentials – full CORS bypass.",
                    remediation="Validate Origin against whitelist; never reflect arbitrary origins.",
                    module="Vulnerability Assessment",
                )
        else:
            self.terminal.ok(f"  ACAO: {acao or 'Not set (OK)'}")

    def _check_csrf(self, url: str):
        self.terminal.separator()
        self.terminal.prompt("CSRF Token Detection")
        code, hdrs, body = self._fetch(url)
        csrf_found = bool(re.search(
            r'(csrf|_token|authenticity_token|__RequestVerificationToken)',
            body, re.IGNORECASE))
        if not csrf_found and code == 200:
            self.terminal.warn("  ⚠ No CSRF token detected in response body.")
            session.add_finding(
                title="CSRF: No token in response",
                severity="MEDIUM",
                description="No CSRF token found in the page – state-changing requests may be forgeable.",
                remediation="Implement CSRF tokens on all state-changing forms.",
                module="Vulnerability Assessment",
            )
        else:
            self.terminal.ok("  CSRF token present or page returned non-200.")

    def _check_ssl(self, domain: str):
        self.terminal.separator()
        self.terminal.prompt("SSL/TLS Weakness Check")
        try:
            for proto_const, proto_name in [
                (ssl.PROTOCOL_TLS_CLIENT, "TLS (default)"),
            ]:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((domain, 443), timeout=5) as s:
                    with ctx.wrap_socket(s, server_hostname=domain) as ss:
                        ver    = ss.version()
                        cipher = ss.cipher()
                        self.terminal.ok(f"  Protocol : {ver}")
                        self.terminal.ok(f"  Cipher   : {cipher[0]} / {cipher[2]} bits")
                        if cipher[2] and cipher[2] < 128:
                            session.add_finding(
                                title="Weak cipher suite",
                                severity="HIGH",
                                description=f"Cipher {cipher[0]} uses only {cipher[2]}-bit keys.",
                                remediation="Configure server to use 256-bit AES ciphers.",
                                module="Vulnerability Assessment",
                            )
                            self.terminal.warn(f"  ⚠ Weak cipher strength: {cipher[2]} bits")
                        cert = ss.getpeercert()
                        exp = cert.get("notAfter", "")
                        self.terminal.dim(f"  Expires  : {exp}")
        except ConnectionRefusedError:
            self.terminal.warn("  Port 443 not open.")
        except Exception as e:
            self.terminal.warn(f"  SSL check error: {e}")

    def _check_sqli(self):
        self.terminal.separator()
        self.terminal.prompt("SQL Injection Testing")
        param_url = self.param_url_var.get().strip()
        if not param_url or "?" not in param_url:
            self.terminal.info("  Set a parameterized URL in controls (e.g. http://site/page?id=1)")
            return

        base, query = param_url.split("?", 1)
        params = urllib.parse.parse_qs(query, keep_blank_values=True)

        for param, vals in params.items():
            original = vals[0]
            for payload, name in SQLI_PAYLOADS:
                if not self._running:
                    break
                new_params = dict(params)
                new_params[param] = payload
                url = base + "?" + urllib.parse.urlencode(new_params, doseq=True)
                code, hdrs, body = self._fetch(url, timeout=5)
                # Check for SQL error patterns
                errors = [
                    "sql syntax", "mysql_fetch", "sqlite3", "odbc",
                    "sqlexception", "pg_query", "syntax error",
                    "unclosed quotation", "quoted string not properly terminated",
                ]
                found_error = any(e in body.lower() for e in errors)
                if found_error:
                    self.terminal.warn(f"  ⚠ SQL error exposed! Param: {param}, Payload: {name}")
                    session.add_finding(
                        title=f"SQL Injection – parameter '{param}'",
                        severity="CRITICAL",
                        description=f"SQL error exposed with payload: {payload}",
                        impact="Full database compromise possible.",
                        remediation="Use parameterized queries / prepared statements.",
                        module="Vulnerability Assessment",
                    )
                    break
                self.terminal.dim(f"  [{code}] {param}={payload[:30]} – {name}")
                time.sleep(0.1)

    def _check_xss(self):
        self.terminal.separator()
        self.terminal.prompt("XSS (Cross-Site Scripting) Testing")
        param_url = self.param_url_var.get().strip()
        if not param_url or "?" not in param_url:
            self.terminal.info("  Set a parameterized URL in controls.")
            return

        base, query = param_url.split("?", 1)
        params = urllib.parse.parse_qs(query, keep_blank_values=True)

        for param, vals in params.items():
            for payload, name in XSS_PAYLOADS:
                if not self._running:
                    break
                new_params = dict(params)
                new_params[param] = payload
                url = base + "?" + urllib.parse.urlencode(new_params, doseq=True)
                code, hdrs, body = self._fetch(url, timeout=5)
                if payload in body:
                    self.terminal.warn(f"  ⚠ XSS reflected! Param: {param}, Payload: {name}")
                    session.add_finding(
                        title=f"Reflected XSS – parameter '{param}'",
                        severity="HIGH",
                        description=f"Payload reflected in response: {payload}",
                        impact="Session hijacking, phishing, credential theft.",
                        remediation="Encode all user output; implement CSP.",
                        module="Vulnerability Assessment",
                    )
                    break
                self.terminal.dim(f"  [{code}] {param}={payload[:30][:30]}")
                time.sleep(0.1)

    def _check_traversal(self, base_url: str):
        self.terminal.separator()
        self.terminal.prompt("Directory Traversal / LFI")
        for payload, name in TRAVERSAL_PAYLOADS:
            if not self._running:
                break
            url = f"{base_url.rstrip('/')}/../../{payload}"
            code, hdrs, body = self._fetch(url)
            if "root:" in body or "[fonts]" in body:
                self.terminal.warn(f"  ⚠ LFI/Traversal CONFIRMED! Payload: {name}")
                session.add_finding(
                    title="Directory Traversal / LFI",
                    severity="CRITICAL",
                    description=f"File traversal payload returned system file content. ({name})",
                    impact="Arbitrary file read on server.",
                    remediation="Validate and sanitize all path inputs; use chroot jails.",
                    module="Vulnerability Assessment",
                )
            else:
                self.terminal.dim(f"  [{code}] {name}")
            time.sleep(0.1)

    def _check_defcreds(self, url: str):
        self.terminal.separator()
        self.terminal.prompt("Default Credentials (HTTP Basic Auth)")
        import base64
        for user, passwd in DEFAULT_CREDS:
            if not self._running:
                break
            cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            code, hdrs, _ = self._fetch(url, headers={"Authorization": f"Basic {cred}"})
            if code == 200:
                self.terminal.warn(f"  ⚠ Default credentials work! {user}:{passwd}")
                session.add_finding(
                    title=f"Default credentials accepted: {user}:{passwd}",
                    severity="CRITICAL",
                    description="HTTP Basic Auth accepts default credentials.",
                    remediation="Change default credentials immediately.",
                    module="Vulnerability Assessment",
                )
                break
            self.terminal.dim(f"  [{code}] {user}:{passwd}")
            time.sleep(0.1)

    def _check_redirect(self, url: str):
        self.terminal.separator()
        self.terminal.prompt("Open Redirect Detection")
        payloads = [
            "?url=https://evil.com", "?redirect=https://evil.com",
            "?next=https://evil.com", "?return=https://evil.com",
            "?to=//evil.com", "?goto=https://evil.com",
        ]
        for p in payloads:
            if not self._running:
                break
            test_url = url.rstrip("/") + p
            try:
                req = urllib.request.Request(
                    test_url, headers={"User-Agent": "VAPTPro/1.0"})
                # Don't follow redirects
                opener = urllib.request.build_opener(
                    urllib.request.HTTPRedirectHandler())
                with opener.open(req, timeout=4) as r:
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc:
                        self.terminal.warn(f"  ⚠ Open redirect! {p}")
                        session.add_finding(
                            title="Open Redirect",
                            severity="MEDIUM",
                            description=f"Open redirect via parameter {p}",
                            remediation="Validate redirect URLs against a whitelist.",
                            module="Vulnerability Assessment",
                        )
            except urllib.error.HTTPError as e:
                loc = e.headers.get("Location", "")
                if "evil.com" in loc:
                    self.terminal.warn(f"  ⚠ Open redirect (3xx)! {p}")
                self.terminal.dim(f"  [{e.code}] {p}")
            except:
                pass

    def _update_counters(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in session.findings:
            sev = f["severity"].upper()
            if sev in counts:
                counts[sev] += 1
        for sev, var in self.severity_vars.items():
            var.set(str(counts.get(sev, 0)))

    def on_show(self):
        self.target_var.set(session.target or "")
        self._update_counters()

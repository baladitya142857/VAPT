# ⚔ VAPT Pro — Vulnerability Assessment & Penetration Testing Platform

> **For educational and authorised use only.**
> Always obtain explicit written permission before testing any system you do not own.

---

## Overview

VAPT Pro is a comprehensive, dark-themed Python GUI application for security professionals and developers to **find, understand, and fix vulnerabilities**. It covers the full pentest lifecycle in six integrated modules.

```
┌─────────────────────────────────────────────────────────┐
│  ⚔  VAPT Pro  │  Target: _________________ [Set]       │
├──────────┬──────────────────────────────────────────────┤
│          │                                              │
│ MODULES  │   Module Content Area                        │
│          │                                              │
│ 🔍 Recon │   Terminal Output / Tables / Tabs            │
│ 📡 Scan  │                                              │
│ ⚠  Vuln  │                                              │
│ 💥 Expl  │                                              │
│ 🕵  PostX │                                              │
│ 📄 Report│                                              │
│          │                                              │
└──────────┴──────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

| Platform | Command |
|----------|---------|
| Ubuntu/Debian | `sudo apt install python3 python3-tk` |
| Fedora/RHEL   | `sudo dnf install python3 python3-tkinter` |
| macOS         | Install Python from python.org (includes Tk) |
| Windows       | Install Python from python.org (includes Tk) |

### Run

```bash
python3 main.py
```

No external packages required — pure Python stdlib + Tkinter.

---

## 📦 Modules

### 1. 🔍 Reconnaissance
Passive and active information gathering:
- **WHOIS Lookup** — registrar, creation/expiry dates, name servers
- **DNS Enumeration** — A, AAAA, MX, NS, TXT, CNAME, SOA, PTR
- **Subdomain Discovery** — configurable wordlist brute-force
- **HTTP Header Analysis** — all headers + security header audit (HSTS, CSP, X-Frame-Options…)
- **SSL/TLS Certificate Info** — protocol, cipher, SANs, expiry
- **Technology Fingerprinting** — Apache, Nginx, PHP, ASP.NET, WordPress…
- **Google Dork Generator** — 14 ready-to-use dork queries
- **Email Harvesting** — OSINT source links (Hunter.io, Phonebook.cz, etc.)

### 2. 📡 Scanning
Network and service discovery:
- **TCP Port Scanner** — Top-100, Full 1–1024, 1–10000, Custom range, Web-only
- **Banner / Service Grabbing** — FTP, SSH, HTTP, and more
- **OS Fingerprinting** — TTL-based (Linux/Windows/Network device)
- **Dangerous Port Detection** — Telnet, FTP, RDP, VNC, Redis, MongoDB, Docker API…
- **Web Directory Brute-Force** — common paths including `.git`, `.env`, `backup`
- **Concurrent scanning** — configurable thread count (10–500)

### 3. ⚠️ Vulnerability Assessment
Automated vulnerability checks:
- **CVE Matching** — banner version → CVE database lookup
- **SQL Injection** — GET param testing with error pattern detection
- **XSS** — reflected XSS detection across parameters
- **Directory Traversal / LFI** — multiple encoded payloads
- **Sensitive File Exposure** — 20+ paths (`.env`, `.git`, backups, phpinfo…)
- **CORS Misconfiguration** — wildcard and reflected origin detection
- **CSRF Token Detection** — checks for token in response body
- **SSL/TLS Weaknesses** — protocol version, cipher strength
- **Default Credentials** — HTTP Basic Auth brute-force
- **Open Redirect** — 6 common parameter names

### 4. 💥 Exploitation
Controlled PoC testing with **remediation guidance** for every exploit:
| Exploit | Severity |
|---------|----------|
| SQL Injection (UNION & Blind/Time-based) | CRITICAL |
| XSS PoC Generator | HIGH |
| FTP Anonymous Login | HIGH |
| Default HTTP Credentials | HIGH |
| Path Traversal / LFI | CRITICAL |
| Clickjacking PoC (generates HTML) | MEDIUM |
| SSRF Probe | HIGH |
| JWT 'none' Algorithm Bypass | CRITICAL |
| XXE Injection | HIGH |
| HTTP Parameter Pollution | MEDIUM |
| Redis No-Auth Check | CRITICAL |

> ⚠ Requires ticking the "I confirm I have authorisation" checkbox.

### 5. 🕵️ Post-Exploitation
Attacker simulation + defender playbooks:
- **Privilege Escalation** — Linux & Windows checklists (commands + remediations)
- **Lateral Movement** — 10 vector descriptions + detection guidance
- **Persistence Mechanisms** — 8 techniques + monitoring advice
- **Data Exfiltration Risk** — 7 channels + DLP controls
- **IoC Generator** — target-specific indicators + SIEM alert pseudo-rules
- **Defender Playbook** — 10-point hardening checklist + IR phases
- **Reverse Shell Generator** — Bash, Python, PHP, Perl, Ruby, Netcat, PowerShell, msfvenom

### 6. 📄 Reporting
Professional report generation:
- **Findings Table** — sortable, filterable by severity, with detail pane
- **Manual Findings** — add custom findings with full metadata
- **Risk Matrix** — bar chart visualisation of finding counts
- **Remediation Tracker** — mark findings OPEN / IN PROGRESS / FIXED
- **Export formats:**
  - **HTML** — full styled report with risk overview
  - **Markdown** — GitHub-ready report
  - **JSON** — full session export
  - **Executive Summary** — text-based c-suite summary
  - **Remediation Plan** — grouped by severity

---

## 💾 Session Management
- **Save Session** — exports full session to JSON (target, findings, results, logs)
- **Load Session** — restores a previous engagement
- **New Session** — resets all data

---

## ⚖️ Legal Notice

This tool is intended for:
- Security professionals conducting authorised penetration tests
- Developers testing their own applications
- Students learning about web security in lab environments

**Never use this tool against systems without explicit written permission.**
The authors accept no liability for misuse.

---

## 📁 Project Structure

```
vapt_tool/
├── main.py              # Entry point
├── gui/
│   ├── app.py           # Main window + sidebar navigation
│   ├── theme.py         # Dark theme colours & fonts
│   └── widgets.py       # Reusable UI components
├── modules/
│   ├── recon.py         # Reconnaissance module
│   ├── scanning.py      # Port/service scanner
│   ├── vuln_assess.py   # Vulnerability assessment
│   ├── exploitation.py  # Exploitation PoCs
│   ├── post_exploit.py  # Post-exploitation reference
│   └── reporting.py     # Report generation
└── utils/
    └── session.py       # Shared session state
```

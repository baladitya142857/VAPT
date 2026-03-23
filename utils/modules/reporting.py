"""
Module 6 – Reporting
Generates professional VAPT reports:
  • Interactive findings table with severity filter
  • Executive Summary generator
  • Technical Report (HTML) with charts
  • Text / Markdown report
  • Risk Matrix visualisation
  • Remediation tracking
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import json
from datetime import datetime

from gui.theme import COLORS, FONTS, SEVERITY_COLORS
from gui.widgets import (
    TerminalOutput, make_button, make_entry, section_header,
    make_scrolled_text,
)
from utils.session import session


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class ReportingModule:
    def __init__(self, parent, update_status, refresh_sidebar):
        self.update_status   = update_status
        self.refresh_sidebar = refresh_sidebar
        self.frame = tk.Frame(parent, bg=COLORS["bg_dark"])
        self._build()

    def _build(self):
        hdr = tk.Frame(self.frame, bg=COLORS["bg_panel"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="📄  Reporting",
                 bg=COLORS["bg_panel"], fg=COLORS["accent_cyan"],
                 font=FONTS["heading"]).pack(side="left", padx=18, pady=12)
        tk.Label(hdr, text="Generate Professional VAPT Reports",
                 bg=COLORS["bg_panel"], fg=COLORS["text_secondary"],
                 font=FONTS["small"]).pack(side="left")

        nb = ttk.Notebook(self.frame)
        nb.pack(fill="both", expand=True, padx=10, pady=8)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=COLORS["bg_dark"], borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=COLORS["bg_panel"],
                        foreground=COLORS["text_secondary"],
                        font=FONTS["small"], padding=[12, 6])
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["bg_selected"])],
                  foreground=[("selected", COLORS["text_primary"])])

        tabs = [
            ("📋 Findings",        self._build_findings_tab),
            ("⚙  Report Settings", self._build_settings_tab),
            ("📊 Risk Matrix",     self._build_risk_tab),
            ("🔧 Remediation",     self._build_remediation_tab),
            ("📝 Export",          self._build_export_tab),
        ]
        for label, builder in tabs:
            tab = tk.Frame(nb, bg=COLORS["bg_dark"])
            nb.add(tab, text=label)
            builder(tab)

    # ── Tabs ─────────────────────────────────────────────────────────────────

    def _build_findings_tab(self, parent):
        section_header(parent, "All Findings").pack(fill="x", padx=4, pady=4)

        # Toolbar
        bar = tk.Frame(parent, bg=COLORS["bg_dark"])
        bar.pack(fill="x", padx=8, pady=4)

        tk.Label(bar, text="Filter severity:", bg=COLORS["bg_dark"],
                 fg=COLORS["text_secondary"], font=FONTS["body"]).pack(side="left", padx=4)
        self.filter_sev = tk.StringVar(value="ALL")
        for sev in ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            color = SEVERITY_COLORS.get(sev, COLORS["text_secondary"])
            tk.Radiobutton(bar, text=sev, variable=self.filter_sev, value=sev,
                           command=self._refresh_findings,
                           bg=COLORS["bg_dark"], fg=color,
                           selectcolor=COLORS["bg_input"],
                           activebackground=COLORS["bg_dark"],
                           font=FONTS["small"]).pack(side="left", padx=4)

        make_button(bar, "🔄 Refresh", self._refresh_findings,
                    color=COLORS["accent_blue"]).pack(side="right", padx=4)
        make_button(bar, "➕ Add Manual Finding", self._add_manual,
                    color=COLORS["accent_green"]).pack(side="right", padx=4)
        make_button(bar, "🗑 Delete Selected", self._delete_finding,
                    color=COLORS["accent_red"]).pack(side="right", padx=4)

        # Treeview
        cols = ("ID", "Severity", "Title", "Module", "Timestamp")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings", height=15)
        style = ttk.Style()
        style.configure("Treeview",
                        background=COLORS["bg_card"],
                        foreground=COLORS["text_primary"],
                        fieldbackground=COLORS["bg_card"],
                        rowheight=26,
                        font=FONTS["mono_small"])
        style.configure("Treeview.Heading",
                        background=COLORS["bg_panel"],
                        foreground=COLORS["accent_cyan"],
                        font=FONTS["small"])
        style.map("Treeview", background=[("selected", COLORS["accent_blue"])])

        widths = {"ID": 40, "Severity": 80, "Title": 340, "Module": 120, "Timestamp": 140}
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=widths[col], minwidth=40)

        # Tags per severity
        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev.lower(), foreground=color)

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(fill="both", expand=False, padx=8, pady=2, side="left")
        vsb.pack(side="left", fill="y", pady=2)

        # Detail pane
        detail_frame = tk.Frame(parent, bg=COLORS["bg_panel"])
        detail_frame.pack(fill="both", expand=True, padx=8, pady=4)
        section_header(detail_frame, "Finding Detail").pack(fill="x")
        self.detail_frame2, self.detail_txt = make_scrolled_text(detail_frame, height=8)
        self.detail_frame2.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self._refresh_findings()

    def _build_settings_tab(self, parent):
        section_header(parent, "Engagement Details").pack(fill="x", padx=4, pady=8)
        fields = [
            ("Engagement Name:", "eng_name",  session.engagement_name),
            ("Tester Name:",     "tester",    session.tester_name),
            ("Organisation:",    "org",        session.org_name),
            ("Target:",          "rpt_target", session.target),
            ("Executive Summary:","exec_summ", ""),
        ]
        self.report_vars = {}
        for label, key, default in fields:
            row = tk.Frame(parent, bg=COLORS["bg_dark"])
            row.pack(fill="x", padx=20, pady=6)
            tk.Label(row, text=label, bg=COLORS["bg_dark"],
                     fg=COLORS["text_secondary"], font=FONTS["body"],
                     width=20, anchor="w").pack(side="left")
            if key == "exec_summ":
                var = tk.Text(row, bg=COLORS["bg_input"], fg=COLORS["text_primary"],
                              font=FONTS["body"], height=6, width=60,
                              insertbackground=COLORS["accent_green"], relief="flat")
                var.insert("1.0",
                           f"This report presents the findings of a penetration test conducted "
                           f"against {session.org_name or 'the target organisation'} between "
                           f"{session.started_at.strftime('%Y-%m-%d')} and "
                           f"{datetime.now().strftime('%Y-%m-%d')}. "
                           f"The assessment identified {len(session.findings)} vulnerabilities "
                           f"across {len(set(f['module'] for f in session.findings))} test categories.")
                var.pack(side="left", padx=4)
                self.exec_summ_widget = var
            else:
                v = tk.StringVar(value=default)
                self.report_vars[key] = v
                make_entry(row, textvariable=v, width=50).pack(side="left", padx=4)

        make_button(parent, "💾 Save Settings", self._save_settings,
                    color=COLORS["accent_green"]).pack(pady=10)

    def _build_risk_tab(self, parent):
        section_header(parent, "Risk Matrix Visualisation").pack(fill="x", padx=4, pady=4)

        # Canvas-based risk matrix
        self.risk_canvas = tk.Canvas(
            parent, bg=COLORS["bg_card"], width=600, height=320,
            highlightthickness=0,
        )
        self.risk_canvas.pack(padx=20, pady=10)
        make_button(parent, "🔄 Refresh Matrix", self._draw_risk_matrix,
                    color=COLORS["accent_blue"]).pack(pady=4)

        # Stats frame
        stats_frame = tk.Frame(parent, bg=COLORS["bg_panel"])
        stats_frame.pack(fill="x", padx=20, pady=4)
        self.stat_vars = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            col_f = tk.Frame(stats_frame, bg=SEVERITY_COLORS.get(sev, COLORS["text_muted"]),
                             padx=12, pady=8)
            col_f.pack(side="left", padx=4)
            v = tk.StringVar(value="0")
            self.stat_vars[sev] = v
            tk.Label(col_f, textvariable=v, bg=SEVERITY_COLORS.get(sev, COLORS["text_muted"]),
                     fg="#ffffff" if sev not in ("LOW", "INFO") else "#000000",
                     font=("Consolas", 22, "bold")).pack()
            tk.Label(col_f, text=sev,
                     bg=SEVERITY_COLORS.get(sev, COLORS["text_muted"]),
                     fg="#ffffff" if sev not in ("LOW", "INFO") else "#000000",
                     font=FONTS["small"]).pack()
        self._draw_risk_matrix()

    def _build_remediation_tab(self, parent):
        section_header(parent, "Remediation Tracker").pack(fill="x", padx=4, pady=4)
        tk.Label(parent, text="Track remediation status for each finding.",
                 bg=COLORS["bg_dark"], fg=COLORS["text_secondary"],
                 font=FONTS["body"]).pack(padx=10, pady=4, anchor="w")

        cols = ("ID", "Severity", "Title", "Status", "Remediation")
        self.rem_tree = ttk.Treeview(parent, columns=cols, show="headings", height=20)
        for col, w in zip(cols, [40, 80, 280, 100, 280]):
            self.rem_tree.heading(col, text=col)
            self.rem_tree.column(col, width=w)

        for sev, color in SEVERITY_COLORS.items():
            self.rem_tree.tag_configure(sev.lower(), foreground=color)

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.rem_tree.yview)
        self.rem_tree.configure(yscrollcommand=vsb.set)
        self.rem_tree.pack(fill="both", expand=True, padx=8, pady=2, side="left")
        vsb.pack(side="left", fill="y", pady=2)

        btn_frame = tk.Frame(parent, bg=COLORS["bg_dark"])
        btn_frame.pack(fill="x", padx=8, pady=4, side="bottom")
        make_button(btn_frame, "✔ Mark Fixed", self._mark_fixed,
                    color=COLORS["status_ok"]).pack(side="left", padx=4)
        make_button(btn_frame, "⚡ Mark In-Progress", self._mark_inprogress,
                    color=COLORS["accent_orange"]).pack(side="left", padx=4)
        make_button(btn_frame, "🔄 Refresh", self._refresh_remediation,
                    color=COLORS["accent_blue"]).pack(side="left", padx=4)
        self._refresh_remediation()

    def _build_export_tab(self, parent):
        section_header(parent, "Export Report").pack(fill="x", padx=4, pady=8)

        formats = [
            ("HTML Report (Full)",           "html",  COLORS["accent_blue"]),
            ("Markdown Report",              "md",    COLORS["accent_purple"]),
            ("JSON Session Export",          "json",  COLORS["accent_orange"]),
            ("Executive Summary (TXT)",      "exec",  COLORS["accent_green"]),
            ("Remediation Plan (TXT)",       "rem",   COLORS["accent_cyan"]),
        ]

        for label, fmt, color in formats:
            row = tk.Frame(parent, bg=COLORS["bg_dark"])
            row.pack(fill="x", padx=40, pady=6)
            tk.Label(row, text=f"  {label}",
                     bg=COLORS["bg_dark"], fg=COLORS["text_primary"],
                     font=FONTS["body"], width=35, anchor="w").pack(side="left")
            make_button(row, f"Export {fmt.upper()}",
                        lambda f=fmt: self._export(f),
                        color=color).pack(side="left", padx=8)

        # Preview
        section_header(parent, "Report Preview").pack(fill="x", padx=4, pady=(16, 4))
        frame, self.preview_txt = make_scrolled_text(parent, height=16)
        frame.pack(fill="both", expand=True, padx=8, pady=4)
        make_button(parent, "🔍 Preview Report", self._preview,
                    color=COLORS["bg_hover"]).pack(pady=4)

    # ─────────────────────────── FINDINGS MANAGEMENT ─────────────────────────

    def _refresh_findings(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        flt = self.filter_sev.get()
        findings = sorted(session.findings,
                          key=lambda f: SEVERITY_ORDER.get(f["severity"].upper(), 99))
        for f in findings:
            if flt != "ALL" and f["severity"].upper() != flt:
                continue
            self.tree.insert("", "end",
                             values=(f["id"], f["severity"], f["title"],
                                     f.get("module", ""), f.get("timestamp", "")),
                             tags=(f["severity"].lower(),))

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        item = self.tree.item(sel[0])
        fid = item["values"][0]
        finding = next((f for f in session.findings if f["id"] == fid), None)
        if not finding:
            return
        self.detail_txt.config(state="normal")
        self.detail_txt.delete("1.0", "end")
        for k, v in finding.items():
            if k == "id":
                continue
            self.detail_txt.insert("end", f"{k.upper()}\n", "key")
            self.detail_txt.insert("end", f"  {v}\n\n", "val")
        self.detail_txt.tag_configure("key", foreground=COLORS["accent_cyan"],
                                      font=FONTS["subheading"])
        self.detail_txt.tag_configure("val", foreground=COLORS["text_primary"],
                                      font=FONTS["mono_small"])
        self.detail_txt.config(state="disabled")

    def _add_manual(self):
        win = tk.Toplevel(self.frame)
        win.title("Add Manual Finding")
        win.geometry("600x480")
        win.configure(bg=COLORS["bg_panel"])

        fields = {}
        entries = [
            ("Title",       "tk.Entry", 60),
            ("Severity",    "combo",    ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]),
            ("Description", "text",     8),
            ("Impact",      "text",     4),
            ("Remediation", "text",     4),
            ("Module",      "tk.Entry", 30),
        ]
        for label, etype, opt in entries:
            tk.Label(win, text=label + ":", bg=COLORS["bg_panel"],
                     fg=COLORS["text_secondary"], font=FONTS["body"]).pack(anchor="w", padx=14, pady=(6,0))
            if etype == "tk.Entry":
                v = tk.StringVar()
                e = tk.Entry(win, textvariable=v, bg=COLORS["bg_input"],
                             fg=COLORS["text_primary"], font=FONTS["body"],
                             relief="flat", width=opt)
                e.pack(padx=14, fill="x")
                fields[label] = v
            elif etype == "combo":
                v = tk.StringVar(value="MEDIUM")
                cb = ttk.Combobox(win, textvariable=v, values=opt, state="readonly", width=20)
                cb.pack(padx=14, anchor="w")
                fields[label] = v
            elif etype == "text":
                t = tk.Text(win, bg=COLORS["bg_input"], fg=COLORS["text_primary"],
                            font=FONTS["body"], height=opt, relief="flat")
                t.pack(padx=14, fill="x")
                fields[label] = t

        def save():
            title = fields["Title"].get().strip()
            sev   = fields["Severity"].get()
            desc  = fields["Description"].get("1.0","end").strip()
            imp   = fields["Impact"].get("1.0","end").strip()
            rem   = fields["Remediation"].get("1.0","end").strip()
            mod   = fields["Module"].get().strip() or "Manual"
            if not title:
                messagebox.showwarning("Required", "Title is required.", parent=win)
                return
            session.add_finding(title, sev, desc, imp, rem, mod)
            self._refresh_findings()
            self._draw_risk_matrix()
            self.refresh_sidebar()
            win.destroy()

        make_button(win, "💾 Save Finding", save,
                    color=COLORS["accent_green"]).pack(pady=10)

    def _delete_finding(self):
        sel = self.tree.selection()
        if not sel:
            return
        fid = self.tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Delete", f"Delete finding #{fid}?"):
            session.findings = [f for f in session.findings if f["id"] != fid]
            self._refresh_findings()
            self._draw_risk_matrix()
            self.refresh_sidebar()

    # ─────────────────────────── RISK MATRIX ─────────────────────────────────

    def _draw_risk_matrix(self):
        c = self.risk_canvas
        c.delete("all")
        counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
        for f in session.findings:
            sev = f["severity"].upper()
            if sev in counts:
                counts[sev] += 1
        for sev, cnt in counts.items():
            if sev in self.stat_vars:
                self.stat_vars[sev].set(str(cnt))

        # Draw bars
        W, H = 580, 280
        labels = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
        colors = [COLORS["critical"],COLORS["high"],COLORS["medium"],COLORS["low"],COLORS["info"]]
        max_count = max(counts.values()) or 1
        bar_w = W // len(labels) - 20

        for i, (sev, col) in enumerate(zip(labels, colors)):
            x = 30 + i * (W // len(labels))
            cnt = counts[sev]
            bar_h = int((cnt / max_count) * 200) if cnt > 0 else 0
            y_top = 220 - bar_h
            y_bot = 220
            c.create_rectangle(x, y_top, x + bar_w, y_bot, fill=col, outline="")
            c.create_text(x + bar_w//2, y_bot + 14, text=sev,
                          fill=col, font=("Consolas",9,"bold"))
            c.create_text(x + bar_w//2, y_top - 10, text=str(cnt),
                          fill=col, font=("Consolas",14,"bold"))
        c.create_line(20, 220, W + 10, 220, fill=COLORS["border"], width=1)
        c.create_text(W//2, 12, text="Findings by Severity",
                      fill=COLORS["accent_cyan"], font=FONTS["subheading"])

    # ─────────────────────────── REMEDIATION ─────────────────────────────────

    def _refresh_remediation(self):
        if not hasattr(self, "_fix_status"):
            self._fix_status = {}
        for row in self.rem_tree.get_children():
            self.rem_tree.delete(row)
        for f in sorted(session.findings,
                        key=lambda x: SEVERITY_ORDER.get(x["severity"].upper(), 99)):
            status = self._fix_status.get(f["id"], "OPEN")
            self.rem_tree.insert("", "end",
                                 values=(f["id"], f["severity"], f["title"],
                                         status, f.get("remediation","")[:60]),
                                 tags=(f["severity"].lower(),))

    def _mark_fixed(self):
        sel = self.rem_tree.selection()
        if not sel:
            return
        fid = self.rem_tree.item(sel[0])["values"][0]
        if not hasattr(self, "_fix_status"):
            self._fix_status = {}
        self._fix_status[fid] = "FIXED ✔"
        self._refresh_remediation()

    def _mark_inprogress(self):
        sel = self.rem_tree.selection()
        if not sel:
            return
        fid = self.rem_tree.item(sel[0])["values"][0]
        if not hasattr(self, "_fix_status"):
            self._fix_status = {}
        self._fix_status[fid] = "IN PROGRESS"
        self._refresh_remediation()

    # ─────────────────────────── SETTINGS ────────────────────────────────────

    def _save_settings(self):
        if hasattr(self, "report_vars"):
            session.engagement_name = self.report_vars.get("eng_name", tk.StringVar()).get()
            session.tester_name     = self.report_vars.get("tester",   tk.StringVar()).get()
            session.org_name        = self.report_vars.get("org",      tk.StringVar()).get()
            session.target          = self.report_vars.get("rpt_target",tk.StringVar()).get()
        messagebox.showinfo("Saved", "Report settings saved to session.")

    # ─────────────────────────── EXPORT ──────────────────────────────────────

    def _preview(self):
        self.preview_txt.config(state="normal")
        self.preview_txt.delete("1.0","end")
        self.preview_txt.insert("end", self._gen_text_report())
        self.preview_txt.config(state="disabled")

    def _export(self, fmt: str):
        ext_map = {"html":".html","md":".md","json":".json",
                   "exec":".txt","rem":".txt"}
        ext = ext_map.get(fmt, ".txt")
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(fmt.upper(), f"*{ext}")],
            title=f"Save {fmt.upper()} Report",
        )
        if not path:
            return
        if fmt == "html":
            content = self._gen_html_report()
        elif fmt == "md":
            content = self._gen_markdown_report()
        elif fmt == "json":
            content = json.dumps(session.to_dict(), indent=2, default=str)
        elif fmt == "exec":
            content = self._gen_exec_summary()
        elif fmt == "rem":
            content = self._gen_remediation_report()
        else:
            content = self._gen_text_report()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")
        self.update_status(f"Report exported: {os.path.basename(path)}")

    # ─────────────────────────── GENERATORS ──────────────────────────────────

    def _gen_text_report(self) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        findings = sorted(session.findings,
                          key=lambda f: SEVERITY_ORDER.get(f["severity"].upper(), 99))
        counts = {}
        for f in findings:
            counts[f["severity"].upper()] = counts.get(f["severity"].upper(), 0) + 1

        lines = [
            "=" * 70,
            f"  VAPT PROFESSIONAL REPORT",
            f"  {session.engagement_name}",
            "=" * 70,
            f"  Organisation : {session.org_name}",
            f"  Target       : {session.target}",
            f"  Tester       : {session.tester_name}",
            f"  Date         : {now}",
            "=" * 70,
            "",
            "EXECUTIVE SUMMARY",
            "-" * 70,
            f"  Total Findings: {len(findings)}",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"  {sev:<10}: {counts.get(sev, 0)}")
        lines += ["", "FINDINGS", "=" * 70, ""]
        for f in findings:
            lines += [
                f"[{f['id']:03d}] [{f['severity']}] {f['title']}",
                f"  Module      : {f.get('module', '')}",
                f"  Description : {f.get('description', '')}",
                f"  Impact      : {f.get('impact', 'N/A')}",
                f"  Remediation : {f.get('remediation', 'N/A')}",
                f"  Timestamp   : {f.get('timestamp', '')}",
                "",
            ]
        return "\n".join(lines)

    def _gen_markdown_report(self) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        findings = sorted(session.findings,
                          key=lambda f: SEVERITY_ORDER.get(f["severity"].upper(), 99))
        counts = {s: 0 for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
        for f in findings:
            counts[f["severity"].upper()] = counts.get(f["severity"].upper(), 0) + 1

        md = [
            f"# VAPT Report – {session.engagement_name}",
            f"",
            f"**Organisation:** {session.org_name}  ",
            f"**Target:** {session.target}  ",
            f"**Tester:** {session.tester_name}  ",
            f"**Date:** {now}  ",
            "",
            "## Executive Summary",
            "",
            f"This assessment of **{session.org_name}** identified **{len(findings)}** security findings.",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            md.append(f"| {sev} | {counts[sev]} |")
        md += ["", "## Findings", ""]
        for f in findings:
            md += [
                f"### [{f['severity']}] {f['title']}",
                f"- **Module:** {f.get('module','')}",
                f"- **Description:** {f.get('description','')}",
                f"- **Impact:** {f.get('impact','N/A')}",
                f"- **Remediation:** {f.get('remediation','N/A')}",
                f"- **Timestamp:** {f.get('timestamp','')}",
                "",
            ]
        return "\n".join(md)

    def _gen_exec_summary(self) -> str:
        findings = session.findings
        counts = {}
        for f in findings:
            counts[f["severity"].upper()] = counts.get(f["severity"].upper(), 0) + 1
        return (
            f"EXECUTIVE SUMMARY – {session.engagement_name}\n"
            f"{'='*60}\n"
            f"Organisation : {session.org_name}\n"
            f"Target       : {session.target}\n"
            f"Date         : {datetime.now().strftime('%Y-%m-%d')}\n\n"
            f"RISK OVERVIEW\n"
            f"{'─'*40}\n"
            + "\n".join(f"  {s:<10}: {counts.get(s,0)}"
                        for s in ["CRITICAL","HIGH","MEDIUM","LOW"])
            + f"\n  TOTAL    : {len(findings)}\n\n"
            f"IMMEDIATE ACTIONS REQUIRED:\n"
            + "\n".join(
                f"  [{f['severity']}] {f['title']}"
                for f in sorted(findings,
                                key=lambda x: SEVERITY_ORDER.get(x["severity"].upper(), 99))
                if f["severity"].upper() in ("CRITICAL","HIGH")
            )
        )

    def _gen_remediation_report(self) -> str:
        status = getattr(self, "_fix_status", {})
        lines = [
            "REMEDIATION PLAN",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 70, "",
        ]
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            group = [f for f in session.findings if f["severity"].upper() == sev]
            if group:
                lines.append(f"\n{sev} FINDINGS\n{'─'*40}")
                for f in group:
                    st = status.get(f["id"], "OPEN")
                    lines += [
                        f"  [{st}] {f['title']}",
                        f"    Remediation: {f.get('remediation','N/A')}",
                        "",
                    ]
        return "\n".join(lines)

    def _gen_html_report(self) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        findings = sorted(session.findings,
                          key=lambda f: SEVERITY_ORDER.get(f["severity"].upper(), 99))
        counts = {s: 0 for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
        for f in findings:
            counts[f["severity"].upper()] = counts.get(f["severity"].upper(), 0) + 1

        sev_colors = {
            "CRITICAL":"#f85149","HIGH":"#d29922",
            "MEDIUM":"#58a6ff","LOW":"#39d353","INFO":"#8b949e",
        }
        rows = ""
        for f in findings:
            c = sev_colors.get(f["severity"].upper(), "#888")
            rows += f"""
        <tr>
          <td>{f['id']}</td>
          <td><span class="badge" style="background:{c}">{f['severity']}</span></td>
          <td>{f.get('title','')}</td>
          <td>{f.get('module','')}</td>
          <td>{f.get('description','')}</td>
          <td>{f.get('remediation','N/A')}</td>
        </tr>"""

        stat_cards = ""
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            c = sev_colors[sev]
            stat_cards += f'<div class="card" style="background:{c}22;border:1px solid {c}"><div class="num" style="color:{c}">{counts[sev]}</div><div class="lbl">{sev}</div></div>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VAPT Report – {session.engagement_name}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family: 'Segoe UI', Consolas, monospace; background:#0d1117; color:#e6edf3; padding:24px; }}
  h1 {{ color:#58a6ff; font-size:2em; margin-bottom:8px; }}
  h2 {{ color:#58a6ff; margin:24px 0 12px; border-left:4px solid #1f6feb; padding-left:12px; }}
  .meta {{ color:#8b949e; margin-bottom:20px; line-height:2; }}
  .cards {{ display:flex; gap:12px; margin:16px 0; flex-wrap:wrap; }}
  .card {{ padding:16px 24px; border-radius:8px; text-align:center; min-width:100px; }}
  .card .num {{ font-size:2.5em; font-weight:bold; }}
  .card .lbl {{ font-size:0.8em; opacity:0.9; }}
  .badge {{ padding:3px 10px; border-radius:12px; color:#fff; font-size:0.8em; font-weight:bold; }}
  table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
  th {{ background:#161b22; color:#58a6ff; padding:12px 8px; text-align:left; border-bottom:2px solid #30363d; }}
  td {{ padding:10px 8px; border-bottom:1px solid #21262d; vertical-align:top; font-size:0.88em; }}
  tr:hover {{ background:#1c2128; }}
  .header-bar {{ background:#161b22; padding:20px 28px; border-radius:8px; margin-bottom:20px;
                 border:1px solid #30363d; }}
  footer {{ color:#484f58; text-align:center; margin-top:40px; font-size:0.8em; }}
</style>
</head>
<body>
<div class="header-bar">
  <h1>⚔ VAPT Report</h1>
  <div class="meta">
    <strong>Engagement:</strong> {session.engagement_name}<br>
    <strong>Organisation:</strong> {session.org_name}<br>
    <strong>Target:</strong> {session.target}<br>
    <strong>Tester:</strong> {session.tester_name}<br>
    <strong>Date:</strong> {now}
  </div>
</div>

<h2>Risk Overview</h2>
<div class="cards">{stat_cards}</div>

<h2>Findings ({len(findings)})</h2>
<table>
  <thead>
    <tr><th>ID</th><th>Severity</th><th>Title</th><th>Module</th><th>Description</th><th>Remediation</th></tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
<footer>Generated by VAPT Pro &bull; {now} &bull; Educational Use Only</footer>
</body>
</html>"""

    def on_show(self):
        self._refresh_findings()
        self._draw_risk_matrix()
        self._refresh_remediation()

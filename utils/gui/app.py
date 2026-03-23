"""
VAPT Pro – Main Application Window
Sidebar navigation + module frame switcher
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from gui.theme import COLORS, FONTS
from utils.session import session

# ── module imports ────────────────────────────────────────────────────────────
from modules.recon       import ReconModule
from modules.scanning    import ScanningModule
from modules.vuln_assess import VulnAssessModule
from modules.exploitation import ExploitationModule
from modules.post_exploit import PostExploitModule
from modules.reporting   import ReportingModule


NAV_ITEMS = [
    ("🔍", "Reconnaissance",       "reconnaissance"),
    ("📡", "Scanning",             "scanning"),
    ("⚠️",  "Vulnerability Assess.","vuln_assess"),
    ("💥", "Exploitation",         "exploitation"),
    ("🕵️",  "Post-Exploitation",   "post_exploit"),
    ("📄", "Reporting",            "reporting"),
]

MODULE_CLASSES = {
    "reconnaissance": ReconModule,
    "scanning":       ScanningModule,
    "vuln_assess":    VulnAssessModule,
    "exploitation":   ExploitationModule,
    "post_exploit":   PostExploitModule,
    "reporting":      ReportingModule,
}


class VAPTApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.configure(bg=COLORS["bg_dark"])
        self.active_module = tk.StringVar(value="reconnaissance")
        self.modules: dict = {}
        self._build_ui()
        self._switch("reconnaissance")

    # ─────────────────────────────── UI BUILD ────────────────────────────────

    def _build_ui(self):
        # Top bar
        self._build_topbar()

        # Main layout: sidebar | content
        main = tk.Frame(self.root, bg=COLORS["bg_dark"])
        main.pack(fill="both", expand=True)

        self._build_sidebar(main)
        self._build_content(main)

        # Status bar
        self._build_statusbar()

    def _build_topbar(self):
        bar = tk.Frame(self.root, bg=COLORS["bg_sidebar"], height=52)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        # Logo / title
        tk.Label(
            bar, text="⚔  VAPT Pro",
            bg=COLORS["bg_sidebar"], fg=COLORS["accent_green"],
            font=FONTS["title"],
        ).pack(side="left", padx=18, pady=8)

        tk.Label(
            bar, text="Vulnerability Assessment & Penetration Testing Platform",
            bg=COLORS["bg_sidebar"], fg=COLORS["text_secondary"],
            font=FONTS["small"],
        ).pack(side="left", padx=4)

        # Right-side controls
        right = tk.Frame(bar, bg=COLORS["bg_sidebar"])
        right.pack(side="right", padx=12)

        tk.Button(
            right, text="💾 Save Session",
            command=self._save_session,
            bg=COLORS["bg_hover"], fg=COLORS["text_primary"],
            font=FONTS["small"], relief="flat", padx=10, pady=4, cursor="hand2",
        ).pack(side="left", padx=4)

        tk.Button(
            right, text="📂 Load Session",
            command=self._load_session,
            bg=COLORS["bg_hover"], fg=COLORS["text_primary"],
            font=FONTS["small"], relief="flat", padx=10, pady=4, cursor="hand2",
        ).pack(side="left", padx=4)

        tk.Button(
            right, text="🔄 New Session",
            command=self._new_session,
            bg=COLORS["status_warn"], fg="#ffffff",
            font=FONTS["small"], relief="flat", padx=10, pady=4, cursor="hand2",
        ).pack(side="left", padx=4)

        # Target field
        tk.Label(bar, text="Target:", bg=COLORS["bg_sidebar"],
                 fg=COLORS["text_secondary"], font=FONTS["small"]).pack(side="left", padx=(20, 4))
        self.target_var = tk.StringVar()
        te = tk.Entry(
            bar, textvariable=self.target_var,
            bg=COLORS["bg_input"], fg=COLORS["accent_cyan"],
            font=FONTS["body"], relief="flat", width=26,
            insertbackground=COLORS["accent_green"],
        )
        te.pack(side="left", padx=4, ipady=4)
        te.bind("<Return>", lambda e: self._set_target())
        tk.Button(
            bar, text="Set",
            command=self._set_target,
            bg=COLORS["accent_blue"], fg="#ffffff",
            font=FONTS["small"], relief="flat", padx=8, pady=4, cursor="hand2",
        ).pack(side="left", padx=2)

    def _build_sidebar(self, parent):
        self.sidebar = tk.Frame(
            parent, bg=COLORS["bg_sidebar"], width=220,
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(
            self.sidebar, text="MODULES",
            bg=COLORS["bg_sidebar"], fg=COLORS["text_muted"],
            font=FONTS["small"],
        ).pack(pady=(18, 6), padx=14, anchor="w")

        self.nav_buttons = {}
        for icon, label, key in NAV_ITEMS:
            self._nav_btn(icon, label, key)

        # ─ separator ─
        tk.Frame(self.sidebar, bg=COLORS["border"], height=1).pack(
            fill="x", padx=14, pady=10)

        # Session info
        self.session_info = tk.Label(
            self.sidebar, text="No target set",
            bg=COLORS["bg_sidebar"], fg=COLORS["text_muted"],
            font=FONTS["small"], wraplength=190, justify="left",
        )
        self.session_info.pack(padx=14, anchor="w")

        tk.Label(
            self.sidebar, text="\n⚙  Findings",
            bg=COLORS["bg_sidebar"], fg=COLORS["text_secondary"],
            font=FONTS["small"],
        ).pack(padx=14, anchor="w")

        self.findings_label = tk.Label(
            self.sidebar, text="0 findings recorded",
            bg=COLORS["bg_sidebar"], fg=COLORS["accent_yellow"],
            font=FONTS["small"],
        )
        self.findings_label.pack(padx=14, anchor="w")

    def _nav_btn(self, icon, label, key):
        frame = tk.Frame(self.sidebar, bg=COLORS["bg_sidebar"], cursor="hand2")
        frame.pack(fill="x", padx=8, pady=1)

        lbl = tk.Label(
            frame,
            text=f"  {icon}  {label}",
            bg=COLORS["bg_sidebar"],
            fg=COLORS["text_secondary"],
            font=FONTS["sidebar"],
            anchor="w",
        )
        lbl.pack(fill="x", ipady=10, padx=4)

        def on_click(k=key):
            self._switch(k)

        frame.bind("<Button-1>", lambda e, k=key: on_click(k))
        lbl.bind("<Button-1>",   lambda e, k=key: on_click(k))
        frame.bind("<Enter>", lambda e: frame.config(bg=COLORS["bg_hover"]) or lbl.config(bg=COLORS["bg_hover"]))
        frame.bind("<Leave>", lambda e: self._restore_nav_hover(key, frame, lbl))
        lbl.bind("<Enter>",   lambda e: frame.config(bg=COLORS["bg_hover"]) or lbl.config(bg=COLORS["bg_hover"]))
        lbl.bind("<Leave>",   lambda e: self._restore_nav_hover(key, frame, lbl))

        self.nav_buttons[key] = (frame, lbl)

    def _restore_nav_hover(self, key, frame, lbl):
        if self.active_module.get() == key:
            frame.config(bg=COLORS["bg_selected"])
            lbl.config(bg=COLORS["bg_selected"], fg=COLORS["text_primary"])
        else:
            frame.config(bg=COLORS["bg_sidebar"])
            lbl.config(bg=COLORS["bg_sidebar"], fg=COLORS["text_secondary"])

    def _build_content(self, parent):
        self.content = tk.Frame(parent, bg=COLORS["bg_dark"])
        self.content.pack(side="left", fill="both", expand=True)

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=COLORS["bg_sidebar"], height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self.status_var = tk.StringVar(value="Ready  |  No target selected")
        tk.Label(
            bar, textvariable=self.status_var,
            bg=COLORS["bg_sidebar"], fg=COLORS["text_muted"],
            font=FONTS["small"],
        ).pack(side="left", padx=12)
        tk.Label(
            bar, text="VAPT Pro v1.0  |  Educational Use Only",
            bg=COLORS["bg_sidebar"], fg=COLORS["text_muted"],
            font=FONTS["small"],
        ).pack(side="right", padx=12)

    # ─────────────────────────────── SWITCHING ────────────────────────────────

    def _switch(self, key: str):
        # Update sidebar highlight
        old = self.active_module.get()
        if old in self.nav_buttons:
            frame, lbl = self.nav_buttons[old]
            frame.config(bg=COLORS["bg_sidebar"])
            lbl.config(bg=COLORS["bg_sidebar"], fg=COLORS["text_secondary"])

        self.active_module.set(key)
        frame, lbl = self.nav_buttons[key]
        frame.config(bg=COLORS["bg_selected"])
        lbl.config(bg=COLORS["bg_selected"], fg=COLORS["text_primary"])

        # Hide all frames
        for child in self.content.winfo_children():
            child.pack_forget()

        # Lazy-load module
        if key not in self.modules:
            cls = MODULE_CLASSES[key]
            mod = cls(self.content, self._update_status, self._refresh_sidebar)
            mod.frame.pack(fill="both", expand=True)
            self.modules[key] = mod
        else:
            self.modules[key].frame.pack(fill="both", expand=True)
            self.modules[key].on_show()

        # Update status
        icon, label, _ = next(x for x in NAV_ITEMS if x[2] == key)
        self._update_status(f"Module: {label}")

    # ─────────────────────────────── ACTIONS ─────────────────────────────────

    def _set_target(self):
        t = self.target_var.get().strip()
        if not t:
            messagebox.showwarning("Target Required", "Please enter a target host/IP/URL.")
            return
        session.target = t
        self._update_status(f"Target set: {t}")
        self._refresh_sidebar()

    def _save_session(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Session", "*.json")],
            title="Save VAPT Session",
        )
        if path:
            session.save(path)
            messagebox.showinfo("Saved", f"Session saved to:\n{path}")

    def _load_session(self):
        path = filedialog.askopenfilename(
            filetypes=[("JSON Session", "*.json")],
            title="Load VAPT Session",
        )
        if path:
            session.load(path)
            self.target_var.set(session.target)
            self._refresh_sidebar()
            # Reload active module
            key = self.active_module.get()
            if key in self.modules:
                self.modules[key].on_show()
            messagebox.showinfo("Loaded", "Session loaded successfully.")

    def _new_session(self):
        if messagebox.askyesno("New Session",
                               "Start a new session? All unsaved data will be lost."):
            session.reset()
            self.target_var.set("")
            self.modules.clear()
            for child in self.content.winfo_children():
                child.destroy()
            self._switch("reconnaissance")
            self._refresh_sidebar()

    def _update_status(self, msg: str):
        target = f"  |  Target: {session.target}" if session.target else "  |  No target"
        self.status_var.set(f"{msg}{target}")

    def _refresh_sidebar(self):
        t = session.target or "No target set"
        self.session_info.config(text=t)
        n = len(session.findings)
        self.findings_label.config(
            text=f"{n} finding{'s' if n != 1 else ''} recorded",
            fg=COLORS["accent_red"] if n > 0 else COLORS["text_muted"],
        )

    def on_close(self):
        if messagebox.askyesno("Quit", "Exit VAPT Pro? Unsaved session data will be lost."):
            self.root.destroy()

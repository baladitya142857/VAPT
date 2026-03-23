"""
Reusable widgets for VAPT Pro GUI
"""
import tkinter as tk
from tkinter import ttk
from gui.theme import COLORS, FONTS


def make_scrolled_text(parent, height=20, **kwargs):
    """Return a Frame containing a Text + Scrollbar."""
    frame = tk.Frame(parent, bg=COLORS["bg_card"])
    sb = tk.Scrollbar(frame, bg=COLORS["bg_panel"], troughcolor=COLORS["bg_dark"])
    txt = tk.Text(
        frame,
        bg=COLORS["bg_input"],
        fg=COLORS["text_primary"],
        insertbackground=COLORS["accent_green"],
        font=FONTS["mono_small"],
        height=height,
        yscrollcommand=sb.set,
        relief="flat",
        borderwidth=0,
        selectbackground=COLORS["accent_blue"],
        **kwargs,
    )
    sb.config(command=txt.yview)
    sb.pack(side="right", fill="y")
    txt.pack(side="left", fill="both", expand=True)
    return frame, txt


def make_label(parent, text, style="body", fg=None, **kwargs):
    return tk.Label(
        parent,
        text=text,
        bg=COLORS["bg_panel"],
        fg=fg or COLORS["text_primary"],
        font=FONTS.get(style, FONTS["body"]),
        **kwargs,
    )


def make_entry(parent, width=40, **kwargs):
    return tk.Entry(
        parent,
        bg=COLORS["bg_input"],
        fg=COLORS["text_primary"],
        insertbackground=COLORS["accent_green"],
        font=FONTS["body"],
        relief="flat",
        borderwidth=4,
        width=width,
        selectbackground=COLORS["accent_blue"],
        **kwargs,
    )


def make_button(parent, text, command, color=None, **kwargs):
    btn_color = color or COLORS["accent_blue"]
    btn = tk.Button(
        parent,
        text=text,
        command=command,
        bg=btn_color,
        fg="#ffffff",
        font=FONTS["subheading"],
        relief="flat",
        borderwidth=0,
        padx=16,
        pady=8,
        cursor="hand2",
        activebackground=COLORS["bg_hover"],
        activeforeground=COLORS["text_primary"],
        **kwargs,
    )
    btn.bind("<Enter>", lambda e: btn.config(bg=COLORS["bg_hover"]))
    btn.bind("<Leave>", lambda e: btn.config(bg=btn_color))
    return btn


def make_danger_button(parent, text, command, **kwargs):
    return make_button(parent, text, command, color=COLORS["accent_red"], **kwargs)


def make_success_button(parent, text, command, **kwargs):
    return make_button(parent, text, command, color=COLORS["status_ok"], **kwargs)


def section_header(parent, text, bg=None):
    bg = bg or COLORS["bg_panel"]
    f = tk.Frame(parent, bg=bg)
    tk.Frame(f, bg=COLORS["accent_cyan"], width=4).pack(side="left", fill="y")
    tk.Label(
        f,
        text=f"  {text}",
        bg=bg,
        fg=COLORS["accent_cyan"],
        font=FONTS["heading"],
    ).pack(side="left", padx=4, pady=6)
    return f


def status_badge(parent, text, severity, bg=None):
    from gui.theme import SEVERITY_COLORS
    color = SEVERITY_COLORS.get(severity.upper(), COLORS["text_secondary"])
    bg = bg or COLORS["bg_card"]
    return tk.Label(
        parent,
        text=f" {text} ",
        bg=color,
        fg="#000000" if severity in ("LOW", "INFO") else "#ffffff",
        font=FONTS["small"],
        relief="flat",
    )


class TerminalOutput(tk.Frame):
    """Scrollable terminal-style output widget."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=COLORS["bg_dark"], **kwargs)
        # Header bar
        hdr = tk.Frame(self, bg=COLORS["bg_sidebar"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="●", bg=COLORS["bg_sidebar"],
                 fg=COLORS["accent_red"], font=FONTS["body"]).pack(side="left", padx=4)
        tk.Label(hdr, text="●", bg=COLORS["bg_sidebar"],
                 fg=COLORS["accent_yellow"], font=FONTS["body"]).pack(side="left", padx=2)
        tk.Label(hdr, text="●", bg=COLORS["bg_sidebar"],
                 fg=COLORS["accent_green"], font=FONTS["body"]).pack(side="left", padx=2)
        tk.Label(hdr, text=" Terminal Output", bg=COLORS["bg_sidebar"],
                 fg=COLORS["text_secondary"], font=FONTS["small"]).pack(side="left", padx=8)

        # Text area
        frm, self.txt = make_scrolled_text(self)
        frm.pack(fill="both", expand=True)
        self.txt.tag_configure("ok",    foreground=COLORS["accent_green"])
        self.txt.tag_configure("warn",  foreground=COLORS["accent_orange"])
        self.txt.tag_configure("error", foreground=COLORS["accent_red"])
        self.txt.tag_configure("info",  foreground=COLORS["accent_cyan"])
        self.txt.tag_configure("cmd",   foreground=COLORS["accent_purple"])
        self.txt.tag_configure("dim",   foreground=COLORS["text_muted"])

    def write(self, text, tag=""):
        self.txt.config(state="normal")
        self.txt.insert("end", text + "\n", tag)
        self.txt.see("end")
        self.txt.config(state="disabled")

    def clear(self):
        self.txt.config(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.config(state="disabled")

    def prompt(self, text):
        self.write(f"[>] {text}", "cmd")

    def ok(self, text):
        self.write(f"[✔] {text}", "ok")

    def warn(self, text):
        self.write(f"[!] {text}", "warn")

    def error(self, text):
        self.write(f"[✘] {text}", "error")

    def info(self, text):
        self.write(f"[i] {text}", "info")

    def dim(self, text):
        self.write(f"    {text}", "dim")

    def separator(self):
        self.write("─" * 70, "dim")

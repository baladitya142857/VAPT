"""
Dark cybersecurity theme for VAPT Pro
"""

# Color Palette - Dark Hacker Theme
COLORS = {
    # Backgrounds
    "bg_dark":       "#0d1117",
    "bg_panel":      "#161b22",
    "bg_sidebar":    "#010409",
    "bg_card":       "#1c2128",
    "bg_input":      "#21262d",
    "bg_hover":      "#2d333b",
    "bg_selected":   "#1f6feb",

    # Accent colors
    "accent_green":  "#39d353",
    "accent_blue":   "#1f6feb",
    "accent_red":    "#f85149",
    "accent_orange": "#d29922",
    "accent_purple": "#bc8cff",
    "accent_cyan":   "#58a6ff",
    "accent_yellow": "#e3b341",

    # Text
    "text_primary":  "#e6edf3",
    "text_secondary":"#8b949e",
    "text_muted":    "#484f58",
    "text_link":     "#58a6ff",

    # Borders
    "border":        "#30363d",
    "border_active": "#1f6feb",

    # Status
    "status_ok":     "#238636",
    "status_warn":   "#9e6a03",
    "status_error":  "#da3633",
    "status_info":   "#1158c7",

    # Severity
    "critical":      "#f85149",
    "high":          "#d29922",
    "medium":        "#58a6ff",
    "low":           "#39d353",
    "info":          "#8b949e",
}

FONTS = {
    "title":      ("Consolas", 20, "bold"),
    "heading":    ("Consolas", 14, "bold"),
    "subheading": ("Consolas", 12, "bold"),
    "body":       ("Consolas", 11),
    "small":      ("Consolas", 10),
    "mono":       ("Courier New", 11),
    "mono_small": ("Courier New", 10),
    "sidebar":    ("Consolas", 12, "bold"),
    "module":     ("Consolas", 13, "bold"),
}

SEVERITY_COLORS = {
    "CRITICAL": COLORS["critical"],
    "HIGH":     COLORS["high"],
    "MEDIUM":   COLORS["medium"],
    "LOW":      COLORS["low"],
    "INFO":     COLORS["info"],
}

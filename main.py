"""
VAPT Pro - Vulnerability Assessment & Penetration Testing Tool
Main entry point
"""

import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app import VAPTApp

def main():
    root = tk.Tk()
    root.title("VAPT Pro - Vulnerability Assessment & Penetration Testing")
    root.geometry("1280x800")
    root.minsize(1100, 700)
    
    # Set app icon if available
    try:
        root.iconbitmap("assets/icon.ico")
    except:
        pass
    
    app = VAPTApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

if __name__ == "__main__":
    main()

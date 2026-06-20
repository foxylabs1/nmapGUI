#!/usr/bin/env python3
"""
NmapGUI - GUI for nmap network scanner.
Run with sudo for SYN/UDP scans: sudo python3 main.py
TCP connect scans work without root.
"""

import tkinter as tk
from tkinter import ttk
import os
import sys
import atexit

from core.process import ProcessManager
from core.theme import apply_theme, style_text_widget, style_menu, BG, SIDEBAR_BG, FG, BORDER
from core.logger import setup_logging, LOG_FILE
from panels.scanner import ScannerPanel
from panels.results import ResultsPanel
from panels.scripts import ScriptsPanel
from panels.profiles import ProfilesPanel
from panels.history import HistoryPanel
from panels.log_viewer import LogPanel

APP_NAME = "NmapGUI"
APP_VERSION = "1.0.3"


class NmapGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1100x800")
        self.minsize(900, 650)

        apply_theme(self)

        self.pm = ProcessManager()
        atexit.register(self.pm.stop_all)

        self._build_ui()
        self._style_all_text_widgets()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        # --- Sidebar ---
        sidebar = tk.Frame(self, bg=SIDEBAR_BG, width=170)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Title
        title_frame = tk.Frame(sidebar, bg=SIDEBAR_BG)
        title_frame.pack(fill="x", padx=10, pady=(15, 5))

        tk.Label(title_frame, text="NMAP", bg=SIDEBAR_BG, fg=FG,
                 font=("Consolas", 18, "bold")).pack(anchor="w")
        tk.Label(title_frame, text="GUI", bg=SIDEBAR_BG, fg="#009926",
                 font=("Consolas", 18, "bold")).pack(anchor="w")

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=10, pady=10)

        # Nav buttons
        self.nav_buttons = {}
        self._active_nav = None
        panels = [
            ("\u25b8 Scanner",  "scanner"),
            ("\u25b8 Results",  "results"),
            ("\u25b8 Scripts",  "scripts"),
            ("\u25b8 Profiles", "profiles"),
            ("\u25b8 History",  "history"),
            ("\u25b8 Log",      "log"),
        ]

        for label, key in panels:
            btn = tk.Button(
                sidebar, text=label, anchor="w",
                bg=SIDEBAR_BG, fg="#00cc33",
                activebackground="#1a3a1a", activeforeground=FG,
                relief="flat", bd=0, padx=15, pady=8,
                font=("Consolas", 11),
                command=lambda k=key: self._show_panel(k),
            )
            btn.pack(fill="x", padx=5, pady=1)
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#0f1f0f"))
            btn.bind("<Leave>", lambda e, b=btn, k=key:
                     b.config(bg="#1a3a1a" if k == self._active_nav else SIDEBAR_BG))
            self.nav_buttons[key] = btn

        # Root status
        root_text = "root" if os.geteuid() == 0 else "user (limited)"
        root_color = FG if os.geteuid() == 0 else "#ffcc00"
        tk.Label(sidebar, text=f"Running as: {root_text}",
                 bg=SIDEBAR_BG, fg=root_color,
                 font=("Consolas", 8)).pack(side="bottom", padx=10, pady=(0, 5))

        tk.Label(sidebar, text=f"v{APP_VERSION}",
                 bg=SIDEBAR_BG, fg="#004d1a",
                 font=("Consolas", 9)).pack(side="bottom", padx=10, pady=(0, 2))

        # --- Separator ---
        tk.Frame(self, bg=BORDER, width=1).pack(side="left", fill="y")

        # --- Content ---
        self.content = ttk.Frame(self)
        self.content.pack(side="right", fill="both", expand=True)

        # Build panels with cross-panel wiring
        self.panels = {}

        self.panels["results"] = ResultsPanel(self.content)

        self.panels["scanner"] = ScannerPanel(
            self.content, self.pm,
            on_scan_complete=self._on_scan_complete,
        )

        self.panels["scripts"] = ScriptsPanel(
            self.content,
            set_scripts_callback=lambda s: self.panels["scanner"].scripts_var.set(s),
        )

        self.panels["profiles"] = ProfilesPanel(
            self.content,
            load_profile_callback=self._load_profile,
            get_current_profile_callback=lambda: self.panels["scanner"].get_profile(),
        )

        self.panels["history"] = HistoryPanel(
            self.content,
            load_results_callback=self._load_history_result,
        )

        self.panels["log"] = LogPanel(self.content)

        self._current = None
        self._show_panel("scanner")

    def _show_panel(self, key):
        if self._current == key:
            return

        if self._active_nav and self._active_nav in self.nav_buttons:
            self.nav_buttons[self._active_nav].config(bg=SIDEBAR_BG, fg="#00cc33")
        self.nav_buttons[key].config(bg="#1a3a1a", fg=FG)
        self._active_nav = key

        if self._current:
            self.panels[self._current].pack_forget()
        self.panels[key].pack(fill="both", expand=True)
        self._current = key

        # Auto-refresh history when switching to it
        if key == "history":
            self.panels["history"].refresh()

    def _on_scan_complete(self, xml_path):
        """Auto-load results and switch to results panel."""
        self.panels["results"].load_xml(xml_path)
        self._show_panel("results")

    def _load_profile(self, profile):
        """Load a profile into the scanner and switch to it."""
        self.panels["scanner"].load_profile(profile)
        self._show_panel("scanner")

    def _load_history_result(self, xml_path):
        """Load a historical scan result."""
        self.panels["results"].load_xml(xml_path)
        self._show_panel("results")

    def _style_all_text_widgets(self):
        for panel in self.panels.values():
            self._recursive_style(panel)

    def _recursive_style(self, widget):
        if isinstance(widget, tk.Text):
            style_text_widget(widget)
        if isinstance(widget, tk.Menu):
            style_menu(widget)
        for child in widget.winfo_children():
            self._recursive_style(child)

    def _on_close(self):
        self.pm.stop_all()
        self.destroy()


def main():
    logger = setup_logging()
    logger.info(f"Log file: {LOG_FILE}")

    from core.process import run_quick
    retcode, _ = run_quick(["which", "nmap"])
    if retcode != 0:
        logger.error("nmap not found")
        print("[!] nmap not found. Install with: sudo apt install nmap")
        sys.exit(1)

    if os.geteuid() != 0:
        print(f"[*] Running as user — SYN/UDP scans require root.")
        print(f"[*] For full functionality: sudo python3 main.py")

    try:
        app = NmapGUI()
        app.mainloop()
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()

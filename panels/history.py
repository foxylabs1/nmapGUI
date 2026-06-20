"""
History Panel - list and reload previous scan results.
"""

import tkinter as tk
from tkinter import ttk
import os

from core.nmap_parser import list_saved_scans
from core.logger import get_scans_dir


class HistoryPanel(ttk.Frame):
    def __init__(self, parent, load_results_callback=None):
        super().__init__(parent)
        self.load_results = load_results_callback
        self._build_ui()

    def _build_ui(self):
        header = ttk.Frame(self)
        header.pack(fill="x", padx=10, pady=(10, 5))

        ttk.Label(header, text="Scan History", style="Header.TLabel").pack(side="left")
        ttk.Button(header, text="Refresh", command=self.refresh).pack(side="right")

        # Scan list
        list_frame = ttk.Frame(self)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        cols = ("time", "command", "hosts", "file")
        self.tree = ttk.Treeview(list_frame, columns=cols, show="headings", height=18)
        self.tree.heading("time", text="Date/Time")
        self.tree.heading("command", text="Command")
        self.tree.heading("hosts", text="Hosts Up")
        self.tree.heading("file", text="File")

        self.tree.column("time", width=180)
        self.tree.column("command", width=350)
        self.tree.column("hosts", width=70)
        self.tree.column("file", width=150)

        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=(5, 5))

        ttk.Button(btn_frame, text="Load Selected", command=self._load_selected).pack(
            side="left", padx=2
        )
        ttk.Button(btn_frame, text="Delete Selected", command=self._delete_selected).pack(
            side="left", padx=2
        )

        # Scan directory info
        self.dir_var = tk.StringVar(value=f"Scans: {get_scans_dir()}")
        ttk.Label(self, textvariable=self.dir_var, style="Dim.TLabel").pack(
            anchor="w", padx=10, pady=(0, 10)
        )

    def refresh(self):
        """Reload scan list from disk."""
        self.tree.delete(*self.tree.get_children())

        scans = list_saved_scans(get_scans_dir())
        for scan in scans:
            cmd = scan["command"]
            if len(cmd) > 60:
                cmd = cmd[:57] + "..."

            self.tree.insert("", "end", values=(
                scan["time"],
                cmd,
                scan["hosts_up"],
                scan["filename"],
            ))

    def _load_selected(self):
        sel = self.tree.selection()
        if not sel:
            return

        filename = self.tree.item(sel[0])["values"][3]
        path = os.path.join(get_scans_dir(), filename)

        if self.load_results and os.path.exists(path):
            self.load_results(path)

    def _delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            return

        filename = self.tree.item(sel[0])["values"][3]
        path = os.path.join(get_scans_dir(), filename)

        if os.path.exists(path):
            os.remove(path)
            self.refresh()

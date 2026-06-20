"""
Scripts Panel - browse and select NSE scripts.
"""

import tkinter as tk
from tkinter import ttk
import subprocess
import os

from core.theme import style_text_widget


class ScriptsPanel(ttk.Frame):
    SCRIPT_DIR = "/usr/share/nmap/scripts"

    def __init__(self, parent, set_scripts_callback=None):
        super().__init__(parent)
        self.set_scripts = set_scripts_callback
        self._all_scripts = []
        self._selected = set()
        self._build_ui()
        self._load_scripts()

    def _build_ui(self):
        ttk.Label(self, text="NSE Scripts", style="Header.TLabel").pack(
            anchor="w", padx=10, pady=(10, 5)
        )

        # Search / filter
        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(filter_frame, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._filter_scripts())
        ttk.Entry(filter_frame, textvariable=self.search_var, width=30).pack(
            side="left", padx=5
        )

        ttk.Label(filter_frame, text="Category:").pack(side="left", padx=(10, 0))
        self.category_var = tk.StringVar(value="all")
        self.cat_combo = ttk.Combobox(filter_frame, textvariable=self.category_var,
                                       width=15, state="readonly")
        self.cat_combo.pack(side="left", padx=5)
        self.cat_combo.bind("<<ComboboxSelected>>", lambda e: self._filter_scripts())

        # Script list
        list_frame = ttk.Frame(self)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        cols = ("name", "categories")
        self.script_tree = ttk.Treeview(list_frame, columns=cols, show="headings", height=15)
        self.script_tree.heading("name", text="Script Name")
        self.script_tree.heading("categories", text="Categories")
        self.script_tree.column("name", width=300)
        self.script_tree.column("categories", width=300)

        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.script_tree.yview)
        self.script_tree.configure(yscrollcommand=scroll.set)
        self.script_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.script_tree.bind("<<TreeviewSelect>>", self._on_select)

        # Buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=5)

        ttk.Button(btn_frame, text="Add Selected", command=self._add_selected).pack(
            side="left", padx=2
        )
        ttk.Button(btn_frame, text="Clear Selection", command=self._clear_selected).pack(
            side="left", padx=2
        )

        self.selected_var = tk.StringVar(value="Selected: none")
        ttk.Label(btn_frame, textvariable=self.selected_var).pack(side="left", padx=10)

        ttk.Button(btn_frame, text="Apply to Scanner", command=self._apply).pack(
            side="right", padx=2
        )

        # Script description
        desc_frame = ttk.LabelFrame(self, text="Description")
        desc_frame.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        self.desc_text = tk.Text(desc_frame, height=6, state="disabled", wrap="word")
        self.desc_text.pack(fill="both", expand=True, padx=5, pady=5)
        style_text_widget(self.desc_text)

    def _load_scripts(self):
        """Load NSE scripts from the filesystem."""
        if not os.path.isdir(self.SCRIPT_DIR):
            return

        categories = set()
        for f in sorted(os.listdir(self.SCRIPT_DIR)):
            if not f.endswith(".nse"):
                continue
            name = f[:-4]  # strip .nse

            # Try to get categories from script header
            cats = self._get_script_categories(os.path.join(self.SCRIPT_DIR, f))
            cat_str = ", ".join(cats) if cats else "unknown"

            self._all_scripts.append({
                "name": name,
                "file": f,
                "categories": cats,
                "cat_str": cat_str,
            })
            categories.update(cats)

        # Populate category filter
        cat_list = ["all"] + sorted(categories)
        self.cat_combo.config(values=cat_list)

        self._filter_scripts()

    def _get_script_categories(self, filepath):
        """Extract categories from script file header."""
        cats = []
        try:
            with open(filepath, "r", errors="ignore") as f:
                header = f.read(5000)
            for line in header.splitlines():
                if "categories" in line and "{" in line:
                    start = line.find("{")
                    end = line.find("}")
                    if start >= 0 and end > start:
                        raw = line[start + 1:end]
                        cats = [c.strip().strip('"').strip("'")
                                for c in raw.split(",")]
                    break
        except (IOError, OSError):
            pass
        return cats

    def _filter_scripts(self):
        """Filter scripts by search text and category."""
        self.script_tree.delete(*self.script_tree.get_children())

        search = self.search_var.get().lower()
        cat_filter = self.category_var.get()

        for script in self._all_scripts:
            if search and search not in script["name"].lower():
                continue
            if cat_filter != "all" and cat_filter not in script["categories"]:
                continue

            tag = "selected" if script["name"] in self._selected else ""
            self.script_tree.insert("", "end", values=(
                script["name"], script["cat_str"]
            ), tags=(tag,))

        self.script_tree.tag_configure("selected", foreground="#33ff66")

    def _on_select(self, event):
        """Show script description when selected."""
        sel = self.script_tree.selection()
        if not sel:
            return

        name = self.script_tree.item(sel[0])["values"][0]
        filepath = os.path.join(self.SCRIPT_DIR, f"{name}.nse")

        desc = self._get_script_description(filepath)
        self.desc_text.config(state="normal")
        self.desc_text.delete("1.0", "end")
        self.desc_text.insert("1.0", desc)
        self.desc_text.config(state="disabled")

    def _get_script_description(self, filepath):
        """Extract description from NSE script."""
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read(3000)

            # Look for description block
            if "description" in content:
                start = content.find("description")
                # Find the string content after description = or description [[
                for marker in ['[[', '="', "='", '= [[', '= "', "= '"]:
                    idx = content.find(marker, start)
                    if idx >= 0:
                        end_marker = "]]" if "[[" in marker else marker[-1]
                        end = content.find(end_marker, idx + len(marker))
                        if end > idx:
                            return content[idx + len(marker):end].strip()

            return "No description available."
        except (IOError, OSError):
            return "Could not read script file."

    def _add_selected(self):
        for sel in self.script_tree.selection():
            name = self.script_tree.item(sel)["values"][0]
            self._selected.add(name)

        self.selected_var.set(f"Selected: {', '.join(sorted(self._selected))}")
        self._filter_scripts()

    def _clear_selected(self):
        self._selected.clear()
        self.selected_var.set("Selected: none")
        self._filter_scripts()

    def _apply(self):
        """Send selected scripts to the scanner panel."""
        if self.set_scripts and self._selected:
            self.set_scripts(",".join(sorted(self._selected)))

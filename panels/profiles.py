"""
Profiles Panel - built-in and custom scan presets.
"""

import tkinter as tk
from tkinter import ttk
import json
import os

from core.logger import get_logger

LOG_DIR = os.path.join(os.path.expanduser("~"), ".local", "share", "nmapgui")
PROFILES_FILE = os.path.join(LOG_DIR, "profiles.json")

BUILTIN_PROFILES = {
    "Quick Scan": {
        "scan_type": "-sS  (SYN Stealth)",
        "timing": "-T4  (Aggressive)",
        "ports": "top100",
        "service_detect": False,
        "os_detect": False,
        "aggressive": False,
        "no_ping": False,
        "scripts": "",
    },
    "Intense Scan": {
        "scan_type": "-sS  (SYN Stealth)",
        "timing": "-T4  (Aggressive)",
        "ports": "top1000",
        "service_detect": True,
        "os_detect": True,
        "aggressive": False,
        "no_ping": False,
        "scripts": "default",
    },
    "Full TCP": {
        "scan_type": "-sT  (TCP Connect)",
        "timing": "-T3  (Normal)",
        "ports": "all",
        "service_detect": True,
        "os_detect": False,
        "aggressive": False,
        "no_ping": False,
        "scripts": "",
    },
    "UDP Top 100": {
        "scan_type": "-sU  (UDP)",
        "timing": "-T4  (Aggressive)",
        "ports": "top100",
        "service_detect": True,
        "os_detect": False,
        "aggressive": False,
        "no_ping": False,
        "scripts": "",
    },
    "Aggressive + Scripts": {
        "scan_type": "-sS  (SYN Stealth)",
        "timing": "-T4  (Aggressive)",
        "ports": "top1000",
        "service_detect": True,
        "os_detect": True,
        "aggressive": True,
        "no_ping": False,
        "scripts": "default,vuln",
    },
    "Stealth Scan": {
        "scan_type": "-sS  (SYN Stealth)",
        "timing": "-T2  (Polite)",
        "ports": "top1000",
        "service_detect": False,
        "os_detect": False,
        "aggressive": False,
        "no_ping": False,
        "scripts": "",
    },
    "Ping Sweep": {
        "scan_type": "-sP  (Ping Only)",
        "timing": "-T4  (Aggressive)",
        "ports": "top1000",
        "service_detect": False,
        "os_detect": False,
        "aggressive": False,
        "no_ping": False,
        "scripts": "",
    },
    "Vuln Scan": {
        "scan_type": "-sS  (SYN Stealth)",
        "timing": "-T3  (Normal)",
        "ports": "top1000",
        "service_detect": True,
        "os_detect": False,
        "aggressive": False,
        "no_ping": False,
        "scripts": "vuln",
    },
}


class ProfilesPanel(ttk.Frame):
    def __init__(self, parent, load_profile_callback=None, get_current_profile_callback=None):
        super().__init__(parent)
        self.load_profile = load_profile_callback
        self.get_current_profile = get_current_profile_callback
        self._custom_profiles = {}
        self._load_custom_profiles()
        self._build_ui()

    def _build_ui(self):
        ttk.Label(self, text="Scan Profiles", style="Header.TLabel").pack(
            anchor="w", padx=10, pady=(10, 5)
        )

        # --- Built-in Profiles ---
        builtin_frame = ttk.LabelFrame(self, text="Built-in Profiles")
        builtin_frame.pack(fill="x", padx=10, pady=5)

        for name, profile in BUILTIN_PROFILES.items():
            row = ttk.Frame(builtin_frame)
            row.pack(fill="x", padx=5, pady=2)

            ttk.Button(row, text="Load", width=6,
                       command=lambda p=profile: self._load(p)).pack(side="left", padx=2)
            ttk.Label(row, text=name, font=("Consolas", 10, "bold")).pack(side="left", padx=5)

            desc = self._describe_profile(profile)
            ttk.Label(row, text=desc, style="Dim.TLabel").pack(side="left", padx=5)

        # --- Custom Profiles ---
        custom_frame = ttk.LabelFrame(self, text="Custom Profiles")
        custom_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.custom_list = ttk.Frame(custom_frame)
        self.custom_list.pack(fill="both", expand=True, padx=5, pady=5)

        self._refresh_custom_list()

        # Save new profile
        save_frame = ttk.Frame(self)
        save_frame.pack(fill="x", padx=10, pady=(5, 10))

        ttk.Label(save_frame, text="Profile name:").pack(side="left")
        self.name_var = tk.StringVar()
        ttk.Entry(save_frame, textvariable=self.name_var, width=25).pack(
            side="left", padx=5
        )
        ttk.Button(save_frame, text="Save Current Settings",
                   command=self._save_current).pack(side="left", padx=5)

    def _describe_profile(self, profile):
        parts = []
        scan = profile.get("scan_type", "").split()[0]
        parts.append(scan)
        parts.append(profile.get("timing", "").split()[0])
        parts.append(f"ports:{profile.get('ports', 'top1000')}")
        if profile.get("service_detect"):
            parts.append("-sV")
        if profile.get("os_detect"):
            parts.append("-O")
        if profile.get("aggressive"):
            parts.append("-A")
        if profile.get("scripts"):
            parts.append(f"scripts:{profile['scripts']}")
        return " ".join(parts)

    def _load(self, profile):
        if self.load_profile:
            self.load_profile(profile)

    def _save_current(self):
        name = self.name_var.get().strip()
        if not name:
            return

        if self.get_current_profile:
            profile = self.get_current_profile()
        else:
            profile = {
                "scan_type": "-sS  (SYN Stealth)",
                "timing": "-T3  (Normal)",
                "ports": "top1000",
                "service_detect": True,
                "os_detect": False,
                "aggressive": False,
                "no_ping": False,
                "scripts": "",
            }

        self._custom_profiles[name] = profile
        self._save_custom_profiles()
        self._refresh_custom_list()
        self.name_var.set("")

    def _refresh_custom_list(self):
        for w in self.custom_list.winfo_children():
            w.destroy()

        if not self._custom_profiles:
            ttk.Label(self.custom_list, text="No custom profiles saved",
                      style="Dim.TLabel").pack(padx=5, pady=5)
            return

        for name, profile in self._custom_profiles.items():
            row = ttk.Frame(self.custom_list)
            row.pack(fill="x", pady=2)

            ttk.Button(row, text="Load", width=6,
                       command=lambda p=profile: self._load(p)).pack(side="left", padx=2)
            ttk.Label(row, text=name, font=("Consolas", 10, "bold")).pack(side="left", padx=5)
            ttk.Button(row, text="Delete", width=6,
                       command=lambda n=name: self._delete_profile(n)).pack(side="right", padx=2)

    def _delete_profile(self, name):
        self._custom_profiles.pop(name, None)
        self._save_custom_profiles()
        self._refresh_custom_list()

    def _load_custom_profiles(self):
        if os.path.exists(PROFILES_FILE):
            try:
                with open(PROFILES_FILE, "r") as f:
                    self._custom_profiles = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._custom_profiles = {}

    def _save_custom_profiles(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(PROFILES_FILE, "w") as f:
            json.dump(self._custom_profiles, f, indent=2)

"""
Scanner Panel - configure and run nmap scans.
"""

import tkinter as tk
from tkinter import ttk
import os
import shlex
from datetime import datetime

from core.theme import style_text_widget
from core.logger import get_logger, get_scans_dir


class ScannerPanel(ttk.Frame):
    def __init__(self, parent, process_manager, on_scan_complete=None):
        super().__init__(parent)
        self.pm = process_manager
        self.on_scan_complete = on_scan_complete
        self._log_obj = get_logger("scanner")
        self._poll_id = None
        self._xml_path = None
        self._build_ui()

    def _build_ui(self):
        # Header
        ttk.Label(self, text="Nmap Scanner", style="Header.TLabel").pack(
            anchor="w", padx=10, pady=(10, 5)
        )

        # --- Target ---
        target_frame = ttk.LabelFrame(self, text="Target")
        target_frame.pack(fill="x", padx=10, pady=5)

        t_row = ttk.Frame(target_frame)
        t_row.pack(fill="x", padx=5, pady=5)

        ttk.Label(t_row, text="Target:").pack(side="left")
        self.target_var = tk.StringVar()
        ttk.Entry(t_row, textvariable=self.target_var, width=40).pack(
            side="left", padx=5, fill="x", expand=True
        )
        ttk.Label(t_row, text="IP, CIDR, hostname, or range", style="Dim.TLabel").pack(
            side="left", padx=5
        )

        # --- Scan Type ---
        type_frame = ttk.LabelFrame(self, text="Scan Configuration")
        type_frame.pack(fill="x", padx=10, pady=5)

        row1 = ttk.Frame(type_frame)
        row1.pack(fill="x", padx=5, pady=3)

        ttk.Label(row1, text="Scan Type:").pack(side="left")
        self.scan_type = tk.StringVar(value="-sS")
        types = ttk.Combobox(row1, textvariable=self.scan_type, width=25, state="readonly",
                             values=[
                                 "-sS  (SYN Stealth)",
                                 "-sT  (TCP Connect)",
                                 "-sU  (UDP)",
                                 "-sA  (ACK)",
                                 "-sW  (Window)",
                                 "-sN  (Null)",
                                 "-sF  (FIN)",
                                 "-sX  (Xmas)",
                                 "-sP  (Ping Only)",
                             ])
        types.pack(side="left", padx=5)
        types.current(0)

        ttk.Label(row1, text="Timing:").pack(side="left", padx=(15, 0))
        self.timing_var = tk.StringVar(value="-T3")
        timing = ttk.Combobox(row1, textvariable=self.timing_var, width=20, state="readonly",
                              values=[
                                  "-T0  (Paranoid)",
                                  "-T1  (Sneaky)",
                                  "-T2  (Polite)",
                                  "-T3  (Normal)",
                                  "-T4  (Aggressive)",
                                  "-T5  (Insane)",
                              ])
        timing.pack(side="left", padx=5)
        timing.current(3)

        # Port specification
        row2 = ttk.Frame(type_frame)
        row2.pack(fill="x", padx=5, pady=3)

        ttk.Label(row2, text="Ports:").pack(side="left")
        self.port_mode = tk.StringVar(value="top1000")
        port_modes = ttk.Combobox(row2, textvariable=self.port_mode, width=18, state="readonly",
                                  values=["top1000", "top100", "all", "custom"])
        port_modes.pack(side="left", padx=5)

        ttk.Label(row2, text="Custom:").pack(side="left", padx=(10, 0))
        self.custom_ports = tk.StringVar()
        self.custom_ports_entry = ttk.Entry(row2, textvariable=self.custom_ports, width=25)
        self.custom_ports_entry.pack(side="left", padx=5)
        ttk.Label(row2, text="e.g. 22,80,443 or 1-1024", style="Dim.TLabel").pack(side="left")

        # Options checkboxes
        row3 = ttk.Frame(type_frame)
        row3.pack(fill="x", padx=5, pady=3)

        self.service_detect = tk.BooleanVar(value=True)
        ttk.Checkbutton(row3, text="Service Detection (-sV)",
                        variable=self.service_detect).pack(side="left", padx=5)

        self.os_detect = tk.BooleanVar()
        ttk.Checkbutton(row3, text="OS Detection (-O)",
                        variable=self.os_detect).pack(side="left", padx=5)

        self.aggressive = tk.BooleanVar()
        ttk.Checkbutton(row3, text="Aggressive (-A)",
                        variable=self.aggressive).pack(side="left", padx=5)

        self.no_ping = tk.BooleanVar()
        ttk.Checkbutton(row3, text="No Ping (-Pn)",
                        variable=self.no_ping).pack(side="left", padx=5)

        self.verbose = tk.BooleanVar(value=True)
        ttk.Checkbutton(row3, text="Verbose (-v)",
                        variable=self.verbose).pack(side="left", padx=5)

        # Extra flags
        row4 = ttk.Frame(type_frame)
        row4.pack(fill="x", padx=5, pady=3)

        ttk.Label(row4, text="Extra flags:").pack(side="left")
        self.extra_flags = tk.StringVar()
        ttk.Entry(row4, textvariable=self.extra_flags, width=40).pack(
            side="left", padx=5, fill="x", expand=True
        )

        # --- NSE Scripts ---
        row5 = ttk.Frame(type_frame)
        row5.pack(fill="x", padx=5, pady=3)

        ttk.Label(row5, text="NSE Scripts:").pack(side="left")
        self.scripts_var = tk.StringVar()
        ttk.Entry(row5, textvariable=self.scripts_var, width=35).pack(
            side="left", padx=5, fill="x", expand=True
        )
        ttk.Label(row5, text="e.g. vuln,default or http-*", style="Dim.TLabel").pack(side="left")

        # --- Command Preview ---
        cmd_frame = ttk.LabelFrame(self, text="Command Preview")
        cmd_frame.pack(fill="x", padx=10, pady=5)

        self.cmd_preview = tk.StringVar(value="nmap")
        ttk.Label(cmd_frame, textvariable=self.cmd_preview, wraplength=700,
                  font=("Consolas", 10)).pack(padx=5, pady=5, anchor="w")

        # Update preview when anything changes
        for var in [self.target_var, self.scan_type, self.timing_var,
                    self.port_mode, self.custom_ports, self.extra_flags,
                    self.scripts_var]:
            var.trace_add("write", lambda *a: self._update_preview())
        for var in [self.service_detect, self.os_detect, self.aggressive,
                    self.no_ping, self.verbose]:
            var.trace_add("write", lambda *a: self._update_preview())

        # --- Buttons ---
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=5)

        self.btn_scan = ttk.Button(btn_frame, text="Start Scan", command=self._start_scan)
        self.btn_scan.pack(side="left", padx=2)

        self.btn_stop = ttk.Button(btn_frame, text="Stop", command=self._stop_scan,
                                   state="disabled")
        self.btn_stop.pack(side="left", padx=2)

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(btn_frame, textvariable=self.status_var).pack(side="left", padx=10)

        # --- Output Log ---
        log_frame = ttk.LabelFrame(self, text="Output")
        log_frame.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        self.log = tk.Text(log_frame, height=10, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True, padx=5, pady=5)
        style_text_widget(self.log)

    def _build_command(self):
        """Build the nmap command from current settings."""
        cmd = ["nmap"]

        # Scan type
        scan_type = self.scan_type.get().split()[0]
        cmd.append(scan_type)

        # Timing
        timing = self.timing_var.get().split()[0]
        cmd.append(timing)

        # Ports
        mode = self.port_mode.get()
        if mode == "top100":
            cmd.extend(["--top-ports", "100"])
        elif mode == "all":
            cmd.append("-p-")
        elif mode == "custom":
            custom = self.custom_ports.get().strip()
            if custom:
                cmd.extend(["-p", custom])

        # Options
        if self.aggressive.get():
            cmd.append("-A")
        else:
            if self.service_detect.get():
                cmd.append("-sV")
            if self.os_detect.get():
                cmd.append("-O")

        if self.no_ping.get():
            cmd.append("-Pn")
        if self.verbose.get():
            cmd.append("-v")

        # NSE scripts
        scripts = self.scripts_var.get().strip()
        if scripts:
            cmd.extend(["--script", scripts])

        # Extra flags
        extra = self.extra_flags.get().strip()
        if extra:
            cmd.extend(shlex.split(extra))

        # XML output
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scans_dir = get_scans_dir()
        self._xml_path = os.path.join(scans_dir, f"scan_{timestamp}.xml")
        cmd.extend(["-oX", self._xml_path])

        # Target
        target = self.target_var.get().strip()
        if target:
            cmd.append(target)

        return cmd

    def _update_preview(self):
        cmd = self._build_command()
        self.cmd_preview.set(" ".join(cmd))

    def _start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            self._log("[!] Enter a target")
            return

        cmd = self._build_command()

        # Check if scan type needs root
        scan_type = self.scan_type.get().split()[0]
        needs_root = (scan_type in ("-sS", "-sA", "-sW", "-sN", "-sF", "-sX", "-sU")
                      or self.os_detect.get())

        if needs_root and os.geteuid() != 0:
            self._log("[!] This scan type requires root. Run nmapgui with sudo.")
            return

        self._log(f"\n$ {' '.join(cmd)}")
        self._log_obj.info(f"Scan started: {' '.join(cmd)}")

        self.pm.start("nmap", cmd)
        self.btn_scan.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.status_var.set("Scanning...")
        self._poll_output()

    def _stop_scan(self):
        self.pm.stop("nmap")
        self.btn_scan.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status_var.set("Scan stopped")
        self._log("[*] Scan stopped")
        if self._poll_id:
            self.after_cancel(self._poll_id)
            self._poll_id = None

    def _poll_output(self):
        proc = self.pm.get("nmap")
        if proc and proc.is_running():
            for line in proc.drain_queue():
                self._log(line)
            self._poll_id = self.after(300, self._poll_output)
        else:
            if proc:
                for line in proc.drain_queue():
                    self._log(line)
            self.btn_scan.config(state="normal")
            self.btn_stop.config(state="disabled")
            self.status_var.set("Scan complete")
            self._log_obj.info(f"Scan complete: {self._xml_path}")

            if self.on_scan_complete and self._xml_path:
                self.on_scan_complete(self._xml_path)

    def load_profile(self, profile):
        """Load a scan profile dict into the UI."""
        if "scan_type" in profile:
            self.scan_type.set(profile["scan_type"])
        if "timing" in profile:
            self.timing_var.set(profile["timing"])
        if "ports" in profile:
            self.port_mode.set(profile["ports"])
        if "custom_ports" in profile:
            self.custom_ports.set(profile["custom_ports"])
        if "service_detect" in profile:
            self.service_detect.set(profile["service_detect"])
        if "os_detect" in profile:
            self.os_detect.set(profile["os_detect"])
        if "aggressive" in profile:
            self.aggressive.set(profile["aggressive"])
        if "no_ping" in profile:
            self.no_ping.set(profile["no_ping"])
        if "scripts" in profile:
            self.scripts_var.set(profile["scripts"])

    def get_xml_path(self):
        return self._xml_path

    def get_profile(self):
        """Return current scanner settings as a profile dict."""
        return {
            "scan_type": self.scan_type.get(),
            "timing": self.timing_var.get(),
            "ports": self.port_mode.get(),
            "custom_ports": self.custom_ports.get(),
            "service_detect": self.service_detect.get(),
            "os_detect": self.os_detect.get(),
            "aggressive": self.aggressive.get(),
            "no_ping": self.no_ping.get(),
            "scripts": self.scripts_var.get(),
        }

    def _log(self, text):
        self.log.config(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

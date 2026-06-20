"""
Results Panel - displays parsed nmap scan results.
Host table, port table, service details, script output.
"""

import tkinter as tk
from tkinter import ttk

from core.nmap_parser import parse_nmap_xml
from core.theme import style_text_widget


class ResultsPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self._result = None
        self._build_ui()

    def _build_ui(self):
        ttk.Label(self, text="Scan Results", style="Header.TLabel").pack(
            anchor="w", padx=10, pady=(10, 5)
        )

        # --- Summary ---
        self.summary_var = tk.StringVar(value="No scan loaded")
        ttk.Label(self, textvariable=self.summary_var).pack(
            anchor="w", padx=10, pady=2
        )

        self.cmd_var = tk.StringVar()
        ttk.Label(self, textvariable=self.cmd_var, style="Dim.TLabel",
                  wraplength=700).pack(anchor="w", padx=10, pady=(0, 5))

        # --- Main paned view ---
        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=5)

        # Top: host table
        host_frame = ttk.LabelFrame(self, text="Hosts")
        paned.add(host_frame, weight=1)

        h_cols = ("ip", "hostname", "state", "os", "ports")
        self.host_tree = ttk.Treeview(host_frame, columns=h_cols, show="headings", height=8)
        self.host_tree.heading("ip", text="IP Address")
        self.host_tree.heading("hostname", text="Hostname")
        self.host_tree.heading("state", text="State")
        self.host_tree.heading("os", text="OS Guess")
        self.host_tree.heading("ports", text="Open Ports")

        self.host_tree.column("ip", width=140)
        self.host_tree.column("hostname", width=180)
        self.host_tree.column("state", width=70)
        self.host_tree.column("os", width=200)
        self.host_tree.column("ports", width=80)

        h_scroll = ttk.Scrollbar(host_frame, orient="vertical", command=self.host_tree.yview)
        self.host_tree.configure(yscrollcommand=h_scroll.set)
        self.host_tree.pack(side="left", fill="both", expand=True)
        h_scroll.pack(side="right", fill="y")

        self.host_tree.bind("<<TreeviewSelect>>", self._on_host_select)

        # Middle: port table
        port_frame = ttk.LabelFrame(self, text="Ports")
        paned.add(port_frame, weight=1)

        p_cols = ("port", "protocol", "state", "service", "version")
        self.port_tree = ttk.Treeview(port_frame, columns=p_cols, show="headings", height=8)
        self.port_tree.heading("port", text="Port")
        self.port_tree.heading("protocol", text="Proto")
        self.port_tree.heading("state", text="State")
        self.port_tree.heading("service", text="Service")
        self.port_tree.heading("version", text="Version")

        self.port_tree.column("port", width=70)
        self.port_tree.column("protocol", width=55)
        self.port_tree.column("state", width=70)
        self.port_tree.column("service", width=120)
        self.port_tree.column("version", width=300)

        p_scroll = ttk.Scrollbar(port_frame, orient="vertical", command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=p_scroll.set)
        self.port_tree.pack(side="left", fill="both", expand=True)
        p_scroll.pack(side="right", fill="y")

        self.port_tree.bind("<<TreeviewSelect>>", self._on_port_select)

        # Bottom: details / script output
        detail_frame = ttk.LabelFrame(self, text="Details / Script Output")
        paned.add(detail_frame, weight=1)

        self.detail_text = tk.Text(detail_frame, height=8, state="disabled", wrap="word")
        self.detail_text.pack(fill="both", expand=True, padx=5, pady=5)
        style_text_widget(self.detail_text)

    def load_xml(self, xml_path):
        """Parse and display results from an nmap XML file."""
        self._result = parse_nmap_xml(xml_path)
        self._display_results()

    def _display_results(self):
        if not self._result:
            return

        r = self._result

        # Summary
        self.summary_var.set(
            f"{r.hosts_up} host(s) up, {r.hosts_down} down — "
            f"completed in {r.elapsed}s"
        )
        self.cmd_var.set(r.command)

        # Populate host tree
        self.host_tree.delete(*self.host_tree.get_children())
        self.port_tree.delete(*self.port_tree.get_children())
        self._clear_details()

        for i, host in enumerate(r.hosts):
            os_guess = host.os_matches[0]["name"] if host.os_matches else ""
            open_ports = sum(1 for p in host.ports if p.state == "open")

            self.host_tree.insert("", "end", iid=str(i), values=(
                host.ip,
                host.hostname,
                host.state,
                os_guess[:50],
                open_ports,
            ))

        # Auto-select first host
        children = self.host_tree.get_children()
        if children:
            self.host_tree.selection_set(children[0])
            self._on_host_select(None)

    def _on_host_select(self, event):
        """When a host is selected, show its ports."""
        sel = self.host_tree.selection()
        if not sel:
            return

        idx = int(sel[0])
        host = self._result.hosts[idx]

        self.port_tree.delete(*self.port_tree.get_children())

        for i, port in enumerate(host.ports):
            self.port_tree.insert("", "end", iid=str(i), values=(
                port.port,
                port.protocol,
                port.state,
                port.service,
                port.version,
            ))

        # Show host details
        self._clear_details()
        details = []
        details.append(f"Host: {host.ip}")
        if host.hostname:
            details.append(f"Hostname: {host.hostname}")
        if host.mac:
            details.append(f"MAC: {host.mac} ({host.vendor})")
        details.append(f"State: {host.state}")

        if host.os_matches:
            details.append("\nOS Detection:")
            for os_match in host.os_matches[:5]:
                details.append(f"  {os_match['accuracy']}% - {os_match['name']}")

        if host.scripts:
            details.append("\nHost Scripts:")
            for script in host.scripts:
                details.append(f"\n--- {script['id']} ---")
                details.append(script['output'])

        self._set_details("\n".join(details))

    def _on_port_select(self, event):
        """When a port is selected, show its details and scripts."""
        host_sel = self.host_tree.selection()
        port_sel = self.port_tree.selection()
        if not host_sel or not port_sel:
            return

        host_idx = int(host_sel[0])
        port_idx = int(port_sel[0])

        host = self._result.hosts[host_idx]
        port = host.ports[port_idx]

        details = []
        details.append(f"Port: {port.port}/{port.protocol}")
        details.append(f"State: {port.state}")
        details.append(f"Service: {port.service}")
        if port.version:
            details.append(f"Version: {port.version}")

        if port.scripts:
            details.append("\nScript Output:")
            for script in port.scripts:
                details.append(f"\n--- {script['id']} ---")
                details.append(script['output'])

        self._set_details("\n".join(details))

    def _set_details(self, text):
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.config(state="disabled")

    def _clear_details(self):
        self._set_details("")

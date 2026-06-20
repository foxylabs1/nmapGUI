"""
Parser for nmap XML output (-oX flag).
Extracts hosts, ports, services, OS detection, and script results.
"""

import xml.etree.ElementTree as ET
import os


class NmapResult:
    """Parsed nmap scan result."""

    def __init__(self):
        self.command = ""
        self.start_time = ""
        self.end_time = ""
        self.elapsed = ""
        self.summary = ""
        self.hosts = []
        self.total_hosts = 0
        self.hosts_up = 0
        self.hosts_down = 0


class NmapHost:
    """Single host from a scan."""

    def __init__(self):
        self.ip = ""
        self.hostname = ""
        self.state = ""
        self.os_matches = []
        self.ports = []
        self.scripts = []
        self.mac = ""
        self.vendor = ""


class NmapPort:
    """Single port on a host."""

    def __init__(self):
        self.port = 0
        self.protocol = "tcp"
        self.state = ""
        self.service = ""
        self.version = ""
        self.product = ""
        self.extra_info = ""
        self.scripts = []


def parse_nmap_xml(filepath):
    """
    Parse an nmap XML output file.

    Returns:
        NmapResult with all hosts, ports, services, etc.
    """
    result = NmapResult()

    if not os.path.exists(filepath):
        return result

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except (ET.ParseError, IOError):
        return result

    # Scan metadata
    result.command = root.get("args", "")
    result.start_time = root.get("startstr", "")

    # Run stats
    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            result.end_time = finished.get("timestr", "")
            result.elapsed = finished.get("elapsed", "")
            result.summary = finished.get("summary", "")

        hosts_stat = runstats.find("hosts")
        if hosts_stat is not None:
            result.total_hosts = int(hosts_stat.get("total", 0))
            result.hosts_up = int(hosts_stat.get("up", 0))
            result.hosts_down = int(hosts_stat.get("down", 0))

    # Parse each host
    for host_elem in root.findall("host"):
        host = _parse_host(host_elem)
        result.hosts.append(host)

    return result


def _parse_host(host_elem):
    """Parse a single <host> element."""
    host = NmapHost()

    # Status
    status = host_elem.find("status")
    if status is not None:
        host.state = status.get("state", "")

    # Addresses
    for addr in host_elem.findall("address"):
        addr_type = addr.get("addrtype", "")
        if addr_type == "ipv4" or addr_type == "ipv6":
            host.ip = addr.get("addr", "")
        elif addr_type == "mac":
            host.mac = addr.get("addr", "")
            host.vendor = addr.get("vendor", "")

    # Hostnames
    hostnames = host_elem.find("hostnames")
    if hostnames is not None:
        for hn in hostnames.findall("hostname"):
            host.hostname = hn.get("name", "")
            break  # Take first hostname

    # Ports
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            port = _parse_port(port_elem)
            host.ports.append(port)

    # OS detection
    os_elem = host_elem.find("os")
    if os_elem is not None:
        for match in os_elem.findall("osmatch"):
            host.os_matches.append({
                "name": match.get("name", ""),
                "accuracy": match.get("accuracy", ""),
            })

    # Host scripts
    hostscript = host_elem.find("hostscript")
    if hostscript is not None:
        for script in hostscript.findall("script"):
            host.scripts.append({
                "id": script.get("id", ""),
                "output": script.get("output", ""),
            })

    return host


def _parse_port(port_elem):
    """Parse a single <port> element."""
    port = NmapPort()
    port.port = int(port_elem.get("portid", 0))
    port.protocol = port_elem.get("protocol", "tcp")

    state = port_elem.find("state")
    if state is not None:
        port.state = state.get("state", "")

    service = port_elem.find("service")
    if service is not None:
        port.service = service.get("name", "")
        port.product = service.get("product", "")
        port.version = service.get("version", "")
        port.extra_info = service.get("extrainfo", "")

    # Build version string
    parts = [port.product, port.version, port.extra_info]
    port.version = " ".join(p for p in parts if p)

    for script in port_elem.findall("script"):
        port.scripts.append({
            "id": script.get("id", ""),
            "output": script.get("output", ""),
        })

    return port


def list_saved_scans(scans_dir):
    """List saved XML scan files with metadata."""
    scans = []
    if not os.path.exists(scans_dir):
        return scans

    for f in sorted(os.listdir(scans_dir), reverse=True):
        if f.endswith(".xml"):
            path = os.path.join(scans_dir, f)
            result = parse_nmap_xml(path)
            scans.append({
                "filename": f,
                "path": path,
                "command": result.command,
                "time": result.start_time,
                "hosts_up": result.hosts_up,
                "summary": result.summary,
            })

    return scans

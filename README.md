# NmapGUI

A graphical interface for the nmap network scanner with NSE script browsing, scan profiles, and persistent history.

Built for Debian-based Linux systems. Matrix green/black theme matching AirNGUI.

---

## Features

- **Scanner** — configure scan type, timing, ports, service/OS detection, NSE scripts, and extra flags. Live command preview shows the exact nmap command being built.
- **Results** — parsed host table, port table, and service/script detail view from nmap XML output. Click through hosts to see open ports, services, versions, and script output.
- **Scripts** — browse all installed NSE scripts with search and category filters. Read descriptions and add scripts to your next scan.
- **Profiles** — 8 built-in presets (Quick, Intense, Full TCP, UDP, Stealth, Vuln, etc.) plus custom profiles you can save and load.
- **History** — all scans saved as XML with timestamps. Reload any previous scan result.
- **Log** — application error log with auto-refresh.

## Requirements

- Python 3.10+
- nmap
- Debian-based Linux (Debian, Kali, Ubuntu, Mint)

## Installation

### From .deb package

```bash
sudo apt install ./nmapgui_1.0.0_all.deb
```

### From source

```bash
sudo apt install nmap python3-tk
sudo python3 main.py
```

## Usage

```bash
nmapgui           # runs with sudo prompt
sudo nmapgui      # full access to all scan types
```

SYN, UDP, and OS detection scans require root. TCP connect scans work without root.

## File Locations

| Path | Contents |
|------|----------|
| `/opt/nmapgui/` | Application files |
| `~/nmapgui-scans/` | Saved scan XML results |
| `~/.local/share/nmapgui/` | Log file and custom profiles |

## License

MIT License — see LICENSE file.

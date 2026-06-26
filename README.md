# Automated NetSec Firewall

A personal firewall built in Python that monitors, filters, and logs network traffic in real time. Includes a graphical dashboard for live visibility into what's happening on your network.

## What it does

- Captures live packets from your network interface
- Evaluates each packet against a configurable set of rules
- Blocks or allows traffic based on those rules
- Detects threats like port scans and flood attacks
- Logs every decision to a file
- Shows everything in a real-time GUI dashboard

## Files

| File | Role |
|------|------|
| `sniffer.py` | Captures raw packets and prints them to the terminal |
| `rules.py` | Manages the ruleset — load, add, remove, evaluate |
| `logger.py` | Logs firewall decisions and detects attack patterns |
| `firewall.py` | Main engine — ties everything together and enforces blocks via iptables |
| `gui.py` | PyQt5 dashboard with live traffic, rules, threats, and quick block tabs |

## Requirements

```
Python 3.10+
scapy
PyQt5
```

Install dependencies:

```bash
pip install scapy PyQt5
```

## Usage

**Run the GUI dashboard:**
```bash
sudo python3 gui.py
```

**Run the firewall engine in the terminal:**
```bash
sudo python3 firewall.py
```

**Dry run (no actual blocking):**
```bash
sudo python3 firewall.py --dry-run
```

**Watch raw traffic only:**
```bash
sudo python3 sniffer.py
```

## Threat Detection

The firewall automatically flags:

- **Port scans** — a single IP hitting 10 or more ports in a short window
- **Flood attacks** — more than 50 connection attempts from one IP within 60 seconds
- **Dangerous ports** — any inbound connection attempt to Telnet, RPC, NetBIOS, SMB, RDP, or VNC

## Default Rules

On first run, the following rules are created automatically:

- Allow outbound TCP 80 and 443 (HTTP/HTTPS)
- Allow outbound UDP 53 (DNS)
- Allow inbound TCP 22 (SSH)
- Block inbound TCP 23 (Telnet)
- Block inbound TCP 3389 (RDP)

Rules are stored in `rules.json` and can be modified through the GUI or directly in the file.

## Notes

- Requires root privileges for packet capture
- Tested on Linux (Kali)
- iptables is used for kernel-level blocking when running `firewall.py`

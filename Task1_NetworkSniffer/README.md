# CodeAlpha_NetworkSniffer

**Cyber Security Internship — Task 1: Basic Network Sniffer**
CodeAlpha | Author: Fares

## 📌 Overview
A Python-based network packet sniffer built with [Scapy](https://scapy.net/) that
captures live traffic and analyzes it in real time. It decodes Ethernet, IP,
TCP, UDP, and ICMP layers and prints a clean, structured summary of every
packet — source/destination IPs and ports, protocol, packet length, and a
safe preview of the payload.

## ✨ Features
- Live packet capture on any network interface
- Protocol identification (TCP / UDP / ICMP / other)
- Source & destination IP and port extraction
- Human-readable payload preview (non-printable bytes shown as `.`)
- Optional BPF filtering (e.g. `tcp port 80`, `icmp`, `host 8.8.8.8`)
- Optional JSON logging of every captured packet for later analysis/reporting
- Simple, dependency-light CLI (built on `argparse`)

## 🛠️ Requirements
- Python 3.9+
- [Npcap](https://npcap.com/) (Windows) or `libpcap` (Linux/macOS — usually preinstalled)
- Root/Administrator privileges (raw sockets require elevated access)

Install dependencies:
```bash
pip install -r requirements.txt --break-system-packages
```

## 🚀 Usage
```bash
# Capture on the default interface (all traffic)
sudo python3 sniffer.py

# Capture exactly 50 packets on a specific interface
sudo python3 sniffer.py -i eth0 -c 50

# Only capture HTTP traffic
sudo python3 sniffer.py -f "tcp port 80"

# Save a structured JSON log of the capture for your report
sudo python3 sniffer.py -c 100 -o capture_log.json
```

### CLI Options
| Flag | Description |
|------|-------------|
| `-i`, `--interface` | Network interface to sniff on |
| `-c`, `--count`     | Number of packets to capture (`0` = run until Ctrl+C) |
| `-f`, `--filter`    | BPF filter string (Wireshark-style filters) |
| `-o`, `--output`    | Path to save a JSON log of all captured packets |

## 📄 Sample Output
```
============================================================
 Basic Network Sniffer - CodeAlpha Cyber Security Task 1
============================================================
Interface : eth0
Filter    : tcp port 80
Count     : 20
------------------------------------------------------------
[2026-09-08 14:02:11] TCP   192.168.1.12:52344     -> 142.250.184.14:80     len=74
[2026-09-08 14:02:11] TCP   142.250.184.14:80      -> 192.168.1.12:52344    len=66
      payload: GET / HTTP/1.1..Host: example.com..
```

## 🎓 What I Learned
- How data flows through a network at the packet level
- The structure of Ethernet, IP, TCP/UDP, and ICMP headers
- How to use Scapy for live packet capture and layer parsing
- Practical use of BPF filters to isolate traffic of interest

## ⚠️ Disclaimer
This tool is intended strictly for educational purposes and for use on
networks you own or have explicit authorization to monitor. Capturing
traffic on networks without permission may be illegal.

## 👤 Author
Fares — Null Pointer Academy | SOC Analyst (Tier 2)

#!/usr/bin/env python3
"""
Basic Network Sniffer
======================
CodeAlpha Cyber Security Internship - Task 1

A packet-capturing and analysis tool built with Scapy. It sniffs live
network traffic, decodes Ethernet/IP/TCP/UDP/ICMP layers, and displays
source/destination IPs, ports, protocols, and a readable payload preview.

Author: Fares
Usage examples:
    sudo python3 sniffer.py                       # sniff all traffic, default interface
    sudo python3 sniffer.py -i eth0 -c 50          # capture 50 packets on eth0
    sudo python3 sniffer.py -f "tcp port 80"       # BPF filter: only HTTP traffic
    sudo python3 sniffer.py -o capture_log.json    # save results to a JSON log file

Requires root/administrator privileges to open a raw socket.
"""

import argparse
import json
import sys
from datetime import datetime

try:
    from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw, conf
except ImportError:
    sys.exit(
        "[!] Scapy is not installed.\n"
        "    Install it first with: pip install scapy --break-system-packages"
    )

# ---------------------------------------------------------------------------
# Protocol number -> name lookup (used when scapy doesn't resolve a name)
# ---------------------------------------------------------------------------
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

# In-memory log of every parsed packet, used if --output is requested
captured_log = []


def format_payload(payload_bytes: bytes, max_len: int = 64) -> str:
    """Return a safe, printable preview of raw payload bytes."""
    if not payload_bytes:
        return ""
    printable = "".join(
        chr(b) if 32 <= b <= 126 else "." for b in payload_bytes[:max_len]
    )
    suffix = "..." if len(payload_bytes) > max_len else ""
    return printable + suffix


def parse_packet(packet) -> dict:
    """Extract the fields we care about from a single sniffed packet."""
    info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "protocol": "OTHER",
        "src_port": None,
        "dst_port": None,
        "length": len(packet),
        "payload_preview": "",
    }

    if packet.haslayer(Ether):
        info["src_mac"] = packet[Ether].src
        info["dst_mac"] = packet[Ether].dst

    ip_layer = None
    if packet.haslayer(IP):
        ip_layer = packet[IP]
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]

    if ip_layer is not None:
        info["src_ip"] = ip_layer.src
        info["dst_ip"] = ip_layer.dst
        proto_num = getattr(ip_layer, "proto", None) or getattr(ip_layer, "nh", None)
        info["protocol"] = PROTO_NAMES.get(proto_num, str(proto_num))

    if packet.haslayer(TCP):
        info["protocol"] = "TCP"
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
    elif packet.haslayer(UDP):
        info["protocol"] = "UDP"
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport
    elif packet.haslayer(ICMP):
        info["protocol"] = "ICMP"

    if packet.haslayer(Raw):
        info["payload_preview"] = format_payload(bytes(packet[Raw].load))

    return info


def print_packet(info: dict) -> None:
    """Pretty-print a parsed packet to the console."""
    header = f"[{info['timestamp']}] {info['protocol']:<5}"
    if info["src_ip"]:
        src = f"{info['src_ip']}:{info['src_port']}" if info["src_port"] else info["src_ip"]
        dst = f"{info['dst_ip']}:{info['dst_port']}" if info["dst_port"] else info["dst_ip"]
        print(f"{header} {src:<22} -> {dst:<22} len={info['length']}")
    else:
        print(f"{header} {info['src_mac']} -> {info['dst_mac']} len={info['length']} (non-IP)")

    if info["payload_preview"]:
        print(f"      payload: {info['payload_preview']}")


def handle_packet(packet, output_file: str | None) -> None:
    info = parse_packet(packet)
    print_packet(info)
    if output_file:
        captured_log.append(info)


def save_log(output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(captured_log, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Saved {len(captured_log)} packet records to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer - capture and analyze live traffic."
    )
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: scapy's default).")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite, stop with Ctrl+C).")
    parser.add_argument("-f", "--filter", dest="bpf_filter", default="", help='BPF filter, e.g. "tcp port 80" or "icmp".')
    parser.add_argument("-o", "--output", help="Save captured packet summaries to a JSON file.")
    args = parser.parse_args()

    iface = args.interface or conf.iface
    print("=" * 60)
    print(" Basic Network Sniffer - CodeAlpha Cyber Security Task 1")
    print("=" * 60)
    print(f"Interface : {iface}")
    print(f"Filter    : {args.bpf_filter or '(none - all traffic)'}")
    print(f"Count     : {'infinite (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("-" * 60)

    try:
        sniff(
            iface=args.interface,
            filter=args.bpf_filter or None,
            prn=lambda pkt: handle_packet(pkt, args.output),
            count=args.count,
            store=False,
        )
    except PermissionError:
        sys.exit("[!] Permission denied. Run this script with sudo/administrator privileges.")
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
    finally:
        if args.output and captured_log:
            save_log(args.output)


if __name__ == "__main__":
    main()

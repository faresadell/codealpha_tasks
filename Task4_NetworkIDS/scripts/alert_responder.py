#!/usr/bin/env python3
"""
alert_responder.py
====================
CodeAlpha Cyber Security Internship - Task 4: Network Intrusion Detection

Tails Suricata's EVE JSON alert log (eve.json) in real time and implements
automated response mechanisms:

  1. Logs every alert into a structured incident log (incidents.log)
  2. Tracks repeat offenders per source IP within a rolling time window
  3. Auto-blocks an IP via iptables once it crosses an offense threshold
     (DRY-RUN by default - nothing is blocked unless --enforce is passed)
  4. Maintains a live blocklist file (blocklist.txt) for audit/reporting

Usage:
    python3 alert_responder.py                          # dry-run, watch default eve.json path
    python3 alert_responder.py --eve /var/log/suricata/eve.json --enforce
    python3 alert_responder.py --demo                   # replay sample_eve.json for testing

This script is intentionally conservative: it never runs a blocking
command unless --enforce is explicitly passed, so it's safe to run in a
training/demo environment.
"""

import argparse
import json
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

INCIDENT_LOG = Path("incidents.log")
BLOCKLIST_FILE = Path("blocklist.txt")

# How many alerts from the same source IP within WINDOW_SECONDS trigger an
# automated block.
OFFENSE_THRESHOLD = 3
WINDOW_SECONDS = 60

SEVERITY_LABELS = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}


class OffenseTracker:
    """Tracks recent alert timestamps per source IP to decide when to escalate."""

    def __init__(self, threshold: int, window_seconds: int):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.history = defaultdict(list)
        self.blocked = set()

    def record(self, src_ip: str, when: datetime) -> bool:
        """Record an alert for src_ip. Returns True if this crosses the block threshold."""
        history = self.history[src_ip]
        history.append(when)
        cutoff = when - self.window
        self.history[src_ip] = [t for t in history if t >= cutoff]

        if src_ip in self.blocked:
            return False
        if len(self.history[src_ip]) >= self.threshold:
            self.blocked.add(src_ip)
            return True
        return False


def log_incident(record: dict) -> None:
    with INCIDENT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def add_to_blocklist(ip: str, reason: str) -> None:
    with BLOCKLIST_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()}\t{ip}\t{reason}\n")


def block_ip(ip: str, enforce: bool) -> None:
    """Block an IP address via iptables. Dry-run unless enforce=True."""
    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    if enforce:
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print(f"  [BLOCKED] {ip} added to iptables DROP rule.")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"  [!] Failed to apply iptables rule for {ip}: {e}")
    else:
        print(f"  [DRY-RUN] Would run: {' '.join(cmd)}")


def handle_alert(event: dict, tracker: OffenseTracker, enforce: bool) -> None:
    alert = event.get("alert", {})
    src_ip = event.get("src_ip", "unknown")
    dest_ip = event.get("dest_ip", "unknown")
    signature = alert.get("signature", "Unknown signature")
    severity = alert.get("severity", 3)
    timestamp_raw = event.get("timestamp")

    try:
        when = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00")) if timestamp_raw else datetime.now()
    except ValueError:
        when = datetime.now()

    label = SEVERITY_LABELS.get(severity, "LOW")
    print(f"[{when.strftime('%H:%M:%S')}] {label:<6} {src_ip:<15} -> {dest_ip:<15} | {signature}")

    incident = {
        "time": when.isoformat(),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "signature": signature,
        "severity": label,
    }
    log_incident(incident)

    should_block = tracker.record(src_ip, when)
    if should_block:
        reason = f"{tracker.threshold}+ alerts within {WINDOW_SECONDS}s (last: {signature})"
        print(f"  [ESCALATION] {src_ip} crossed offense threshold -> auto-blocking")
        add_to_blocklist(src_ip, reason)
        block_ip(src_ip, enforce)


def tail_file(path: Path):
    """Generator that yields new lines appended to a growing log file."""
    with path.open("r", encoding="utf-8") as f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def replay_file(path: Path):
    """Generator that yields every existing line once (for --demo mode)."""
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            yield line


def main():
    parser = argparse.ArgumentParser(description="Automated response engine for Suricata EVE JSON alerts.")
    parser.add_argument("--eve", default="/var/log/suricata/eve.json", help="Path to Suricata's eve.json log.")
    parser.add_argument("--enforce", action="store_true", help="Actually apply iptables blocks (default: dry-run).")
    parser.add_argument("--demo", action="store_true", help="Replay sample_eve.json once instead of tailing a live log.")
    args = parser.parse_args()

    tracker = OffenseTracker(OFFENSE_THRESHOLD, WINDOW_SECONDS)

    print("=" * 65)
    print(" Suricata Alert Responder - CodeAlpha Cyber Security Task 4")
    print("=" * 65)
    print(f"Mode        : {'DEMO REPLAY' if args.demo else 'LIVE TAIL'}")
    print(f"Enforcement : {'ENABLED (will run iptables)' if args.enforce else 'DRY-RUN (no changes made)'}")
    print(f"Threshold   : {OFFENSE_THRESHOLD} alerts / {WINDOW_SECONDS}s triggers auto-block")
    print("-" * 65)

    source_path = Path("sample_eve.json") if args.demo else Path(args.eve)
    if not source_path.exists():
        sys.exit(f"[!] Log file not found: {source_path}")

    line_source = replay_file(source_path) if args.demo else tail_file(source_path)

    try:
        for line in line_source:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                handle_alert(event, tracker, args.enforce)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")


if __name__ == "__main__":
    main()

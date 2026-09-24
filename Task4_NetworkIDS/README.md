# CodeAlpha_NetworkIDS

**Cyber Security Internship — Task 4: Network Intrusion Detection System**
CodeAlpha | Author: Fares

## 📌 Overview
A complete, working Network IDS setup built on **Suricata**, covering
every part of the task: custom detection rules, alert configuration,
continuous monitoring, an automated response mechanism, and a visual
dashboard for detected attacks.

## 📂 Structure
```
rules/custom.rules              # 15 custom detection rules (recon, brute force, web attacks, DoS)
suricata_config_excerpt.yaml    # The suricata.yaml sections wired up for this project
scripts/alert_responder.py      # Tails eve.json and auto-responds to repeat offenders
scripts/sample_eve.json         # Sample alert data for demo/testing without live traffic
dashboard/index.html            # Visual dashboard (charts + alert table)
```

## 1️⃣ Setting up the IDS (Suricata)

Install Suricata:
```bash
sudo apt update
sudo apt install suricata
```

Update the official ruleset and add the custom rules from this project:
```bash
sudo suricata-update                              # pulls the official Emerging Threats ruleset
sudo cp rules/custom.rules /etc/suricata/rules/
```

Merge the relevant sections from `suricata_config_excerpt.yaml` into your
system's `/etc/suricata/suricata.yaml` — in particular:
- `vars.address-groups.HOME_NET` (your protected network range)
- `rule-files:` (make sure `custom.rules` is listed)
- `af-packet.interface` (the interface to monitor, e.g. `eth0`)
- `outputs.eve-log` (enables the JSON alert log the other scripts read)

Validate the configuration before running it live:
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

Run Suricata on your interface:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

## 2️⃣ What the custom rules detect

| Category | Rules |
|----------|-------|
| **Reconnaissance** | TCP port scan (SYN flood pattern), NULL scan, XMAS scan |
| **Brute force** | Repeated SSH connection attempts, repeated HTTP login POSTs |
| **Web application attacks** | SQL injection patterns (`UNION SELECT`, `OR 1=1`), XSS (`<script`), path traversal (`../../`) |
| **Denial of service** | ICMP flood (ping flood), SYN flood |
| **Suspicious tooling** | Known scanner user-agents (`sqlmap`, `Nikto`) |

All rules use SIDs in the `1000000+` range so they never collide with the
official ruleset, and every rule was validated with:
```bash
suricata -T -S rules/custom.rules -c /etc/suricata/suricata.yaml
# -> "Configuration provided was successfully loaded."
```

## 3️⃣ Automated response mechanism

`scripts/alert_responder.py` tails Suricata's `eve.json` alert log in real
time and:
1. Logs every alert into a structured `incidents.log` (JSON lines)
2. Tracks how many alerts each source IP triggers within a rolling
   60-second window
3. **Auto-blocks** an IP via `iptables` once it crosses **3 alerts** in
   that window, and records the action in `blocklist.txt`

Safety first: the script runs in **dry-run mode by default** — it prints
what it *would* block without touching `iptables` unless you explicitly
pass `--enforce`.

```bash
# Try it instantly with the included sample data - no live traffic needed
cd scripts
python3 alert_responder.py --demo

# Watch a real, live Suricata log (dry-run)
python3 alert_responder.py --eve /var/log/suricata/eve.json

# Watch a real log AND actually apply iptables blocks
sudo python3 alert_responder.py --eve /var/log/suricata/eve.json --enforce
```

## 4️⃣ Visualizing detected attacks

Open `dashboard/index.html` in any browser. It shows:
- Summary cards (total alerts, high-severity count, unique source IPs, auto-blocked IPs)
- Top offending source IPs (bar chart)
- Alerts by severity (donut chart)
- Alert timeline (line chart)
- A full, sortable-by-eye alert table

It ships pre-loaded with the same sample data as the demo above, so it's
meaningful to look at immediately. To visualize your own captured alerts,
paste JSON lines from your `incidents.log` into the "Load your own data"
box at the bottom and click **Render Dashboard**.

## 🎓 What I learned
- How to configure and validate a real network IDS (Suricata) end to end
- How to write detection rules across multiple attack categories: recon,
  brute force, web attacks, and denial of service
- How to build an automated response loop around raw alert data, with a
  safe dry-run default before anything touches the firewall
- How to turn raw JSON security telemetry into something a human can
  actually read at a glance

## ⚠️ Disclaimer
For educational use on networks and systems you own or are authorized to
monitor. `alert_responder.py --enforce` modifies live firewall rules —
test in dry-run mode first.

## 👤 Author
Fares Adel| SOC Analyst (Tier 2)

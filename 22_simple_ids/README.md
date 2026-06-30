# 🚨 Project 22 — Simple Intrusion Detection System (IDS)

A working IDS engine combining signature-based detection (Snort-style rules)
with anomaly-based detection (time-windowed thresholds) to catch SQL injection,
XSS, port scans, connection floods, and known-bad IPs in network traffic.
Includes a live mode that analyses your machine's real active connections.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| Signature-based detection | Matching traffic against known-bad patterns (Snort-style rules) |
| Anomaly-based detection | Flagging behaviour that deviates from a statistical baseline |
| Port scan detection | Many distinct ports from one source in a short time window |
| Flood/DoS detection | Many connections to the same destination in a short time window |
| Threat intelligence | Blacklist matching against known-bad IP addresses |
| IDS vs IPS | Passive alerting vs active blocking |
| Live connection monitoring | Reading real local network state via `netstat` |

## ▶️ How to Run

```bash
python3 simple_ids.py
```

Option 1 (sample traffic) and option 2 (rule database) work fully offline.
Option 3 (live connections) reads your machine's actual current connections —
no internet required, no root needed.

## 🔍 Features

- **9 built-in signature rules** — SQLi, XSS, directory traversal, EICAR,
  shellcode patterns, known attack tools, cleartext Telnet, C2 beaconing
- **Threat intelligence blocklist** — 3 known-bad IPs with stated reasons
- **Port scan detector** — anomaly-based, time-windowed distinct-port tracking
- **Flood detector** — anomaly-based, time-windowed connection-rate tracking
- **Live-feed style output** — events stream past with inline alerts, just
  like a real IDS console
- **Severity-grouped summary** — CRITICAL → HIGH → MEDIUM → LOW → INFO
- **Live connection analysis** — flags suspicious listening ports and
  unusual outbound connection patterns on your real machine
- Built-in explainer covering IDS vs IPS and both detection approaches (option 4)

## 🧪 Recommended Flow

1. Option 4 — read the IDS/IPS explainer first
2. Option 2 — review the signature rule database and blacklist
3. Option 1 — run the full engine against synthetic traffic and watch
   alerts fire in real time, then read the severity-grouped summary
4. Option 3 — analyse your own machine's live connections

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Security Operations — IDS/IPS, SIEM, detection methods |
| CEH | Evading IDS, Firewalls & Honeypots — understanding detection to evade it |

## 📖 Key Terms

- **IDS (Intrusion Detection System)** — monitors and alerts, does not block
- **IPS (Intrusion Prevention System)** — monitors and actively blocks traffic
- **Signature-based detection** — matching against known-bad patterns
- **Anomaly-based detection** — flagging deviations from a normal baseline
- **SID** — Signature ID, the unique identifier for a detection rule (Snort convention)
- **Port scan** — probing many ports to discover open services
- **Connection flood** — excessive connection attempts, often DoS or brute force
- **Threat intelligence** — curated data about known threats (IPs, hashes, domains)
- **Alert fatigue** — analysts becoming desensitised due to high alert volume
- **Snort / Suricata** — real-world open-source IDS/IPS engines
- **SOC (Security Operations Center)** — team that monitors and responds to alerts

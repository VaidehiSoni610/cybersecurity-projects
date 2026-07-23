# 🍯 Project 28 — Honeypot Simulator

A multi-service honeypot that runs fake SSH, HTTP, FTP, and Telnet listeners,
logs every connection and credential attempt in real time, profiles attacker
behaviour, and generates a threat intelligence report — all using only the
Python standard library.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| Honeypots | Fake services that detect and study attackers |
| Deception technology | Using decoys as a defensive strategy |
| Low-interaction honeypots | Simulating service banners without a real OS |
| Attacker profiling | Extracting patterns from honeypot interaction logs |
| Credential harvesting (defence) | Capturing attacker wordlists from brute-force attempts |
| Canary tokens | Passive tripwires that alert when triggered |
| Threat intelligence | Building IOCs from observed attacker behaviour |

## ▶️ How to Run

```bash
python3 honeypot_simulator.py
```

All services listen on **127.0.0.1 only** (localhost) — nothing is exposed
to the network. Safe to run on any machine.

## 🔍 Features

- **4 fake services** — SSH (2222), HTTP (8080), FTP (2121), Telnet (2323)
- **Real-time event log** — every connection, banner exchange, and credential
  attempt printed to the console as it happens
- **Traffic simulator** — option 2 sends realistic attacker traffic so you
  can see the full system in action without waiting for real connections
- **Threat report** — connection counts by service, top source IPs,
  most-tried usernames and passwords
- **Canary token explainer** — covers web bugs, fake credentials,
  DNS tokens, and the free canarytokens.org service (option 7)
- Built-in explainer covering low vs high-interaction honeypots,
  honeynets, and real-world deployment strategies (option 6)

## 🧪 Recommended Flow

1. Option 6 — read the honeypot explainer first
2. Option 1 — start all 4 fake services
3. Option 2 — run the traffic simulator (safe, localhost only)
4. Option 4 — view the live event log and see what was captured
5. Option 3 — generate the threat report
6. Option 7 — read about canary tokens as a complementary technique

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Security Operations — honeypots, deception technology, threat intelligence |
| CEH | Evading IDS, Firewalls & Honeypots — understanding honeypots to evade them |

## 📖 Key Terms

- **Honeypot** — a fake system set up to attract and detect attackers
- **Low-interaction honeypot** — simulates service banners only, no real OS
- **High-interaction honeypot** — real OS and services, full attacker exploitation possible
- **Honeynet** — a network of honeypots forming a fake environment
- **Canary token** — a passive tripwire (URL, credential, file) that alerts when triggered
- **Deception technology** — using decoys to detect and mislead attackers
- **Attacker profiling** — learning about attacker tools and techniques from honeypot logs
- **Threat intelligence** — actionable knowledge about threats derived from real observations
- **Cowrie** — popular open-source SSH/Telnet honeypot used in production

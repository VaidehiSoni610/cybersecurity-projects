# 🔥 Project 13 — Firewall Rule Simulator

A command-line firewall simulator that models how real packet-filtering firewalls
work — including rule ordering, default-deny policy, traffic logging, and statistics.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| Packet filtering | Inspecting traffic and deciding allow or deny |
| ACLs | Access Control Lists — ordered rules applied to traffic |
| Default-deny | Block everything not explicitly permitted |
| Rule ordering | First match wins — order matters |
| Traffic logging | Recording what the firewall allowed and blocked |

## ▶️ How to Run

```bash
python3 firewall_simulator.py
```

## 🔍 Features

- **Add / remove rules** with custom protocol, source IP, destination IP, and port
- **Two preset rulesets** — web server and office network
- **Test any packet** manually against the current ruleset
- **Traffic simulation** — fires 8 realistic packets and shows what gets through
- **Live log and stats** — see hit counts per rule and allow/block ratios

## 🧪 Recommended Flow

1. Load the **web server preset** (option 5)
2. View the rules (option 1)
3. Run the traffic simulation (option 7)
4. Check the log and stats (option 8)
5. Try adding your own rule (option 2) and test a custom packet (option 4)

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Network Security — firewall types, ACLs, rule-based access control |
| CEH | Scanning & Enumeration — understanding what firewalls block and why |

## 📖 Key Terms

- **Firewall** — network security device that monitors and filters traffic based on rules
- **Packet filtering** — inspecting individual packets against a ruleset
- **ACL** — Access Control List — ordered list of allow/deny rules
- **Default-deny** — block everything not explicitly permitted (safest policy)
- **Stateless firewall** — inspects each packet independently (what this simulates)
- **Stateful firewall** — tracks connection state across packets (more advanced)
- **Implicit deny** — the invisible final rule that blocks everything with no match

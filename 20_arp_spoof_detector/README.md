# 🕵️ Project 20 — ARP Spoof Detector

A network security tool that reads your system's ARP cache, detects duplicate
MAC addresses, monitors for gateway MAC changes, and alerts on signs of ARP
poisoning — the technique behind most Man-in-the-Middle attacks.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| ARP protocol | How IP addresses are resolved to MAC addresses on a LAN |
| ARP spoofing | Sending fake ARP replies to redirect traffic through an attacker |
| MITM attacks | Man-in-the-Middle — intercepting traffic between two devices |
| MAC addresses | Hardware-level identifiers — how they reveal spoofing |
| Anomaly detection | Flagging deviations from a known-good baseline |
| subprocess module | Running system commands (`arp -a`) from Python |

## ▶️ How to Run

```bash
python3 arp_spoof_detector.py
```

No root access required. Reads the existing ARP cache via the system
`arp -a` command — no packet capture needed.

## 🔍 Features

- **Full ARP table scan** — displays all entries with IP, MAC, vendor, interface
- **Duplicate MAC detection** — the primary indicator of ARP poisoning
- **Baseline comparison** — compare current table against a saved snapshot
- **Monitor mode** — polls the ARP table continuously and alerts on any change
- **Gateway tracking** — flags changes to the gateway's MAC as critical alerts
- **OUI vendor lookup** — identifies hardware manufacturer from MAC prefix
- Built-in explainer covering how ARP spoofing enables MITM attacks (option 5)

## 🧪 Recommended Flow

1. Option 5 — read the ARP spoofing explainer first
2. Option 1 — scan your current ARP table and see your local devices
3. Option 4 — save the current table as a baseline
4. Option 3 — start monitor mode, then browse your network to watch new entries appear
5. Option 2 — compare current state against the saved baseline

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Network Security — ARP, MITM attacks, protocol vulnerabilities |
| CEH | Sniffing — ARP poisoning, session hijacking, MITM techniques |

## 📖 Key Terms

- **ARP** — Address Resolution Protocol — maps IP addresses to MAC addresses on a LAN
- **ARP cache / ARP table** — local store of IP → MAC mappings
- **ARP spoofing / ARP poisoning** — sending fake ARP replies to redirect traffic
- **MITM (Man-in-the-Middle)** — attacker secretly intercepts communication between two parties
- **MAC address** — 6-byte hardware identifier (e.g. `aa:bb:cc:dd:ee:ff`)
- **OUI** — Organizationally Unique Identifier — first 3 bytes of MAC identify the manufacturer
- **Duplicate MAC** — same MAC for multiple IPs — primary sign of ARP spoofing
- **Gratuitous ARP** — unsolicited ARP reply used legitimately (but also by attackers)
- **Dynamic ARP Inspection (DAI)** — enterprise switch feature that validates ARP packets
- **arpwatch** — production tool that monitors ARP table and alerts on changes

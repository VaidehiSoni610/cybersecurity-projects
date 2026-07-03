# 🔑 Project 23 — Keylogger Detector

A forensic analysis tool that scans your Mac for keylogger indicators —
suspicious processes, persistence mechanisms, hidden files, and malicious
command-line patterns — using only the Python standard library.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| Keyloggers | How they capture keystrokes and exfiltrate data |
| Persistence mechanisms | LaunchAgents/Daemons — how malware survives reboots |
| Process analysis | Scanning `ps aux` output for suspicious names and patterns |
| IOC hunting | Matching against a database of known-bad indicators |
| Forensic indicators | What traces malware leaves on a compromised system |
| Masquerading | Malware hiding as legitimate system processes |

## ▶️ How to Run

```bash
python3 keylogger_detector.py
```

No internet connection or root access required. Reads process list,
filesystem metadata, and shell configs via standard system calls.

## 🔍 Features

- **Process scanner** — checks all running processes against known keylogger
  names and suspicious command-line patterns (reverse shells, obfuscation, tunnels)
- **Persistence location scanner** — audits Mac LaunchAgent/Daemon directories
  and shell config files for unexpected or recently modified items
- **Hidden file scanner** — finds hidden files and suspicious extensions
  in `/tmp`, `~`, and common staging locations
- **Manual IOC checker** — look up any process name or filename against the database
- Severity-rated findings: CRITICAL → HIGH → MEDIUM → LOW → INFO
- Built-in explainer on how Mac keyloggers work (option 6)

## 🧪 Recommended Flow

1. Option 6 — read the keylogger explainer first (covers Mac-specific attack methods)
2. Option 1 — run a full system scan on your Mac
3. Option 2 — process-only scan to understand what's currently running
4. Option 3 — persistence scan to audit your LaunchAgents directory
5. Option 5 — manually check specific names (try `nc`, `ngrok`, `logkext`)

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Threats, Attacks & Vulnerabilities — spyware, keyloggers, malware types |
| CEH | Malware Threats — keyloggers, trojans, persistence, privilege escalation |

## 📖 Key Terms

- **Keylogger** — software or hardware that secretly records every keystroke
- **Persistence** — mechanism allowing malware to survive reboots and re-execute
- **LaunchAgent** — Mac plist file that launches a program at user login
- **LaunchDaemon** — Mac plist file that launches a program at system boot (as root)
- **CGEventTap** — low-level Mac API used to intercept keyboard/mouse events
- **Accessibility API** — Mac system permission that allows observing all keyboard events
- **Masquerading** — malware naming itself like a legitimate process to hide
- **RAT (Remote Access Trojan)** — malware giving an attacker remote control
- **Reverse shell** — connection that gives attacker a command prompt on the target
- **IOC (Indicator of Compromise)** — observable evidence of a security incident

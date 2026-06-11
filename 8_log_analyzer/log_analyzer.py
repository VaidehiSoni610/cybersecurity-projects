"""
Project 8: Log Analyzer — Detect Suspicious Activity
Concepts: log analysis, SIEM, intrusion detection, forensics, threat hunting
"""
import re
from datetime import datetime
from collections import defaultdict, Counter

SAMPLE_LOGS = [
    "2024-01-15 08:01:23 INFO  sshd: Accepted password for alice from 192.168.1.10 port 52341",
    "2024-01-15 08:05:11 INFO  sshd: Accepted password for bob from 192.168.1.22 port 48291",
    "2024-01-15 09:12:44 WARN  sshd: Failed password for root from 45.33.32.156 port 4444",
    "2024-01-15 09:12:45 WARN  sshd: Failed password for root from 45.33.32.156 port 4445",
    "2024-01-15 09:12:46 WARN  sshd: Failed password for root from 45.33.32.156 port 4446",
    "2024-01-15 09:12:47 WARN  sshd: Failed password for root from 45.33.32.156 port 4447",
    "2024-01-15 09:12:48 WARN  sshd: Failed password for root from 45.33.32.156 port 4448",
    "2024-01-15 09:12:50 WARN  sshd: Failed password for admin from 45.33.32.156 port 4450",
    "2024-01-15 09:12:51 WARN  sshd: Failed password for admin from 45.33.32.156 port 4451",
    "2024-01-15 09:13:00 WARN  sshd: Failed password for alice from 45.33.32.156 port 4453",
    "2024-01-15 09:30:00 INFO  sshd: Accepted password for alice from 45.33.32.156 port 4499",
    "2024-01-15 09:30:15 WARN  sudo: alice : command not allowed ; user=root ; command=/bin/bash",
    "2024-01-15 09:30:30 WARN  sudo: alice : 3 incorrect password attempts ; user=root",
    "2024-01-15 10:01:00 WARN  sshd: Failed password for invalid user guest from 203.0.113.5 port 1234",
    "2024-01-15 10:01:02 WARN  sshd: Failed password for invalid user test from 203.0.113.5 port 1235",
    "2024-01-15 10:01:04 WARN  sshd: Failed password for invalid user admin from 203.0.113.5 port 1236",
    "2024-01-15 10:01:06 WARN  sshd: Failed password for invalid user oracle from 203.0.113.5 port 1237",
    "2024-01-15 10:01:08 WARN  sshd: Failed password for invalid user postgres from 203.0.113.5 port 1238",
    "2024-01-15 11:00:00 INFO  sshd: Accepted publickey for devops from 10.10.0.1 port 22022",
    "2024-01-15 14:22:33 WARN  sshd: Failed password for root from 198.51.100.7 port 8080",
    "2024-01-15 14:22:34 WARN  sshd: Failed password for root from 198.51.100.7 port 8081",
    "2024-01-15 14:22:35 WARN  sshd: Failed password for root from 198.51.100.7 port 8082",
    "2024-01-15 23:55:10 WARN  sshd: Failed password for root from 192.168.1.10 port 9999",
]

class LogEntry:
    def __init__(self, raw):
        self.raw      = raw
        self.time     = (re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', raw) or type('',(),{'group':lambda s:None})()).group(0)
        self.level    = next((x for x in ['INFO','WARN','ERROR'] if x in raw), 'UNKNOWN')
        self.ip       = (re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', raw) or type('',(),{'group':lambda *a:None})()).group(0)
        self.success  = True if 'Accepted' in raw else (False if 'Failed' in raw else None)
        m = re.search(r'(?:Accepted \w+ for|Failed password for (?:invalid user )?)(\S+)', raw)
        self.username = m.group(1) if m else (re.search(r'sudo: (\w+)', raw) or type('',(),{'group':lambda *a:None})()).group(1)

def detect_threats(entries):
    alerts = []
    fail_by_ip = defaultdict(list)
    for e in entries:
        if e.success is False and e.ip: fail_by_ip[e.ip].append(e)

    # Brute force
    for ip, fails in fail_by_ip.items():
        if len(fails) >= 5:
            users = list({f.username for f in fails if f.username})
            alerts.append(("🔴 HIGH", "BRUTE_FORCE", f"{len(fails)} failed logins from {ip} → targeting: {', '.join(users)}", [f.raw for f in fails[:2]]))

    # Success after failures
    for e in entries:
        if e.success is True and e.ip and len(fail_by_ip[e.ip]) >= 3:
            alerts.append(("🚨 CRITICAL", "BREACH_LIKELY", f"Login succeeded for '{e.username}' from {e.ip} after {len(fail_by_ip[e.ip])} failures!", [e.raw]))

    # Root attempts
    root = [e for e in entries if e.username == 'root']
    if root:
        alerts.append(("🟠 MEDIUM", "ROOT_ATTEMPTS", f"{len(root)} root login attempt(s)", [e.raw for e in root[:2]]))

    # Privilege escalation
    privesc = [e for e in entries if 'sudo' in e.raw and 'incorrect' in e.raw]
    if privesc:
        alerts.append(("🟠 MEDIUM", "PRIV_ESC", f"Failed sudo by: {privesc[0].username}", [privesc[0].raw]))

    # Off-hours logins
    off = []
    for e in entries:
        if e.success is True and e.time:
            try:
                h = datetime.strptime(e.time, "%Y-%m-%d %H:%M:%S").hour
                if h >= 22 or h < 6: off.append(e)
            except: pass
    if off:
        alerts.append(("🟡 LOW", "OFF_HOURS", f"{len(off)} login(s) outside business hours", [e.raw for e in off]))

    return alerts

def print_report(entries, alerts):
    successes = sum(1 for e in entries if e.success is True)
    failures  = sum(1 for e in entries if e.success is False)
    ip_fails  = Counter(e.ip for e in entries if e.success is False and e.ip)
    print(f"\n{'='*60}")
    print(f"  📋 LOG ANALYSIS REPORT — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print(f"\n  📊 Summary: {len(entries)} lines | ✅ {successes} logins | ❌ {failures} failures")
    if ip_fails:
        print(f"\n  🌐 Top IPs with failures:")
        for ip, count in ip_fails.most_common(3):
            print(f"     {ip:<18} {count} failures  {'█'*min(count,20)}")
    print(f"\n  🚨 Alerts ({len(alerts)} found)\n  {'-'*56}")
    if not alerts:
        print("  ✅ No threats detected.")
    else:
        for severity, rule, desc, evidence in alerts:
            print(f"\n  {severity} — {rule}")
            print(f"  {desc}")
            for ev in evidence: print(f"    → {ev}")
    print(f"\n{'='*60}\n")

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   LOG ANALYZER                       ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Analyze sample logs             ║")
        print("║  [2] Analyze a real log file         ║")
        print("║  [3] Show raw sample logs            ║")
        print("║  [4] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")
        choice = input("Choose: ").strip()
        if choice == '1':
            entries = [LogEntry(l) for l in SAMPLE_LOGS]
            print_report(entries, detect_threats(entries))
        elif choice == '2':
            path = input("Log file path (e.g. /var/log/auth.log): ").strip()
            try:
                with open(path, errors='ignore') as f: lines = f.readlines()
                entries = [LogEntry(l.strip()) for l in lines if l.strip()]
                print_report(entries, detect_threats(entries))
            except FileNotFoundError: print(f"❌ File not found: {path}\n")
        elif choice == '3':
            print("\n  📄 Sample logs:\n")
            for line in SAMPLE_LOGS: print(f"  {line}")
            print()
        elif choice == '4': print("\nGoodbye! Always review your logs. 🔐\n"); break

if __name__ == "__main__":
    main()

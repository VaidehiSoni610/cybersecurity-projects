"""
Project 23: Keylogger Detector
Concepts: keyloggers, persistence mechanisms, process analysis, IOC hunting,
          LaunchAgents (Mac), forensic indicators, privilege escalation

What you'll learn:
- How keyloggers work and what signs they leave on a system
- What persistence mechanisms are and how malware survives reboots
- How to enumerate running processes and flag suspicious ones
- How to check Mac LaunchAgent/LaunchDaemon startup locations
- How to scan for hidden files and suspicious file system artifacts
- What indicators of compromise (IOCs) look like in practice

Builds on: Project 8 (pattern-based detection), Project 20 (subprocess),
           Project 21 (IOC matching), Project 22 (anomaly flagging)
"""

import subprocess
import os
import re
import json
import glob
import time
from datetime import datetime

SEVERITY_ICONS = {
    "CRITICAL": "🚨",
    "HIGH":     "🔴",
    "MEDIUM":   "🟠",
    "LOW":      "🟡",
    "INFO":     "🔵",
}

# ── Indicator Databases ────────────────────────────────────────────────────────

# Process names associated with known keyloggers, RATs, and spyware
SUSPICIOUS_PROCESS_NAMES = {
    # Known keylogger / RAT process names
    "logkext":        ("CRITICAL", "Mac keylogger (logKext)"),
    "keycatcher":     ("CRITICAL", "Commercial keylogger"),
    "amac keylogger": ("CRITICAL", "Mac keylogger tool"),
    "refog":          ("CRITICAL", "REFOG employee monitoring / keylogger"),
    "actualspy":      ("CRITICAL", "ActualSpy keylogger"),
    "elite keylogger":("CRITICAL", "Elite Keylogger tool"),
    "revealer":       ("HIGH",     "Revealer Keylogger"),
    "spyrix":         ("HIGH",     "Spyrix employee monitoring"),
    "hoverwatch":     ("HIGH",     "Hoverwatch surveillance app"),
    "mspy":           ("HIGH",     "mSpy commercial spyware"),
    "nohup":          ("LOW",      "Process running detached from terminal (common legit use, worth noting)"),
    "remotedesktop":  ("INFO",     "Remote Desktop — verify this is authorised"),
    "screensharing":  ("INFO",     "Screen Sharing — verify this is authorised"),

    # Common RAT / backdoor patterns
    "nc":             ("MEDIUM",   "netcat — legitimate tool but often used for backdoors"),
    "ncat":           ("MEDIUM",   "ncat — legitimate but used in reverse shells"),
    "socat":          ("MEDIUM",   "socat — network relay, used in reverse shells"),
    "ngrok":          ("HIGH",     "ngrok — tunnel tool, used to expose local ports externally"),
    "frp":            ("HIGH",     "frp — reverse proxy, common C2 tunnel tool"),
}

# Suspicious command-line argument patterns (substrings to look for in ps output)
SUSPICIOUS_CMDLINE_PATTERNS = [
    (r'python.*keylog',    "CRITICAL", "Python keylogging script"),
    (r'python.*hook',      "HIGH",     "Python input hook (possible keylogger)"),
    (r'/tmp/.*\.sh',       "HIGH",     "Shell script running from /tmp"),
    (r'/tmp/.*\.py',       "HIGH",     "Python script running from /tmp"),
    (r'bash.*-i.*>&',      "CRITICAL", "Bash interactive reverse shell pattern"),
    (r'exec.*socket',      "HIGH",     "Socket exec pattern (reverse shell)"),
    (r'base64.*decode',    "HIGH",     "Base64 decode in command line (obfuscation)"),
    (r'curl.*\|\s*bash',   "CRITICAL", "Curl pipe to bash (RCE / dropper pattern)"),
    (r'wget.*\|\s*bash',   "CRITICAL", "Wget pipe to bash (RCE / dropper pattern)"),
    (r'chmod.*\+x.*/tmp/', "HIGH",     "Making file executable in /tmp"),
]

# Mac-specific persistence locations
# Legitimate software uses these — context and name matter
PERSISTENCE_LOCATIONS = [
    ("~/Library/LaunchAgents",            "User LaunchAgents — runs at user login"),
    ("/Library/LaunchAgents",             "System LaunchAgents — runs for all users"),
    ("/Library/LaunchDaemons",            "System LaunchDaemons — runs as root"),
    ("~/Library/Application Support",     "App support files — check for unexpected items"),
    ("~/.bash_profile",                   "Bash profile — check for added commands"),
    ("~/.zshrc",                          "Zsh config — check for added commands"),
    ("~/.profile",                        "Shell profile — check for added commands"),
]

# File extensions that should be suspicious in temp/download locations
SUSPICIOUS_EXTENSIONS = [".sh", ".py", ".rb", ".pl", ".dylib", ".kext"]

# ── Process Analysis ───────────────────────────────────────────────────────────

def get_running_processes():
    """
    Get all running processes via 'ps aux'.
    Returns a list of dicts: [{pid, user, cpu, mem, command}, ...]
    ps aux shows: USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND
    """
    try:
        result = subprocess.run(
            ['ps', 'aux'],
            capture_output=True, text=True, timeout=5
        )
        return parse_ps_output(result.stdout)
    except FileNotFoundError:
        print("  ❌ 'ps' command not found.")
        return []
    except subprocess.TimeoutExpired:
        print("  ❌ ps command timed out.")
        return []

def parse_ps_output(raw):
    """
    Parse 'ps aux' output into structured records.
    The COMMAND field is everything from column 10 onwards — may contain spaces.
    """
    processes = []
    lines = raw.strip().split('\n')
    if not lines:
        return processes

    for line in lines[1:]:    # skip header
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            processes.append({
                'user':    parts[0],
                'pid':     parts[1],
                'cpu':     parts[2],
                'mem':     parts[3],
                'command': parts[10].strip(),
            })
        except IndexError:
            continue
    return processes

def scan_processes():
    """
    Check all running processes against the suspicious name and
    command-line pattern databases. Returns a list of alert dicts.
    """
    processes = get_running_processes()
    alerts = []

    for proc in processes:
        cmd_lower = proc['command'].lower()

        # Name-based check
        for name, (severity, reason) in SUSPICIOUS_PROCESS_NAMES.items():
            if name in cmd_lower:
                alerts.append({
                    'check':    'PROCESS_NAME',
                    'severity': severity,
                    'pid':      proc['pid'],
                    'user':     proc['user'],
                    'command':  proc['command'][:80],
                    'reason':   reason,
                })
                break

        # Command-line pattern check
        for pattern, severity, reason in SUSPICIOUS_CMDLINE_PATTERNS:
            if re.search(pattern, cmd_lower):
                alerts.append({
                    'check':    'CMDLINE_PATTERN',
                    'severity': severity,
                    'pid':      proc['pid'],
                    'user':     proc['user'],
                    'command':  proc['command'][:80],
                    'reason':   reason,
                })
                break

    return processes, alerts

# ── Persistence Location Scanner ──────────────────────────────────────────────

def scan_persistence_locations():
    """
    Walk Mac persistence locations and flag anything worth reviewing.
    Keyloggers and malware typically install a LaunchAgent/Daemon plist
    so they restart automatically on every login/reboot.
    """
    findings = []

    for location_template, description in PERSISTENCE_LOCATIONS:
        location = os.path.expanduser(location_template)

        # Check shell config files (single files, not directories)
        if location.endswith(('.bash_profile', '.zshrc', '.profile')):
            if os.path.isfile(location):
                findings.append({
                    'path':        location,
                    'type':        'SHELL_CONFIG',
                    'severity':    'INFO',
                    'description': description,
                    'size':        os.path.getsize(location),
                    'modified':    datetime.fromtimestamp(
                                       os.path.getmtime(location)
                                   ).strftime('%Y-%m-%d %H:%M'),
                })
            continue

        # Walk directories
        if not os.path.isdir(location):
            continue

        for root, dirs, files in os.walk(location):
            # Skip hidden sub-directories (e.g. .git)
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    size    = os.path.getsize(filepath)
                    mtime   = os.path.getmtime(filepath)
                    mod_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')
                    ext     = os.path.splitext(filename)[1].lower()

                    # Determine severity based on location and file type
                    severity = 'INFO'
                    if 'LaunchDaemons' in filepath:
                        severity = 'MEDIUM'
                    elif 'LaunchAgents' in filepath:
                        severity = 'LOW'
                    if ext in SUSPICIOUS_EXTENSIONS:
                        severity = 'HIGH'

                    # Plist files in LaunchAgents/Daemons are common —
                    # only flag ones modified very recently (last 7 days)
                    # or with suspicious names
                    suspicious_name = any(
                        kw in filename.lower()
                        for kw in ['key', 'log', 'spy', 'monitor', 'track',
                                   'record', 'capture', 'hidden', 'stealth']
                    )

                    recently_modified = (time.time() - mtime) < (7 * 86400)

                    if suspicious_name or ext in SUSPICIOUS_EXTENSIONS or recently_modified:
                        findings.append({
                            'path':        filepath,
                            'type':        'PERSISTENCE_FILE',
                            'severity':    severity,
                            'description': description,
                            'size':        size,
                            'modified':    mod_str,
                            'flags':       (
                                ('suspicious name ' if suspicious_name else '') +
                                ('executable ext '  if ext in SUSPICIOUS_EXTENSIONS else '') +
                                ('recently modified' if recently_modified else '')
                            ).strip(),
                        })
                except (PermissionError, OSError):
                    continue

    return findings

# ── Hidden File Scanner ────────────────────────────────────────────────────────

def scan_for_hidden_files():
    """
    Look for hidden files and executables in locations malware commonly uses.
    Legitimate software rarely hides files in /tmp or ~ directly.
    """
    suspicious = []
    search_locations = [
        os.path.expanduser('~'),
        '/tmp',
        '/var/tmp',
        os.path.expanduser('~/Library/Application Support'),
    ]

    for location in search_locations:
        if not os.path.isdir(location):
            continue
        try:
            for entry in os.listdir(location):
                filepath = os.path.join(location, entry)
                if not os.path.isfile(filepath):
                    continue

                is_hidden  = entry.startswith('.')
                ext        = os.path.splitext(entry)[1].lower()
                is_sus_ext = ext in SUSPICIOUS_EXTENSIONS

                if not (is_hidden or is_sus_ext):
                    continue

                try:
                    size  = os.path.getsize(filepath)
                    mtime = os.path.getmtime(filepath)
                    suspicious.append({
                        'path':     filepath,
                        'hidden':   is_hidden,
                        'ext':      ext,
                        'size':     size,
                        'modified': datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M'),
                        'severity': 'HIGH' if '/tmp' in filepath else 'MEDIUM',
                    })
                except (PermissionError, OSError):
                    continue
        except PermissionError:
            continue

    return suspicious

# ── Report Printer ────────────────────────────────────────────────────────────

def print_report(processes, proc_alerts, persist_findings, hidden_files):
    """Print a formatted forensic analysis report."""
    print(f"\n{'='*62}")
    print(f"  🔍 KEYLOGGER DETECTOR — System Report")
    print(f"{'='*62}")
    print(f"  Scanned  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Processes: {len(processes)} running")
    print(f"{'='*62}\n")

    total_alerts = 0

    # ── Process Alerts ────────────────────────────────────────────
    print(f"  📋 Process Analysis")
    print(f"  {'─'*50}")
    if proc_alerts:
        for a in proc_alerts:
            icon = SEVERITY_ICONS.get(a['severity'], '⚠️')
            print(f"  {icon} [{a['severity']}] {a['reason']}")
            print(f"     PID {a['pid']} ({a['user']}): {a['command']}")
            total_alerts += 1
    else:
        print(f"  ✅ No suspicious processes found")

    # ── Persistence Location Findings ─────────────────────────────
    print(f"\n  📁 Persistence Location Scan")
    print(f"  {'─'*50}")
    if persist_findings:
        for f in persist_findings:
            icon = SEVERITY_ICONS.get(f['severity'], '⚠️')
            rel  = f['path'].replace(os.path.expanduser('~'), '~')
            print(f"  {icon} [{f['severity']}] {rel}")
            print(f"     {f['description']}")
            if f.get('flags'):
                print(f"     Flags: {f['flags']}")
            print(f"     Size: {f['size']} bytes  Modified: {f['modified']}")
            total_alerts += 1
    else:
        print(f"  ✅ No suspicious persistence items found")

    # ── Hidden Files ──────────────────────────────────────────────
    print(f"\n  🗂  Hidden / Suspicious Files")
    print(f"  {'─'*50}")
    if hidden_files:
        for f in hidden_files:
            icon = SEVERITY_ICONS.get(f['severity'], '⚠️')
            rel  = f['path'].replace(os.path.expanduser('~'), '~')
            flags = []
            if f['hidden']:   flags.append('hidden')
            if f['ext'] in SUSPICIOUS_EXTENSIONS: flags.append(f"executable ext ({f['ext']})")
            print(f"  {icon} [{f['severity']}] {rel}")
            print(f"     Flags: {', '.join(flags)}  Size: {f['size']}B  Modified: {f['modified']}")
            total_alerts += 1
    else:
        print(f"  ✅ No hidden/suspicious files found")

    # ── Summary ───────────────────────────────────────────────────
    print(f"\n{'='*62}")
    if total_alerts == 0:
        print(f"  ✅ System looks clean — no keylogger indicators found.")
    else:
        print(f"  ⚠️  {total_alerts} item(s) flagged — review each one above.")
        print(f"  ℹ️  Not every finding is malicious — investigate context.")
    print(f"{'='*62}\n")

# ── Manual IOC Checker ────────────────────────────────────────────────────────

def check_manual_ioc():
    """Let the user check a specific process name or file path."""
    print("\n  🔎 Manual IOC Check")
    print("  ─────────────────────────────────────")
    target = input("  Enter process name or filename to check: ").strip().lower()
    if not target:
        return

    found = False
    for name, (severity, reason) in SUSPICIOUS_PROCESS_NAMES.items():
        if target in name or name in target:
            icon = SEVERITY_ICONS.get(severity, '⚠️')
            print(f"\n  {icon} MATCH: {reason}")
            print(f"  Severity: {severity}\n")
            found = True

    for pattern, severity, reason in SUSPICIOUS_CMDLINE_PATTERNS:
        if re.search(pattern, target):
            icon = SEVERITY_ICONS.get(severity, '⚠️')
            print(f"\n  {icon} PATTERN MATCH: {reason}")
            print(f"  Severity: {severity}\n")
            found = True

    if not found:
        print(f"\n  ✅ '{target}' not found in any IOC database.\n")

# ── Explainer ─────────────────────────────────────────────────────────────────

def explain_keyloggers():
    print("""
  📖 KEYLOGGERS — How They Work & How to Detect Them
  ══════════════════════════════════════════════════════

  WHAT IS A KEYLOGGER?
  A keylogger is software (or hardware) that records every keystroke
  a user types and secretly sends the data to an attacker. Every
  password, message, credit card number, and email you type is captured.

  HOW KEYLOGGERS WORK ON MAC:
  ┌──────────────────────────────────────────────────────┐
  │ Method 1: Accessibility API                          │
  │   → Requests system accessibility permissions        │
  │   → Can observe all keyboard events system-wide      │
  │   → Legitimate screen readers use the same API       │
  │   → Detection: check System Preferences → Privacy    │
  │                → Accessibility for unknown apps       │
  ├──────────────────────────────────────────────────────┤
  │ Method 2: CGEventTap (lower-level)                   │
  │   → Taps into the Core Graphics event stream         │
  │   → Requires Accessibility permission or root        │
  │   → Used by tools like logKext                       │
  ├──────────────────────────────────────────────────────┤
  │ Method 3: Kernel Extension (kext)                    │
  │   → Installs at the OS kernel level                  │
  │   → Hardest to detect, requires root to install      │
  │   → Largely blocked on modern macOS (SIP)            │
  └──────────────────────────────────────────────────────┘

  HOW KEYLOGGERS SURVIVE REBOOTS (PERSISTENCE):
  On Mac, the primary persistence mechanism is LaunchAgents/Daemons:
  • ~/Library/LaunchAgents/  — runs at user login
  • /Library/LaunchDaemons/  — runs at system boot (as root)

  A malicious plist file in these locations will restart the keylogger
  after every reboot. The plist specifies what program to run and when.

  Example malicious LaunchAgent plist:
  <?xml version="1.0"?>
  <!DOCTYPE plist ...>
  <plist>
    <dict>
      <key>Label</key>          <string>com.apple.updater</string>
      <key>ProgramArguments</key>
      <array><string>/tmp/.update.py</string></array>
      <key>RunAtLoad</key>      <true/>
      <key>KeepAlive</key>      <true/>
    </dict>
  </plist>

  Note: the label mimics Apple ("com.apple.updater") to blend in —
  this is a common evasion technique called "masquerading".

  WHAT WE CHECK IN THIS PROJECT:
  1. Running process names — against a database of known keyloggers
  2. Command-line arguments — patterns suggesting obfuscation/shells
  3. LaunchAgent/Daemon locations — unexpected or recently modified plists
  4. Shell configs (.zshrc, .bash_profile) — added startup commands
  5. Hidden files in temp directories — common malware staging areas

  HARDWARE KEYLOGGERS:
  Physical devices that plug between the keyboard and computer. Record
  keystrokes in onboard memory. Software detection is impossible —
  they require physical inspection of USB/PS2 connections.

  DEFENCES:
  ✅ Check System Preferences → Privacy → Accessibility regularly
  ✅ Audit ~/Library/LaunchAgents for unknown entries
  ✅ Use a password manager — keylogging captures typing, not clipboard
  ✅ 2FA — even if password is captured, second factor blocks login
  ✅ Full-disk encryption — prevents offline keylog file extraction
  ✅ Anti-malware software — signature-based detection (Project 21)
  ══════════════════════════════════════════════════════
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   KEYLOGGER DETECTOR                 ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Full system scan                ║")
        print("║  [2] Scan running processes only     ║")
        print("║  [3] Scan persistence locations only ║")
        print("║  [4] Scan for hidden files only      ║")
        print("║  [5] Check a specific name / path    ║")
        print("║  [6] How keyloggers work (explained) ║")
        print("║  [7] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            print("\n  Running full system scan...\n")
            processes, proc_alerts = scan_processes()
            persist_findings       = scan_persistence_locations()
            hidden_files           = scan_for_hidden_files()
            print_report(processes, proc_alerts, persist_findings, hidden_files)

        elif choice == "2":
            print("\n  Scanning running processes...")
            processes, alerts = scan_processes()
            print(f"\n  {'─'*50}")
            print(f"  Processes scanned : {len(processes)}")
            if alerts:
                print(f"  Alerts found      : {len(alerts)}\n")
                for a in alerts:
                    icon = SEVERITY_ICONS.get(a['severity'], '⚠️')
                    print(f"  {icon} [{a['severity']}] {a['reason']}")
                    print(f"     PID {a['pid']} ({a['user']}): {a['command']}")
            else:
                print(f"  ✅ No suspicious processes detected.\n")

        elif choice == "3":
            print("\n  Scanning persistence locations...")
            findings = scan_persistence_locations()
            if findings:
                print(f"\n  {len(findings)} item(s) found:\n")
                for f in findings:
                    icon = SEVERITY_ICONS.get(f['severity'], '⚠️')
                    rel  = f['path'].replace(os.path.expanduser('~'), '~')
                    print(f"  {icon} [{f['severity']}] {rel}")
                    print(f"     {f['description']}")
                    if f.get('flags'):
                        print(f"     Flags: {f['flags']}")
                    print()
            else:
                print("  ✅ No suspicious persistence items found.\n")

        elif choice == "4":
            print("\n  Scanning for hidden/suspicious files...")
            files = scan_for_hidden_files()
            if files:
                print(f"\n  {len(files)} suspicious file(s) found:\n")
                for f in files:
                    icon = SEVERITY_ICONS.get(f['severity'], '⚠️')
                    print(f"  {icon} {f['path']}")
                    print(f"     Modified: {f['modified']}  Size: {f['size']}B\n")
            else:
                print("  ✅ No hidden/suspicious files found.\n")

        elif choice == "5":
            check_manual_ioc()

        elif choice == "6":
            explain_keyloggers()

        elif choice == "7":
            print("\nGoodbye! Check your LaunchAgents regularly. 🔐\n")
            break

        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

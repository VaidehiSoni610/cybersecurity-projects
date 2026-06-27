"""
Project 20: ARP Spoof Detector
Concepts: ARP protocol, MAC addresses, ARP poisoning, MITM attacks,
          network monitoring, anomaly detection

What you'll learn:
- How ARP (Address Resolution Protocol) works and why it's inherently insecure
- What ARP spoofing / ARP poisoning is and how attackers use it for MITM
- How to read your system's ARP cache using subprocess
- How to detect duplicate MACs — the primary sign of ARP spoofing
- How to monitor the ARP table over time and alert on suspicious changes

Note: Reads the system ARP cache via 'arp -a' — no root required on Mac.
      Real ARP packet capture (like arpwatch) needs root + pcap library.
"""

import subprocess
import re
import time
import json
import os
from datetime import datetime

# ── ARP Cache Reader ──────────────────────────────────────────────────────────

def read_arp_table():
    """
    Read the system ARP cache by running 'arp -a'.
    The ARP cache maps IP addresses → MAC addresses for recently
    contacted devices on the local network.

    Returns a list of dicts: [{ip, mac, interface, hostname}, ...]
    """
    try:
        result = subprocess.run(
            ['arp', '-a'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return parse_arp_output(result.stdout)
    except FileNotFoundError:
        print("  ❌ 'arp' command not found on this system.")
        return []
    except subprocess.TimeoutExpired:
        print("  ❌ ARP command timed out.")
        return []

def parse_arp_output(raw_output):
    """
    Parse the output of 'arp -a' into structured records.

    Mac/Linux 'arp -a' format:
      hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
      ? (192.168.1.100) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
      ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
    """
    entries = []

    # Regex to capture: hostname (ip) at mac on interface
    pattern = re.compile(
        r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+'
        r'([0-9a-fA-F:]+(?:[0-9a-fA-F]{2}:?){5})\s+'
        r'(?:on\s+(\S+))?',
        re.IGNORECASE
    )

    for line in raw_output.strip().split('\n'):
        match = pattern.search(line)
        if not match:
            continue

        hostname, ip, mac, iface = match.groups()
        mac = mac.lower().rstrip(':')

        # Skip entries with 'incomplete' MAC (device offline)
        if 'incomplete' in line.lower() or len(mac) < 11:
            continue

        # Normalize MAC to xx:xx:xx:xx:xx:xx format
        mac = normalise_mac(mac)
        if not mac:
            continue

        entries.append({
            'hostname':  hostname if hostname != '?' else None,
            'ip':        ip,
            'mac':       mac,
            'interface': iface or 'unknown',
        })

    return entries

def normalise_mac(mac):
    """
    Normalise a MAC address to xx:xx:xx:xx:xx:xx format.
    Handles: aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabbccddeeff
    """
    # Remove all separators and validate
    clean = re.sub(r'[:\-\.]', '', mac).lower()
    if len(clean) != 12 or not re.match(r'^[0-9a-f]{12}$', clean):
        return None
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))

# ── OUI Lookup (MAC Vendor) ───────────────────────────────────────────────────

# Partial OUI database — first 3 bytes of MAC identify manufacturer
OUI_DB = {
    '00:50:56': 'VMware',
    '00:0c:29': 'VMware',
    '08:00:27': 'VirtualBox',
    '52:54:00': 'QEMU/KVM',
    'ac:de:48': 'Apple',
    'f8:ff:c2': 'Apple',
    '3c:22:fb': 'Apple',
    'a4:c3:f0': 'Apple',
    '00:1a:11': 'Google',
    '94:eb:2c': 'Google',
    '00:17:f2': 'Apple Airport',
    'b8:27:eb': 'Raspberry Pi',
    'dc:a6:32': 'Raspberry Pi',
    '00:e0:4c': 'Realtek',
    '00:1b:21': 'Intel',
    '8c:8d:28': 'Intel',
    'fc:3f:db': 'Apple',
    '28:cd:c1': 'Apple',
}

def lookup_vendor(mac):
    """Look up the hardware vendor from the first 3 bytes of a MAC."""
    prefix = mac[:8].lower()
    return OUI_DB.get(prefix, 'Unknown vendor')

# ── Detection Engine ──────────────────────────────────────────────────────────

def detect_duplicate_macs(entries):
    """
    PRIMARY DETECTION: One MAC address serving multiple IP addresses.
    This is the strongest indicator of ARP spoofing / poisoning.

    Legitimate scenario: a router may have one MAC but multiple IPs.
    Suspicious: a non-gateway device shares a MAC with the gateway.
    """
    mac_to_ips = {}
    for entry in entries:
        mac = entry['mac']
        if mac not in mac_to_ips:
            mac_to_ips[mac] = []
        mac_to_ips[mac].append(entry['ip'])

    duplicates = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
    return duplicates

def detect_gateway_mac(entries):
    """
    Identify the likely default gateway entry in the ARP table.
    Gateways are typically the lowest host IP in the subnet (x.x.x.1).
    """
    candidates = [e for e in entries if e['ip'].endswith('.1')]
    if candidates:
        return candidates[0]
    # Fallback: return the entry with lowest last octet
    if entries:
        return sorted(entries, key=lambda e: int(e['ip'].split('.')[-1]))[0]
    return None

def check_broadcast_mac(entries):
    """
    Flag the broadcast MAC (ff:ff:ff:ff:ff:ff) appearing for a unicast IP.
    This can indicate a misconfiguration or ARP cache poisoning attempt.
    """
    return [e for e in entries if e['mac'] == 'ff:ff:ff:ff:ff:ff']

# ── Snapshot System ───────────────────────────────────────────────────────────

SNAPSHOT_FILE = 'arp_baseline.json'

def save_snapshot(entries):
    """Save the current ARP table as a baseline for future comparison."""
    snapshot = {
        'timestamp': datetime.now().isoformat(),
        'entries':   entries
    }
    with open(SNAPSHOT_FILE, 'w') as f:
        json.dump(snapshot, f, indent=2)
    print(f"  ✅ Baseline saved ({len(entries)} entries) → {SNAPSHOT_FILE}\n")

def load_snapshot():
    """Load a previously saved ARP baseline."""
    if not os.path.exists(SNAPSHOT_FILE):
        return None
    with open(SNAPSHOT_FILE) as f:
        return json.load(f)

def compare_with_baseline(current_entries):
    """
    Compare current ARP table against the saved baseline.
    Reports: new entries, removed entries, MAC changes for same IP.
    A MAC change for the gateway IP is a CRITICAL alert.
    """
    baseline = load_snapshot()
    if not baseline:
        print("  ⚠️  No baseline found. Run option [4] first to save one.\n")
        return

    baseline_entries = baseline['entries']
    baseline_time    = baseline['timestamp'][:19]

    # Build lookup dicts keyed by IP
    base_map    = {e['ip']: e for e in baseline_entries}
    current_map = {e['ip']: e for e in current_entries}

    new_ips     = set(current_map) - set(base_map)
    removed_ips = set(base_map)    - set(current_map)
    changed_ips = {ip for ip in set(base_map) & set(current_map)
                   if base_map[ip]['mac'] != current_map[ip]['mac']}

    print(f"\n  📋 ARP Table Change Report")
    print(f"  Baseline : {baseline_time} ({len(baseline_entries)} entries)")
    print(f"  Current  : {datetime.now().strftime('%H:%M:%S')} ({len(current_entries)} entries)")
    print(f"  {'─'*50}")

    alerts = 0

    if not new_ips and not removed_ips and not changed_ips:
        print("  ✅ No changes detected — ARP table matches baseline.\n")
        return

    for ip in sorted(new_ips):
        e = current_map[ip]
        print(f"  🟡 NEW     {ip:<18} {e['mac']}  ({lookup_vendor(e['mac'])})")
        alerts += 1

    for ip in sorted(removed_ips):
        e = base_map[ip]
        print(f"  🟠 REMOVED {ip:<18} {e['mac']}")
        alerts += 1

    for ip in sorted(changed_ips):
        old_mac = base_map[ip]['mac']
        new_mac = current_map[ip]['mac']
        severity = "🚨 CRITICAL" if ip.endswith('.1') else "🔴 WARNING"
        print(f"  {severity} MAC CHANGED for {ip}")
        print(f"    Was : {old_mac}  ({lookup_vendor(old_mac)})")
        print(f"    Now : {new_mac}  ({lookup_vendor(new_mac)})")
        if ip.endswith('.1'):
            print(f"    ⚠️  Gateway MAC changed — possible ARP poisoning / MITM attack!")
        alerts += 1

    print(f"\n  {alerts} change(s) detected.\n")

# ── Full Scan Report ──────────────────────────────────────────────────────────

def run_full_scan():
    """Read ARP table and run all detection checks."""
    print(f"\n  Reading ARP cache...", end='\r')
    entries = read_arp_table()

    if not entries:
        print("  ⚠️  ARP table is empty or could not be read.")
        print("  Try browsing your local network first to populate the cache.\n")
        return entries

    print(f"\n{'='*60}")
    print(f"  🔍 ARP SPOOF DETECTOR — Full Scan")
    print(f"{'='*60}")
    print(f"  Scanned  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Entries  : {len(entries)} in ARP cache\n")

    # ── Display ARP Table ───────────────────────────────────────
    print(f"  {'IP Address':<20} {'MAC Address':<20} {'Vendor':<18} Interface")
    print(f"  {'─'*18} {'─'*18} {'─'*16} {'─'*8}")

    gateway = detect_gateway_mac(entries)
    for entry in sorted(entries, key=lambda e: tuple(int(x) for x in e['ip'].split('.'))):
        vendor  = lookup_vendor(entry['mac'])
        gw_flag = ' ← gateway' if gateway and entry['ip'] == gateway['ip'] else ''
        print(f"  {entry['ip']:<20} {entry['mac']:<20} {vendor:<18} "
              f"{entry['interface']}{gw_flag}")

    # ── Detection Checks ────────────────────────────────────────
    alerts = 0
    print(f"\n  {'─'*50}")
    print(f"  🚦 Detection Results")
    print(f"  {'─'*50}")

    # Check 1: Duplicate MACs
    duplicates = detect_duplicate_macs(entries)
    if duplicates:
        for mac, ips in duplicates.items():
            print(f"  🚨 DUPLICATE MAC: {mac} ({lookup_vendor(mac)})")
            print(f"     Assigned to multiple IPs: {', '.join(ips)}")
            if any(ip.endswith('.1') for ip in ips):
                print(f"     ⚠️  Gateway IP involved — HIGH SUSPICION of ARP spoofing!")
            alerts += 1
    else:
        print(f"  ✅ No duplicate MACs detected")

    # Check 2: Broadcast MAC
    broadcast = check_broadcast_mac(entries)
    if broadcast:
        for e in broadcast:
            print(f"  ⚠️  Broadcast MAC on unicast IP: {e['ip']}")
            alerts += 1
    else:
        print(f"  ✅ No broadcast MAC anomalies")

    # Check 3: Gateway status
    if gateway:
        vendor = lookup_vendor(gateway['mac'])
        print(f"  ℹ️  Gateway: {gateway['ip']} → {gateway['mac']} ({vendor})")
    else:
        print(f"  ⚠️  Could not identify gateway")

    print(f"\n  {'='*58}")
    if alerts == 0:
        print(f"  ✅ ARP table looks clean — no spoofing indicators found.")
    else:
        print(f"  🚨 {alerts} alert(s) found — investigate immediately.")
    print(f"  {'='*58}\n")

    return entries

# ── Monitor Mode ──────────────────────────────────────────────────────────────

def monitor_mode(interval=10, duration=60):
    """
    Continuously monitor the ARP table and alert on any changes.
    Simulates what tools like arpwatch do in production.
    """
    print(f"\n  👁  ARP Monitor Mode")
    print(f"  Checking every {interval}s for {duration}s. Press Ctrl+C to stop.\n")

    baseline = {e['ip']: e['mac'] for e in read_arp_table()}
    print(f"  Baseline recorded: {len(baseline)} entries")
    print(f"  {'─'*50}")

    elapsed = 0
    try:
        while elapsed < duration:
            time.sleep(interval)
            elapsed += interval
            current = {e['ip']: e['mac'] for e in read_arp_table()}

            changed = {ip for ip in set(baseline) & set(current)
                       if baseline[ip] != current[ip]}
            new     = set(current) - set(baseline)

            if changed or new:
                ts = datetime.now().strftime('%H:%M:%S')
                for ip in changed:
                    severity = "🚨 CRITICAL" if ip.endswith('.1') else "🔴 WARNING"
                    print(f"  [{ts}] {severity} MAC changed for {ip}")
                    print(f"    {baseline[ip]} → {current[ip]}")
                for ip in new:
                    print(f"  [{ts}] 🟡 New device: {ip} → {current[ip]}")
                baseline = current
            else:
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] ✅ No changes", end='\r')

    except KeyboardInterrupt:
        print(f"\n\n  Monitor stopped.\n")

# ── Explainer ─────────────────────────────────────────────────────────────────

def explain_arp_spoofing():
    print("""
  📖 ARP SPOOFING / ARP POISONING — How MITM Attacks Work
  ══════════════════════════════════════════════════════

  WHAT IS ARP?
  ARP (Address Resolution Protocol) translates IP addresses → MAC addresses.
  When device A wants to talk to 192.168.1.1 (the router), it broadcasts:
  "Who has 192.168.1.1? Tell 192.168.1.50"
  The router replies: "192.168.1.1 is at aa:bb:cc:dd:ee:ff"
  Device A stores this in its ARP cache and uses it for all future traffic.

  THE VULNERABILITY:
  ARP has NO authentication. Any device can send an ARP reply at any time
  claiming any IP-to-MAC mapping — even without being asked.
  Devices accept and cache these replies unconditionally.

  THE ATTACK (ARP Spoofing):
  1. Attacker sends fake ARP reply to Alice:
     "192.168.1.1 (router) is at attacker_mac"  (LIE)
  2. Attacker sends fake ARP reply to the router:
     "192.168.1.50 (Alice) is at attacker_mac"  (LIE)
  3. Now ALL traffic between Alice and the router flows through the attacker.
     This is a classic Man-In-The-Middle (MITM) attack.

  Normal traffic flow:
    Alice ──────────────────────────── Router ── Internet

  After ARP poisoning:
    Alice ── Attacker (sees everything) ── Router ── Internet

  WHAT ATTACKERS CAN DO WITH MITM:
  ⚠️  Credential theft — capture unencrypted HTTP logins
  ⚠️  Session hijacking — steal cookies and take over accounts
  ⚠️  SSL stripping — downgrade HTTPS to HTTP
  ⚠️  Traffic injection — insert malicious content into pages
  ⚠️  DNS spoofing — redirect traffic to fake websites

  HOW WE DETECT IT:
  Primary indicator: one MAC address serving multiple IP addresses.
  If the router's MAC suddenly matches another device → poisoning!

  DEFENCES:
  ✅ Static ARP entries — manually set the gateway MAC (small networks)
  ✅ Dynamic ARP Inspection (DAI) — enterprise switch feature
  ✅ HTTPS everywhere — encrypted traffic can't be read even if intercepted
  ✅ VPN — encrypts all traffic end-to-end
  ✅ arpwatch — monitors ARP table and alerts on changes (what we built)
  ══════════════════════════════════════════════════════
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   ARP SPOOF DETECTOR                 ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Scan ARP table now              ║")
        print("║  [2] Compare with baseline           ║")
        print("║  [3] Monitor for changes             ║")
        print("║  [4] Save current table as baseline  ║")
        print("║  [5] How ARP spoofing works          ║")
        print("║  [6] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            run_full_scan()

        elif choice == "2":
            entries = read_arp_table()
            compare_with_baseline(entries)

        elif choice == "3":
            try:
                interval = int(input("\n  Check interval in seconds (default 10): ").strip() or 10)
                duration = int(input("  Monitor duration in seconds (default 60): ").strip() or 60)
            except ValueError:
                interval, duration = 10, 60
            monitor_mode(interval, duration)

        elif choice == "4":
            entries = read_arp_table()
            if entries:
                save_snapshot(entries)
            else:
                print("  ⚠️  Cannot save empty ARP table.\n")

        elif choice == "5":
            explain_arp_spoofing()

        elif choice == "6":
            print("\nGoodbye! Trust no ARP reply. 🔐\n")
            break

        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

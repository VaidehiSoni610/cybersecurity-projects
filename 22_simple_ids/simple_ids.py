"""
Project 22: Simple Intrusion Detection System (IDS)
Concepts: signature-based detection, anomaly-based detection, Snort-style rules,
          port scan detection, flood/DoS detection, live connection monitoring

What you'll learn:
- How real IDS/IPS products like Snort and Suricata structure detection rules
- The difference between signature-based and anomaly-based detection
- How to detect port scans and connection floods using time-windowed thresholds
- How to monitor your own machine's live connections for suspicious patterns
- Why an IDS only alerts, while an IPS alerts AND actively blocks traffic

Builds on: Project 3 (port scanning), Project 8 (rule-based log analysis),
           Project 18 (packet/connection structure), Project 21 (signature matching)
"""

import subprocess
import re
import time
from datetime import datetime, timedelta
from collections import defaultdict

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_ICONS = {
    "CRITICAL": "🚨",
    "HIGH":     "🔴",
    "MEDIUM":   "🟠",
    "LOW":      "🟡",
    "INFO":     "🔵",
}

# ── Signature-Based Detection (Snort-style rules) ─────────────────────────────

class SignatureRule:
    """
    A single detection rule, modelled after real Snort/Suricata rule syntax:
        alert tcp any any -> any 80 (msg:"SQLi attempt"; content:"' OR '1'='1"; sid:1000001;)

    A rule matches a connection event if protocol, destination port, and
    content pattern (a substring found in the payload) all match. Any field
    set to "ANY" is treated as a wildcard.
    """
    def __init__(self, sid, msg, severity, protocol="ANY", dst_port="ANY", content=None):
        self.sid      = sid
        self.msg      = msg
        self.severity = severity
        self.protocol = protocol
        self.dst_port = dst_port
        self.content  = content

    def matches(self, event):
        if self.protocol != "ANY" and self.protocol != event.get("protocol"):
            return False
        if self.dst_port != "ANY" and self.dst_port != event.get("dst_port"):
            return False
        if self.content:
            payload = event.get("payload", "")
            if self.content.lower() not in payload.lower():
                return False
        return True


# Built-in ruleset — simplified versions of real-world IDS signatures
SIGNATURE_RULES = [
    SignatureRule(1000001, "SQL Injection — tautology pattern",
                  "HIGH", "TCP", 80, content="' OR '1'='1"),
    SignatureRule(1000002, "SQL Injection — UNION SELECT data exfiltration",
                  "HIGH", "TCP", 80, content="UNION SELECT"),
    SignatureRule(1000003, "Cross-Site Scripting (XSS) attempt",
                  "MEDIUM", "TCP", 80, content="<script>"),
    SignatureRule(1000004, "Directory traversal attempt",
                  "MEDIUM", "TCP", 80, content="../../../"),
    SignatureRule(1000005, "EICAR test string in transit",
                  "INFO", "ANY", "ANY", content="EICAR-STANDARD-ANTIVIRUS-TEST-FILE"),
    SignatureRule(1000006, "Shellcode NOP sled detected",
                  "CRITICAL", "TCP", "ANY", content="\\x90\\x90\\x90\\x90"),
    SignatureRule(1000007, "Known attack tool user-agent (sqlmap)",
                  "HIGH", "TCP", 80, content="sqlmap"),
    SignatureRule(1000008, "Cleartext Telnet login attempt",
                  "MEDIUM", "TCP", 23),
    SignatureRule(1000009, "Possible C2 beacon check-in pattern",
                  "CRITICAL", "TCP", "ANY", content="beacon_check_in"),
]

# Known-bad IPs — simulates a threat intelligence blocklist feed
BLACKLISTED_IPS = {
    "45.33.32.156":   "Repeat scanning source seen across multiple honeypots",
    "185.220.101.45": "Known Tor exit node associated with malicious activity",
    "198.51.100.7":   "Flagged in commercial threat intelligence feed",
}

def check_signatures(event):
    """Check an event against every signature rule. Returns list of hits."""
    return [rule for rule in SIGNATURE_RULES if rule.matches(event)]

def check_blacklist(event):
    """Check if the event's source IP is on the threat intelligence blocklist."""
    src = event.get("src_ip")
    if src in BLACKLISTED_IPS:
        return BLACKLISTED_IPS[src]
    return None

# ── Anomaly-Based Detection ───────────────────────────────────────────────────

class PortScanDetector:
    """
    Flags a source IP that contacts many DISTINCT ports in a short time window.
    This is the classic signature of a port scan (Project 3's technique, seen
    from the defender's side) — low volume per port, but high port diversity.
    """
    def __init__(self, port_threshold=8, time_window=5):
        self.port_threshold = port_threshold
        self.time_window    = time_window
        self.activity       = defaultdict(list)   # src_ip -> [(time, port), ...]

    def process(self, event):
        src, t, port = event["src_ip"], event["time"], event["dst_port"]
        self.activity[src].append((t, port))
        self.activity[src] = [(tt, p) for tt, p in self.activity[src]
                               if t - tt <= self.time_window]

        distinct_ports = {p for _, p in self.activity[src]}
        if len(distinct_ports) >= self.port_threshold:
            return {
                "sid":      "ANOMALY-PORTSCAN",
                "msg":      f"Possible port scan from {src} "
                            f"({len(distinct_ports)} distinct ports in {self.time_window}s)",
                "severity": "HIGH",
            }
        return None


class FloodDetector:
    """
    Flags a source IP making an unusually high number of connections to the
    SAME destination in a short time window. This pattern indicates a
    connection flood, brute-force attempt, or denial-of-service attack.
    """
    def __init__(self, conn_threshold=15, time_window=3):
        self.conn_threshold = conn_threshold
        self.time_window    = time_window
        self.activity       = defaultdict(list)   # (src_ip,dst_port) -> [time, ...]

    def process(self, event):
        key = (event["src_ip"], event["dst_port"])
        t   = event["time"]
        self.activity[key].append(t)
        self.activity[key] = [tt for tt in self.activity[key] if t - tt <= self.time_window]

        count = len(self.activity[key])
        if count >= self.conn_threshold:
            return {
                "sid":      "ANOMALY-FLOOD",
                "msg":      f"Possible connection flood from {event['src_ip']} "
                            f"to port {event['dst_port']} "
                            f"({count} connections in {self.time_window}s)",
                "severity": "CRITICAL",
            }
        return None

# ── Synthetic Traffic Feed ────────────────────────────────────────────────────

BASE_TIME = datetime(2024, 1, 15, 14, 0, 0)

def generate_sample_traffic():
    """
    Build a realistic mixed traffic stream: mostly normal connections,
    with embedded attack patterns the engine should catch.
    'time' is a synthetic offset in seconds — keeps the demo instant and
    deterministic rather than waiting on a real clock.
    """
    events = []

    # Normal browsing traffic — should generate zero alerts
    normal_sources = ["192.168.1.10", "192.168.1.22", "192.168.1.35"]
    for i, src in enumerate(normal_sources):
        events.append({"time": i * 2, "src_ip": src, "dst_ip": "10.0.0.1",
                        "dst_port": 443, "protocol": "TCP",
                        "payload": "GET /dashboard HTTP/1.1"})

    # SQL injection attempt
    events.append({"time": 8, "src_ip": "203.0.113.50", "dst_ip": "10.0.0.1",
                    "dst_port": 80, "protocol": "TCP",
                    "payload": "GET /login?user=admin' OR '1'='1 HTTP/1.1"})

    # XSS attempt
    events.append({"time": 9, "src_ip": "203.0.113.51", "dst_ip": "10.0.0.1",
                    "dst_port": 80, "protocol": "TCP",
                    "payload": "GET /comment?text=<script>alert(1)</script>"})

    # Directory traversal
    events.append({"time": 10, "src_ip": "203.0.113.52", "dst_ip": "10.0.0.1",
                    "dst_port": 80, "protocol": "TCP",
                    "payload": "GET /files?path=../../../etc/passwd HTTP/1.1"})

    # Connection from a blacklisted IP
    events.append({"time": 11, "src_ip": "185.220.101.45", "dst_ip": "10.0.0.1",
                    "dst_port": 443, "protocol": "TCP",
                    "payload": "GET /admin HTTP/1.1"})

    # EICAR string transiting the network (ties back to Project 21)
    events.append({"time": 12, "src_ip": "192.168.1.40", "dst_ip": "10.0.0.5",
                    "dst_port": 25, "protocol": "TCP",
                    "payload": "Attachment content: EICAR-STANDARD-ANTIVIRUS-TEST-FILE"})

    # Telnet login attempt
    events.append({"time": 13, "src_ip": "198.51.100.7", "dst_ip": "10.0.0.1",
                    "dst_port": 23, "protocol": "TCP", "payload": "login attempt"})

    # Port scan burst — one source, 10 distinct ports, all within 4 seconds
    # (Deliberately NOT a blacklisted IP — isolates the anomaly detector demo
    #  from the signature/blacklist demo above for clarity.)
    scan_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
    for i, port in enumerate(scan_ports):
        events.append({"time": 20 + (i * 0.4), "src_ip": "67.205.128.50",
                        "dst_ip": "10.0.0.1", "dst_port": port,
                        "protocol": "TCP", "payload": "SYN probe"})

    # Connection flood — one source hammering ONE port repeatedly
    for i in range(18):
        events.append({"time": 30 + (i * 0.1), "src_ip": "203.0.113.99",
                        "dst_ip": "10.0.0.1", "dst_port": 22,
                        "protocol": "TCP", "payload": "login attempt"})

    return sorted(events, key=lambda e: e["time"])

# ── Detection Engine ───────────────────────────────────────────────────────────

def run_engine(events, verbose=True):
    """
    Process every event through signature rules AND anomaly detectors.
    Prints a live-feed style trace, then returns a list of all alerts raised.
    """
    port_scan_detector = PortScanDetector()
    flood_detector      = FloodDetector()
    alerts = []

    if verbose:
        print(f"\n  {'TIME':<10} {'SRC IP':<17} → {'DST':<20} {'PROTO':<6} EVENT")
        print(f"  {'─'*9} {'─'*16}   {'─'*19} {'─'*5} {'─'*30}")

    for event in events:
        ts = (BASE_TIME + timedelta(seconds=event["time"])).strftime("%H:%M:%S")
        dst = f"{event['dst_ip']}:{event['dst_port']}"

        event_alerts = []

        # Signature checks
        for rule in check_signatures(event):
            event_alerts.append({"sid": rule.sid, "msg": rule.msg,
                                  "severity": rule.severity, "event": event})

        # Blacklist check
        reason = check_blacklist(event)
        if reason:
            event_alerts.append({"sid": "BLACKLIST", "msg": f"Blacklisted source IP — {reason}",
                                  "severity": "HIGH", "event": event})

        # Anomaly checks (always run, regardless of signature hits)
        scan_hit  = port_scan_detector.process(event)
        flood_hit = flood_detector.process(event)
        for hit in (scan_hit, flood_hit):
            if hit:
                event_alerts.append({**hit, "event": event})

        alerts.extend(event_alerts)

        if verbose:
            line = f"  {ts:<10} {event['src_ip']:<17} → {dst:<20} {event['protocol']:<6} {event['payload'][:35]}"
            print(line)
            for a in event_alerts:
                icon = SEVERITY_ICONS.get(a["severity"], "⚠️")
                print(f"            {icon} ALERT [{a['sid']}] {a['msg']}")

    return alerts

def print_summary(alerts):
    """Group and display all alerts by severity, like a SIEM dashboard would."""
    print(f"\n{'='*62}")
    print(f"  📊 IDS ALERT SUMMARY")
    print(f"{'='*62}")

    if not alerts:
        print("  ✅ No alerts raised — traffic looks clean.\n")
        return

    by_severity = defaultdict(list)
    for a in alerts:
        by_severity[a["severity"]].append(a)

    for severity in sorted(by_severity, key=lambda s: SEVERITY_ORDER.get(s, 9)):
        icon  = SEVERITY_ICONS.get(severity, "⚠️")
        group = by_severity[severity]
        print(f"\n  {icon} {severity} ({len(group)})")
        for a in group:
            src = a["event"]["src_ip"]
            print(f"     [{a['sid']}] {a['msg']}  (src: {src})")

    print(f"\n  Total alerts: {len(alerts)}")
    print(f"{'='*62}\n")

# ── Live Local Connection Monitor ─────────────────────────────────────────────

SUSPICIOUS_PORTS = {
    4444:  "Default Metasploit reverse shell handler port",
    31337: "Classic 'elite' backdoor port (Back Orifice era)",
    1337:  "Common modern C2/backdoor port",
    6667:  "IRC — historically used for botnet command & control",
    12345: "NetBus trojan default port",
}

def read_live_connections():
    """
    Read currently active network connections using the system 'netstat'
    command. This shows REAL connections from your machine right now —
    no synthetic data involved.
    """
    try:
        result = subprocess.run(['netstat', '-an'], capture_output=True,
                                 text=True, timeout=5)
        return parse_netstat(result.stdout)
    except FileNotFoundError:
        print("  ❌ 'netstat' command not found on this system.")
        return []
    except subprocess.TimeoutExpired:
        print("  ❌ netstat command timed out.")
        return []

def parse_netstat(raw_output):
    """
    Parse 'netstat -an' output into structured connection records.
    Mac/BSD format:
      tcp4   0  0  192.168.1.5.54321   140.82.121.3.443   ESTABLISHED
      tcp4   0  0  *.22                *.*                LISTEN
    """
    connections = []
    pattern = re.compile(
        r'^(tcp4?|tcp6?|udp4?|udp6?)\s+\d+\s+\d+\s+'
        r'(\S+)\s+(\S+)\s*(\S+)?',
        re.IGNORECASE
    )

    for line in raw_output.split('\n'):
        match = pattern.match(line.strip())
        if not match:
            continue
        proto, local, foreign, state = match.groups()

        local_port   = local.rsplit('.', 1)[-1]   if '.' in local   else ''
        foreign_port = foreign.rsplit('.', 1)[-1] if '.' in foreign else ''

        connections.append({
            "protocol":     proto.upper(),
            "local_addr":   local,
            "local_port":   local_port,
            "foreign_addr": foreign,
            "foreign_port": foreign_port,
            "state":        state or "",
        })

    return connections

def analyse_live_connections():
    """Snapshot the machine's real connections and flag anything suspicious."""
    print("\n  Reading live connections via netstat...")
    connections = read_live_connections()

    if not connections:
        print("  ⚠️  No connections found or netstat unavailable.\n")
        return

    established = [c for c in connections if c["state"].upper() == "ESTABLISHED"]
    listening    = [c for c in connections if c["state"].upper() == "LISTEN"]

    print(f"\n{'='*60}")
    print(f"  🔍 LIVE CONNECTION ANALYSIS")
    print(f"{'='*60}")
    print(f"  Total connections : {len(connections)}")
    print(f"  Established       : {len(established)}")
    print(f"  Listening         : {len(listening)}\n")

    alerts = 0

    # Check listening ports against suspicious port list
    for conn in listening:
        try:
            port = int(conn["local_port"])
        except ValueError:
            continue
        if port in SUSPICIOUS_PORTS:
            print(f"  🚨 SUSPICIOUS LISTENER on port {port}")
            print(f"     {SUSPICIOUS_PORTS[port]}")
            alerts += 1

    # Check established connections to suspicious remote ports
    for conn in established:
        try:
            port = int(conn["foreign_port"])
        except ValueError:
            continue
        if port in SUSPICIOUS_PORTS:
            print(f"  🚨 SUSPICIOUS OUTBOUND connection to {conn['foreign_addr']}")
            print(f"     {SUSPICIOUS_PORTS[port]}")
            alerts += 1

    # Flag repeated connections to the same foreign IP (possible beaconing)
    foreign_counts = defaultdict(int)
    for conn in established:
        ip = conn["foreign_addr"].rsplit('.', 1)[0]
        foreign_counts[ip] += 1
    for ip, count in foreign_counts.items():
        if count >= 5:
            print(f"  ⚠️  {count} simultaneous connections to {ip} — "
                  f"unusual concentration, worth reviewing")
            alerts += 1

    if alerts == 0:
        print(f"  ✅ No suspicious patterns found in current connections.")
    print(f"\n{'='*60}\n")

# ── Explainer ─────────────────────────────────────────────────────────────────

def explain_ids_concepts():
    print("""
  📖 HOW INTRUSION DETECTION SYSTEMS WORK
  ══════════════════════════════════════════════════════

  WHAT IS AN IDS?
  An IDS (Intrusion Detection System) monitors network traffic or system
  activity and ALERTS when it sees something suspicious. It does not
  block anything — it's a smoke detector, not a sprinkler system.

  IDS vs IPS:
  ┌─────────────────────────────────────────────────────┐
  │ IDS (Intrusion Detection System)                    │
  │   → Monitors and ALERTS only                        │
  │   → Passive — sits beside the traffic (out-of-band) │
  ├─────────────────────────────────────────────────────┤
  │ IPS (Intrusion Prevention System)                   │
  │   → Monitors and BLOCKS automatically               │
  │   → Active — sits inline with the traffic           │
  │   → Risk: a false positive can block real users!    │
  └─────────────────────────────────────────────────────┘

  TWO DETECTION APPROACHES (we built both):

  1. SIGNATURE-BASED (like Project 21's hash scanner, applied to traffic)
     Matches traffic against known-bad PATTERNS.
       alert tcp any any -> any 80 (msg:"SQLi"; content:"OR 1=1"; sid:1001;)
     ✅ Fast, accurate, zero false positives for KNOWN attacks
     ❌ Blind to brand-new attack patterns it has never seen

  2. ANOMALY-BASED (statistical thresholds — what our PortScanDetector
     and FloodDetector use)
     Flags behaviour that deviates from a normal baseline.
       "20 connections to 20 different ports in 5 seconds? That's a scan."
     ✅ Catches novel attacks with no existing signature
     ❌ Needs careful tuning — too sensitive = alert fatigue

  REAL-WORLD IDS/IPS PRODUCTS:
  • Snort     — the original open-source IDS, rules use the syntax we
                modelled above
  • Suricata  — modern multi-threaded IDS/IPS, Snort-rule compatible
  • Zeek (Bro)— network analysis framework, scriptable detection logic
  • CrowdStrike / SentinelOne — commercial EDR with IDS-like detection

  WHY BOTH DETECTION TYPES MATTER:
  A real SOC (Security Operations Center) runs BOTH signature and
  anomaly detection together. Signatures catch known threats instantly.
  Anomaly detection catches the zero-days that have no signature yet.
  Neither one alone is enough — this is called defence in depth.

  ALERT FATIGUE IS A REAL PROBLEM:
  Real IDS deployments generate THOUSANDS of alerts per day. Security
  analysts spend much of their time tuning rules and triaging alerts
  to separate real threats from noise — this is literally a full job
  title: "SOC Analyst" / "Security Analyst Tier 1".
  ══════════════════════════════════════════════════════
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   SIMPLE INTRUSION DETECTION SYSTEM  ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Run IDS against sample traffic  ║")
        print("║  [2] View signature rule database    ║")
        print("║  [3] Monitor live local connections  ║")
        print("║  [4] How IDS/IPS works (explained)   ║")
        print("║  [5] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            events = generate_sample_traffic()
            alerts = run_engine(events, verbose=True)
            print_summary(alerts)

        elif choice == "2":
            print(f"\n  📋 Signature Rules ({len(SIGNATURE_RULES)} loaded)")
            print(f"  {'─'*70}")
            print(f"  {'SID':<10} {'Severity':<10} {'Port':<6} Message")
            print(f"  {'─'*8} {'─'*8} {'─'*4} {'─'*40}")
            for r in SIGNATURE_RULES:
                icon = SEVERITY_ICONS.get(r.severity, "⚠️")
                print(f"  {r.sid:<10} {icon} {r.severity:<8} {str(r.dst_port):<6} {r.msg}")
            print(f"\n  🚫 Blacklisted IPs ({len(BLACKLISTED_IPS)})")
            for ip, reason in BLACKLISTED_IPS.items():
                print(f"     {ip:<18} — {reason}")
            print()

        elif choice == "3":
            analyse_live_connections()

        elif choice == "4":
            explain_ids_concepts()

        elif choice == "5":
            print("\nGoodbye! Stay vigilant. 🔐\n")
            break

        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

"""
Project 28: Honeypot Simulator
Concepts: honeypots, deception technology, attacker profiling, canary tokens,
          threat intelligence, low-interaction vs high-interaction honeypots

What you'll learn:
- What honeypots are and how defenders use them to detect and study attackers
- How fake service banners lure automated scanners into revealing themselves
- How to capture credentials from brute-force attempts against fake services
- What attacker behaviour patterns look like in honeypot logs
- The difference between low-interaction and high-interaction honeypots
- How canary tokens work as tripwires

Builds on: Project 3 (port scanning — now seen from the defender's side),
           Project 8 (log analysis), Project 22 (IDS detection rules)
"""

import socket
import threading
import time
import json
import os
import re
from datetime import datetime
from collections import defaultdict

# ── Session Log ────────────────────────────────────────────────────────────────

SESSION_LOG = []
LOG_FILE    = "honeypot_log.json"

def log_event(service, src_ip, src_port, event_type, data=""):
    """Record every honeypot interaction with a timestamp."""
    entry = {
        "time":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "service":    service,
        "src_ip":     src_ip,
        "src_port":   src_port,
        "event_type": event_type,
        "data":       data[:500] if data else "",
    }
    SESSION_LOG.append(entry)
    # Live console alert
    icon = {"CONNECT":"🔌","CREDENTIAL":"🔑","COMMAND":"💻",
            "SCAN":"🔍","PAYLOAD":"📦","DISCONNECT":"🔌"}.get(event_type, "📋")
    print(f"  {icon} [{entry['time'][11:]}] {service:<6} {src_ip:<18} "
          f"{event_type}: {data[:60]}")

# ── Fake Service Handlers ──────────────────────────────────────────────────────

def handle_fake_ssh(conn, addr):
    """
    Simulate an SSH server. Real SSH uses a version banner exchange first —
    attackers and scanners always grab this to fingerprint the service.
    Then they attempt authentication, revealing their credential wordlists.
    """
    ip, port = addr
    log_event("SSH", ip, port, "CONNECT", "Connection established")
    try:
        # SSH version banner — mimics an older OpenSSH to attract more attempts
        conn.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")
        data = conn.recv(256)
        if data:
            log_event("SSH", ip, port, "CREDENTIAL",
                      f"Client banner: {data[:60].decode('utf-8', errors='replace')}")

        # Simulate SSH auth failure loop (captures credential attempts)
        for attempt in range(4):
            # Send a simplified SSH auth failure response
            conn.sendall(
                b"\x00\x00\x00\x1c\x05\x14"          # packet length + auth failure
                b"\x00\x00\x00\x0epublickey,password" # auth methods
                b"\x00"
            )
            data = conn.recv(512)
            if not data:
                break
            decoded = data.decode('utf-8', errors='replace')
            # Look for username/password patterns in the raw bytes
            if b'password' in data.lower() or len(data) > 10:
                log_event("SSH", ip, port, "CREDENTIAL",
                          f"Auth attempt #{attempt+1}: {decoded[:80]}")
        conn.sendall(b"\x00\x00\x00\x0c\x05\x01\x00\x00\x00\x00\x00\x00")

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        log_event("SSH", ip, port, "DISCONNECT", "")
        try:
            conn.close()
        except Exception:
            pass


def handle_fake_http(conn, addr):
    """
    Simulate an HTTP server. Returns a fake login page and logs what
    attackers POST to it — revealing credential stuffing payloads,
    SQL injection attempts, and vulnerability scanner signatures.
    """
    ip, port = addr
    log_event("HTTP", ip, port, "CONNECT", "Connection established")
    try:
        data = conn.recv(4096)
        if not data:
            return
        request = data.decode('utf-8', errors='replace')
        first_line = request.split('\n')[0].strip()
        log_event("HTTP", ip, port, "SCAN", first_line)

        # Detect tool signatures in User-Agent header
        ua_match = re.search(r'User-Agent:\s*([^\r\n]+)', request, re.IGNORECASE)
        if ua_match:
            ua = ua_match.group(1).strip()
            scanners = ['sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab',
                        'python-requests', 'curl', 'wget', 'dirbuster']
            for scanner in scanners:
                if scanner.lower() in ua.lower():
                    log_event("HTTP", ip, port, "SCAN", f"Scanner detected: {ua}")
                    break

        # Log POST body — credential stuffing, injection payloads
        if 'POST' in request.upper():
            body_start = request.find('\r\n\r\n')
            if body_start != -1:
                body = request[body_start+4:]
                if body.strip():
                    log_event("HTTP", ip, port, "CREDENTIAL",
                              f"POST body: {body[:200]}")

        # Return a convincing fake admin login page
        html = (
            b"<html><head><title>Admin Login</title></head>"
            b"<body><h2>Administrator Login</h2>"
            b"<form method='POST'>"
            b"<input name='username'><input type='password' name='password'>"
            b"<button>Login</button></form></body></html>"
        )
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.6\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: " + str(len(html)).encode() + b"\r\n"
            b"X-Powered-By: PHP/5.6.40\r\n"
            b"\r\n" + html
        )
        conn.sendall(response)

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        log_event("HTTP", ip, port, "DISCONNECT", "")
        try:
            conn.close()
        except Exception:
            pass


def handle_fake_ftp(conn, addr):
    """
    Simulate an FTP server. FTP sends credentials in cleartext —
    attackers still target it heavily. This captures every attempt.
    """
    ip, port = addr
    log_event("FTP", ip, port, "CONNECT", "Connection established")
    try:
        conn.sendall(b"220 FTP Server Ready\r\n")

        username = ""
        for _ in range(6):
            data = conn.recv(256)
            if not data:
                break
            cmd = data.decode('utf-8', errors='replace').strip()

            if cmd.upper().startswith("USER"):
                username = cmd[5:].strip()
                log_event("FTP", ip, port, "CREDENTIAL",
                          f"USER: {username}")
                conn.sendall(b"331 Password required\r\n")

            elif cmd.upper().startswith("PASS"):
                password = cmd[5:].strip()
                log_event("FTP", ip, port, "CREDENTIAL",
                          f"PASS: {password}  (user: {username})")
                conn.sendall(b"530 Login incorrect\r\n")
                username = ""

            elif cmd.upper().startswith("QUIT"):
                conn.sendall(b"221 Goodbye\r\n")
                break
            else:
                conn.sendall(b"500 Unknown command\r\n")

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        log_event("FTP", ip, port, "DISCONNECT", "")
        try:
            conn.close()
        except Exception:
            pass


def handle_fake_telnet(conn, addr):
    """
    Simulate a Telnet server. Telnet is completely unencrypted — a strong
    signal that any connection is either legacy equipment or an attacker
    (modern systems should never run Telnet). Captures cleartext credentials.
    """
    ip, port = addr
    log_event("TEL", ip, port, "CONNECT", "Connection established")
    try:
        conn.sendall(b"\r\nWelcome to router management console\r\nlogin: ")
        username = conn.recv(128).decode('utf-8', errors='replace').strip()
        log_event("TEL", ip, port, "CREDENTIAL", f"Username: {username}")

        conn.sendall(b"Password: ")
        password = conn.recv(128).decode('utf-8', errors='replace').strip()
        log_event("TEL", ip, port, "CREDENTIAL",
                  f"Password: {password}  (user: {username})")

        conn.sendall(b"\r\nLogin failed\r\n")

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        log_event("TEL", ip, port, "DISCONNECT", "")
        try:
            conn.close()
        except Exception:
            pass

# ── Honeypot Service Manager ───────────────────────────────────────────────────

class HoneypotService:
    """A single fake service listener on a specific port."""

    SERVICES = {
        2222:  ("SSH",    handle_fake_ssh),
        8080:  ("HTTP",   handle_fake_http),
        2121:  ("FTP",    handle_fake_ftp),
        2323:  ("TEL",    handle_fake_telnet),
    }

    def __init__(self, port, name, handler):
        self.port    = port
        self.name    = name
        self.handler = handler
        self.running = False
        self._sock   = None

    def start(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(('127.0.0.1', self.port))
            self._sock.listen(10)
            self._sock.settimeout(0.5)
            self.running = True

            def _serve():
                while self.running:
                    try:
                        conn, addr = self._sock.accept()
                        t = threading.Thread(
                            target=self.handler, args=(conn, addr), daemon=True
                        )
                        t.start()
                    except socket.timeout:
                        continue
                    except OSError:
                        break

            t = threading.Thread(target=_serve, daemon=True)
            t.start()
            return True
        except OSError as e:
            print(f"  ⚠️  Could not start {self.name} on port {self.port}: {e}")
            return False

    def stop(self):
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


class HoneypotManager:
    """Manages multiple honeypot services simultaneously."""

    def __init__(self):
        self.services = []
        self.running  = False

    def start_all(self):
        print(f"\n  Starting honeypot services on localhost...\n")
        started = []
        for port, (name, handler) in HoneypotService.SERVICES.items():
            svc = HoneypotService(port, name, handler)
            if svc.start():
                self.services.append(svc)
                started.append(f"{name}:{port}")
                print(f"  ✅ {name:<6} honeypot listening on 127.0.0.1:{port}")
            else:
                print(f"  ❌ {name:<6} failed (port {port} in use?)")
        self.running = len(started) > 0
        if self.running:
            print(f"\n  {len(started)} service(s) active. Waiting for connections...")
            print(f"  Press Ctrl+C or enter to stop.\n")
        return started

    def stop_all(self):
        for svc in self.services:
            svc.stop()
        self.services = []
        self.running  = False
        print(f"\n  🔴 All honeypot services stopped.\n")

# ── Threat Report ──────────────────────────────────────────────────────────────

def generate_threat_report():
    """Analyse session log and produce an attacker profiling report."""
    if not SESSION_LOG:
        print("\n  📭 No events logged yet.\n")
        return

    events    = SESSION_LOG
    connects  = [e for e in events if e['event_type'] == 'CONNECT']
    creds     = [e for e in events if e['event_type'] == 'CREDENTIAL']
    scans     = [e for e in events if e['event_type'] == 'SCAN']

    # Count by source IP
    ip_counts = defaultdict(int)
    for e in connects:
        ip_counts[e['src_ip']] += 1

    # Extract usernames and passwords from credential events
    usernames  = []
    passwords  = []
    for e in creds:
        d = e['data']
        if 'USER:' in d or 'Username:' in d:
            u = d.split(':', 1)[-1].strip()
            if u:
                usernames.append(u)
        if 'PASS:' in d or 'Password:' in d:
            p = d.split('PASS:', 1)[-1].split('Password:', 1)[-1].split('(')[0].strip()
            if p:
                passwords.append(p)

    print(f"\n{'='*62}")
    print(f"  📊 HONEYPOT THREAT REPORT")
    print(f"{'='*62}")
    print(f"  Report time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total events: {len(events)}")
    print(f"  Connections : {len(connects)}")
    print(f"  Cred probes : {len(creds)}")
    print(f"  Scan events : {len(scans)}")
    print()

    # Service breakdown
    svc_counts = defaultdict(int)
    for e in connects:
        svc_counts[e['service']] += 1
    print(f"  📡 By Service:")
    for svc, cnt in sorted(svc_counts.items(), key=lambda x: -x[1]):
        bar = '█' * min(cnt, 20)
        print(f"    {svc:<6} {cnt:>3}  {bar}")

    # Top source IPs
    if ip_counts:
        print(f"\n  🌐 Top Source IPs:")
        for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1])[:5]:
            print(f"    {ip:<18} {cnt} connection(s)")

    # Credential analysis
    if usernames:
        from collections import Counter
        top_u = Counter(usernames).most_common(5)
        print(f"\n  🔑 Most-Tried Usernames:")
        for u, cnt in top_u:
            print(f"    {u:<20} (tried {cnt}x)")

    if passwords:
        from collections import Counter
        top_p = Counter(passwords).most_common(5)
        print(f"\n  🔑 Most-Tried Passwords:")
        for p, cnt in top_p:
            print(f"    {p:<20} (tried {cnt}x)")

    print(f"\n  {'='*58}")
    if len(connects) == 0:
        print(f"  ℹ️  No connections recorded yet.")
    elif len(creds) > 0:
        print(f"  ⚠️  Credential harvesting activity detected.")
        print(f"  These IPs are actively brute-forcing services.")
    else:
        print(f"  ✅ Connections recorded — no credential attempts yet.")
    print(f"  {'='*58}\n")

# ── Canary Token Explainer ─────────────────────────────────────────────────────

def explain_canary_tokens():
    print("""
  📖 CANARY TOKENS — Digital Tripwires
  ══════════════════════════════════════════════════════

  WHAT IS A CANARY TOKEN?
  A canary token is a hidden item — a URL, a file, a fake credential —
  that has no legitimate use. If it's ever triggered, you know someone
  (or something) has accessed a place they shouldn't have.

  The name comes from the "canary in a coal mine" — an early warning
  system. If the canary dies, something is very wrong.

  HOW THEY WORK:

  Example 1 — Fake credentials in a config file:
    Attacker breaks in, finds credentials.txt:
      DB_PASSWORD = honeypot_password_a3k9x
    They try those credentials → you get alerted → you know you've
    been breached AND you know they found the config file.

  Example 2 — Tracking URL in a document:
    Embed a unique URL in a sensitive internal document:
      https://canarytokens.org/unique_id_here/...
    If anyone views the document → the URL is fetched → you're alerted
    with the viewer's IP address and browser fingerprint.

  Example 3 — Fake AWS credentials:
    Add fake AWS_ACCESS_KEY in a code repo or .env file.
    If used → AWS alerts you, you know credentials were stolen.

  Example 4 — DNS canary token:
    A fake hostname like internal-db.secret.yourdomain.com
    that should NEVER be resolved. DNS query = breach indicator.

  TYPES OF CANARY TOKENS:
  ┌─────────────────────────────────────────────────────┐
  │ Web bug        → URL embedded in email/doc/page     │
  │ Fake creds     → API keys/passwords that alert      │
  │ Honeypot file  → file that shouldn't be accessed    │
  │ DNS token      → hostname that shouldn't be resolved│
  │ Excel/Word     → Office docs with embedded beacons  │
  └─────────────────────────────────────────────────────┘

  FREE SERVICE: canarytokens.org
  Create free canary tokens for dozens of trigger types.
  No setup required — get alerts via email or webhook.

  RELATIONSHIP TO HONEYPOTS:
  A honeypot = a fake SERVICE (SSH, HTTP, FTP)
  A canary token = a fake ITEM (credential, file, URL)
  Both are deception technology — the goal is the same:
  detect intruders by watching what they touch or try.
  ══════════════════════════════════════════════════════
""")

# ── Explainer ──────────────────────────────────────────────────────────────────

def explain_honeypots():
    print("""
  📖 HONEYPOTS — Deception as a Security Strategy
  ══════════════════════════════════════════════════════

  WHAT IS A HONEYPOT?
  A honeypot is a fake system or service deliberately set up to attract
  and detect attackers. It looks real but has no legitimate users — so
  ANY interaction is suspicious by definition.

  "If you get a connection to your honeypot SSH server,
   someone is probing your network. Period."

  LOW-INTERACTION vs HIGH-INTERACTION:
  ┌──────────────────────────────────────────────────────┐
  │ LOW-INTERACTION (what we built)                      │
  │   Simulates service banners and simple responses     │
  │   No real OS underneath — cannot be truly exploited  │
  │   Safe, easy to deploy, low maintenance             │
  │   Gathers: IPs, scan patterns, credential wordlists  │
  │   Tools: Honeyd, Cowrie (low mode), what we built   │
  ├──────────────────────────────────────────────────────┤
  │ HIGH-INTERACTION                                     │
  │   Real OS and services — attackers can fully exploit │
  │   Dangerous: attacker may pivot to other systems     │
  │   Requires careful isolation (VM, network firewall)  │
  │   Gathers: full attack techniques, tools, malware    │
  │   Tools: Cowrie (full), real systems in a sandbox    │
  └──────────────────────────────────────────────────────┘

  WHAT HONEYPOTS REVEAL:
  • Which ports are being scanned (attacker target list)
  • Automated tool signatures (User-Agent, packet patterns)
  • Credential wordlists (what passwords attackers try)
  • Attack timing patterns (automated bots vs humans)
  • New techniques not yet in signature databases

  HONEYNETS:
  A collection of honeypots forming a fake network segment.
  Used by security researchers to study attack campaigns.
  The Honeynet Project (honeynet.org) shares this research publicly.

  REAL-WORLD DEPLOYMENT:
  Place honeypots on internal networks where legitimate traffic
  should NEVER appear. Any connection = lateral movement attempt.
  For example: fake Windows fileshare on VLAN that only servers use.
  If any workstation touches it → it's likely compromised.

  LEGAL NOTE:
  Honeypots are legal to run on your own network.
  Attacker activity logged by a honeypot is typically admissible
  in court as evidence of unauthorised access.
  ══════════════════════════════════════════════════════
""")

# ── Traffic Simulator (for demo without real attackers) ───────────────────────

def simulate_attack_traffic(manager):
    """
    Simulate realistic attacker traffic against the running honeypots
    so you can see how the logging works without waiting for real connections.
    Uses localhost connections — completely safe, everything stays local.
    """
    print(f"\n  🎭 Simulating attack traffic...\n")
    time.sleep(0.5)

    def _connect_and_send(port, data_sequence, delay=0.05):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(('127.0.0.1', port))
            for data in data_sequence:
                try:
                    s.recv(512)     # read server banner/prompt
                except Exception:
                    pass
                if data:
                    s.sendall(data if isinstance(data, bytes) else data.encode())
                time.sleep(delay)
            s.close()
        except Exception:
            pass

    # Simulate SSH scanner
    _connect_and_send(2222, [
        b"SSH-2.0-libssh_0.9.3\r\n",
        None,
        None,
        None,
    ])

    time.sleep(0.2)

    # Simulate FTP brute force
    _connect_and_send(2121, [
        b"USER admin\r\n",
        b"PASS password123\r\n",
        b"USER root\r\n",
        b"PASS toor\r\n",
        b"QUIT\r\n",
    ])

    time.sleep(0.2)

    # Simulate HTTP scanner
    _connect_and_send(8080, [
        (b"GET /admin HTTP/1.1\r\nHost: localhost\r\n"
         b"User-Agent: sqlmap/1.7.8\r\n\r\n"),
    ])

    time.sleep(0.2)

    # Simulate Telnet probe
    _connect_and_send(2323, [
        b"admin\r\n",
        b"admin123\r\n",
    ])

    time.sleep(0.5)
    print(f"\n  ✅ Simulation complete. Check the report (option [3]).\n")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    manager = HoneypotManager()

    while True:
        status = "🟢 RUNNING" if manager.running else "🔴 STOPPED"
        print(f"\n╔══════════════════════════════════════╗")
        print(f"║   HONEYPOT SIMULATOR          {status} ║")
        print(f"║   Cybersecurity Learning Project     ║")
        print(f"╠══════════════════════════════════════╣")
        print(f"║  [1] Start all honeypot services     ║")
        print(f"║  [2] Simulate attack traffic (demo)  ║")
        print(f"║  [3] View threat report              ║")
        print(f"║  [4] Show live event log             ║")
        print(f"║  [5] Stop all services               ║")
        print(f"║  [6] How honeypots work              ║")
        print(f"║  [7] What are canary tokens?         ║")
        print(f"║  [8] Exit                            ║")
        print(f"╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            if manager.running:
                print("\n  ⚠️  Services already running. Stop them first (option 5).\n")
                continue
            manager.start_all()

        elif choice == "2":
            if not manager.running:
                print("\n  ❌ Start the honeypot services first (option 1).\n")
                continue
            simulate_attack_traffic(manager)

        elif choice == "3":
            generate_threat_report()

        elif choice == "4":
            if not SESSION_LOG:
                print("\n  📭 No events yet.\n")
                continue
            print(f"\n  📋 Live Event Log ({len(SESSION_LOG)} entries)")
            print(f"  {'─'*60}")
            for e in SESSION_LOG[-20:]:
                t   = e['time'][11:]
                svc = e['service']
                ip  = e['src_ip']
                evt = e['event_type']
                d   = e['data'][:50]
                print(f"  {t} {svc:<6} {ip:<18} {evt:<12} {d}")
            if len(SESSION_LOG) > 20:
                print(f"  ... ({len(SESSION_LOG)-20} earlier entries)")
            print()

        elif choice == "5":
            if manager.running:
                manager.stop_all()
            else:
                print("\n  ⚠️  No services are running.\n")

        elif choice == "6":
            explain_honeypots()

        elif choice == "7":
            explain_canary_tokens()

        elif choice == "8":
            if manager.running:
                manager.stop_all()
            print("\nGoodbye! Deceive to detect. 🔐\n")
            break

        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

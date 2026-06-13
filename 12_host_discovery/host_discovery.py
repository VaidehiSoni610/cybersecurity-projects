"""
Project 12: Network Host Discovery (Ping Sweeper)
Concepts: ICMP, ARP, network ranges, CIDR notation, live host detection

What you'll learn:
- What a ping sweep is and how attackers use it
- How IP address ranges work (192.168.1.0/24 explained)
- How to discover active hosts on a network
- What ICMP is and why ping works
- The difference between internal and external scanning

⚠ Only scan networks you own or have explicit permission to scan.
"""

import socket
import concurrent.futures
import subprocess
import platform
import time
import ipaddress
from datetime import datetime

# ── Network Range Parser ──────────────────────────────────────────────────────

def parse_ip_range(target):
    """
    Parse various IP input formats into a list of IP addresses.
    Supports:
    - Single IP:   192.168.1.1
    - CIDR range:  192.168.1.0/24  (256 addresses)
    - Range:       192.168.1.1-20  (custom range)
    """
    target = target.strip()
    ips = []

    try:
        # CIDR notation (e.g. 192.168.1.0/24)
        if '/' in target:
            network = ipaddress.IPv4Network(target, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            print(f"  Parsed CIDR: {target} → {len(ips)} hosts")

        # Range notation (e.g. 192.168.1.1-50)
        elif '-' in target.split('.')[-1]:
            base = '.'.join(target.split('.')[:-1])
            last = target.split('.')[-1]
            start, end = last.split('-')
            ips = [f"{base}.{i}" for i in range(int(start), int(end)+1)]
            print(f"  Parsed range: {target} → {len(ips)} hosts")

        # Single IP
        else:
            socket.inet_aton(target)  # Validate it's a real IP
            ips = [target]

    except (ValueError, socket.error) as e:
        print(f"  ❌ Invalid target format: {e}")

    return ips

# ── Host Detection Methods ────────────────────────────────────────────────────

def ping_host(ip, timeout=1):
    """
    Send a ping (ICMP echo request) to a host.
    Uses the OS ping command — works on Mac/Linux without root.
    Returns True if host responded, False if not.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-W' if platform.system().lower() != 'windows' else '/w'

    try:
        result = subprocess.run(
            ['ping', param, '1', timeout_param, str(int(timeout*1000)),  ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def tcp_probe(ip, ports=(80, 443, 22, 445), timeout=0.5):
    """
    Alternative to ping: try connecting to common ports.
    If ANY port responds, the host is up.
    Useful when ICMP (ping) is blocked by firewalls.
    """
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return True, port
        except Exception:
            pass
    return False, None

def get_hostname(ip):
    """Try reverse DNS lookup — convert IP back to hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def probe_host(ip, method="ping"):
    """
    Probe a single host and return its status.
    Returns dict with ip, alive, hostname, open_port.
    """
    alive = False
    open_port = None
    hostname = None

    if method == "ping":
        alive = ping_host(ip)
    else:
        alive, open_port = tcp_probe(ip)

    if alive:
        hostname = get_hostname(ip)

    return {
        "ip":        ip,
        "alive":     alive,
        "hostname":  hostname,
        "open_port": open_port,
    }

# ── Sweep Engine ──────────────────────────────────────────────────────────────

def sweep_network(target, method="ping", max_workers=30):
    """
    Sweep a network range for live hosts.
    """
    ips = parse_ip_range(target)
    if not ips:
        return []

    print(f"\n{'='*60}")
    print(f"  🔍 NETWORK HOST DISCOVERY")
    print(f"{'='*60}")
    print(f"  Target   : {target}")
    print(f"  Hosts    : {len(ips)} IPs to probe")
    print(f"  Method   : {'ICMP Ping' if method=='ping' else 'TCP Port Probe'}")
    print(f"  Started  : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}\n")
    print(f"  {'IP Address':<18} {'Status':<10} {'Hostname'}")
    print(f"  {'─'*17} {'─'*9} {'─'*25}")

    alive_hosts = []
    tested = 0
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(probe_host, ip, method): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            tested += 1
            print(f"  Scanning {tested}/{len(ips)}...", end="\r")

            if result["alive"]:
                alive_hosts.append(result)
                hostname = result["hostname"] or "—"
                port_note = f" (port {result['open_port']} open)" if result["open_port"] else ""
                print(f"  {result['ip']:<18} 🟢 UP    {hostname}{port_note}")

    elapsed = time.time() - start

    print(f"\n{'='*60}")
    print(f"  ✅ Sweep complete in {elapsed:.1f}s")
    print(f"  💻 Live hosts: {len(alive_hosts)} / {len(ips)}")
    print(f"{'='*60}\n")

    if alive_hosts:
        print("  📋 Summary of live hosts:")
        for h in alive_hosts:
            hostname = f"({h['hostname']})" if h['hostname'] else ""
            print(f"  • {h['ip']} {hostname}")
        print()

    return alive_hosts

# ── CIDR Explainer ────────────────────────────────────────────────────────────

def explain_cidr():
    """Teach CIDR notation — one of the most confusing topics for beginners."""
    print("""
  📖 CIDR NOTATION EXPLAINED — Plain English
  ══════════════════════════════════════════════════════

  An IP address has 4 parts: 192 . 168 . 1 . 0
  Each part is 1 byte (0-255). Total = 32 bits.

  CIDR (Classless Inter-Domain Routing) notation:
  192.168.1.0/24

  The /24 means the first 24 bits are the NETWORK part.
  The remaining 8 bits are for HOSTS.

  /24 → 2^8 = 256 addresses (254 usable hosts)
  /16 → 2^16 = 65,536 addresses
  /8  → 2^24 = 16,777,216 addresses

  Common ranges you'll see:
  ┌────────────────┬──────────┬──────────────────────────┐
  │ Range          │ Hosts    │ Common use               │
  ├────────────────┼──────────┼──────────────────────────┤
  │ 192.168.1.0/24 │ 254      │ Home/small office network│
  │ 10.0.0.0/8     │ 16.7M    │ Large corporate network  │
  │ 172.16.0.0/12  │ 1M       │ Medium corporate network │
  └────────────────┴──────────┴──────────────────────────┘

  These three ranges are PRIVATE — they only exist inside
  your home/office network and are never routed on the internet.

  WHY THIS MATTERS FOR SECURITY:
  An attacker who gets inside a network runs a sweep like ours
  to find all live hosts before deciding which to attack.
  This is called NETWORK MAPPING or ENUMERATION.
  ══════════════════════════════════════════════════════
""")

def scan_my_network():
    """Helper to detect the user's likely local network range."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]
        s.close()
        # Guess /24 subnet
        parts = my_ip.rsplit('.', 1)
        subnet = parts[0] + '.0/24'
        print(f"\n  Your IP appears to be: {my_ip}")
        print(f"  Suggested range:       {subnet}")
        return subnet
    except Exception:
        return "192.168.1.0/24"

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   NETWORK HOST DISCOVERY             ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Sweep a network range           ║")
        print("║  [2] Detect my network & sweep it    ║")
        print("║  [3] CIDR notation explained         ║")
        print("║  [4] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            print("\n  Target formats:")
            print("  • 192.168.1.0/24    (CIDR — whole subnet)")
            print("  • 192.168.1.1-20    (range — specific IPs)")
            print("  • 192.168.1.1       (single IP)\n")
            target = input("  Enter target: ").strip()
            if not target:
                continue
            print("\n  Method:")
            print("  [1] ICMP Ping (standard, may be blocked by firewalls)")
            print("  [2] TCP Probe (connects to ports 22/80/443 — works even if ping blocked)")
            m = input("  Choose (default 1): ").strip()
            method = "tcp" if m == "2" else "ping"
            sweep_network(target, method)

        elif choice == "2":
            subnet = scan_my_network()
            confirm = input(f"\n  Sweep {subnet}? (y/n): ").strip().lower()
            if confirm == 'y':
                sweep_network(subnet, "ping")

        elif choice == "3":
            explain_cidr()

        elif choice == "4":
            print("\nGoodbye! Know your network. 🔐\n")
            break
        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

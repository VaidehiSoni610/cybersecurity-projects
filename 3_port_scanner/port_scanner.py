"""
Project 3: TCP Port Scanner
Concepts: networking, sockets, port states, common services
⚠ LEGAL NOTE: Only scan hosts you own or have explicit permission to scan.
"""

import socket
import concurrent.futures
import time
from datetime import datetime

# Common ports and their typical services
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}

def scan_port(host, port, timeout=1.0):
    """
    Attempt a TCP connection to host:port.
    Returns (port, is_open, service_name, banner).
    """
    service = COMMON_PORTS.get(port, "Unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                # Try to grab a banner
                banner = ""
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    raw = sock.recv(1024).decode(errors='ignore').strip()
                    banner = raw.split('\n')[0][:60] if raw else ""
                except Exception:
                    pass
                return (port, True, service, banner)
            return (port, False, service, "")
    except socket.gaierror:
        return (port, None, service, "DNS resolution failed")
    except Exception as e:
        return (port, False, service, str(e)[:40])

def resolve_host(host):
    """Resolve hostname to IP."""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        return None

def scan_host(host, ports, timeout=1.0, max_workers=50):
    """Scan a list of ports on the given host using threads."""
    ip = resolve_host(host)
    if not ip:
        print(f"\n❌ Could not resolve host: {host}")
        return []

    print(f"\n{'='*55}")
    print(f"  🔍 PORT SCANNER — Cybersecurity Learning Project")
    print(f"{'='*55}")
    print(f"  Target  : {host}")
    print(f"  IP      : {ip}")
    print(f"  Ports   : {len(ports)} ports")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Timeout : {timeout}s per port")
    print(f"{'='*55}\n")

    print(f"  {'PORT':<8} {'STATUS':<10} {'SERVICE':<14} BANNER")
    print(f"  {'-'*7} {'-'*9} {'-'*13} {'-'*30}")

    open_ports = []
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        results = []
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    # Sort by port number
    results.sort(key=lambda x: x[0])

    for port, is_open, service, banner in results:
        if is_open is True:
            status_icon = "🟢 OPEN"
            open_ports.append(port)
            print(f"  {port:<8} {status_icon:<10} {service:<14} {banner}")
        elif is_open is False and port in COMMON_PORTS:
            # Only show closed common ports if explicitly scanning them
            pass  # Suppress closed ports for cleaner output

    elapsed = time.time() - start

    print(f"\n{'='*55}")
    print(f"  ✅ Scan complete in {elapsed:.2f} seconds")
    print(f"  📂 Open ports found: {len(open_ports)}")
    if open_ports:
        print(f"  🔓 Open: {', '.join(map(str, open_ports))}")
    else:
        print("  🔒 No open ports found in scanned range.")
    print(f"{'='*55}\n")

    # Security notes
    if open_ports:
        print("⚡ Security Notes:")
        if 23 in open_ports:
            print("  ⚠ Port 23 (Telnet) is open — unencrypted! Use SSH instead.")
        if 21 in open_ports:
            print("  ⚠ Port 21 (FTP) is open — consider SFTP/FTPS.")
        if 3389 in open_ports:
            print("  ⚠ Port 3389 (RDP) exposed — restrict with firewall rules.")
        if 6379 in open_ports:
            print("  ⚠ Port 6379 (Redis) is open — should NOT be public-facing!")
        print()

    return open_ports

def main():
    print("\n╔══════════════════════════════════════╗")
    print("║   TCP PORT SCANNER                   ║")
    print("║   Cybersecurity Learning Project     ║")
    print("╠══════════════════════════════════════╣")
    print("║  ⚠ Only scan hosts you own or have   ║")
    print("║    explicit written permission for.  ║")
    print("╚══════════════════════════════════════╝\n")

    print("Scan options:")
    print("  [1] Scan common ports (top 17 services)")
    print("  [2] Scan a port range")
    print("  [3] Scan localhost (safe practice)\n")

    choice = input("Choose option: ").strip()

    if choice == '3':
        host = "127.0.0.1"
    else:
        host = input("Enter target hostname or IP: ").strip()
        if not host:
            print("No host entered. Exiting.")
            return

    if choice == '1' or choice == '3':
        ports = list(COMMON_PORTS.keys())
    elif choice == '2':
        try:
            start_port = int(input("Start port (e.g. 1): "))
            end_port   = int(input("End port   (e.g. 1024): "))
            if not (0 < start_port <= 65535 and 0 < end_port <= 65535):
                print("Ports must be between 1 and 65535.")
                return
            ports = list(range(start_port, end_port + 1))
        except ValueError:
            print("Invalid port numbers.")
            return
    else:
        ports = list(COMMON_PORTS.keys())

    scan_host(host, ports)

if __name__ == "__main__":
    main()

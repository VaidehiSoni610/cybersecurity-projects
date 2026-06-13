"""
Project 9: Subdomain Enumerator
Concepts: DNS, reconnaissance, footprinting, attack surface mapping

What you'll learn:
- How DNS (Domain Name System) works
- What subdomains are and why they matter to attackers
- How to enumerate subdomains using wordlists
- Why reducing your attack surface matters

⚠ Only enumerate domains you own or have explicit permission to test.
"""

import socket
import concurrent.futures
import time
from datetime import datetime

# Common subdomains attackers always check first
WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "portal", "vpn", "remote", "blog", "shop", "store", "login",
    "secure", "app", "mobile", "beta", "old", "new", "backup",
    "db", "database", "mysql", "sql", "oracle", "mongo",
    "smtp", "pop", "imap", "webmail", "email", "mx",
    "ns1", "ns2", "dns", "cdn", "static", "assets", "media",
    "img", "images", "upload", "uploads", "files", "docs",
    "support", "help", "status", "monitor", "dashboard",
    "jenkins", "jira", "gitlab", "github", "ci", "build",
    "internal", "intranet", "corp", "office", "hr", "finance",
    "git", "svn", "repo", "code", "dev1", "dev2", "stage",
    "uat", "qa", "prod", "production", "web", "web1", "web2",
    "server", "server1", "host", "cloud", "aws", "azure",
]

def resolve_subdomain(subdomain, domain, timeout=2):
    """
    Try to resolve a subdomain via DNS.
    Returns (subdomain, ip) if found, None if it doesn't exist.
    """
    full = f"{subdomain}.{domain}"
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(full)
        return (full, ip)
    except socket.gaierror:
        return None  # DNS lookup failed = subdomain doesn't exist
    except Exception:
        return None

def get_all_ips(domain):
    """Get all IP addresses for a domain (some have multiple)."""
    try:
        results = socket.getaddrinfo(domain, None)
        ips = list({r[4][0] for r in results})
        return ips
    except Exception:
        return []

def enumerate_subdomains(domain, wordlist=None, max_workers=50):
    """
    Main enumeration function.
    Tries each word in the wordlist as a subdomain and checks if it resolves.
    """
    words = wordlist or WORDLIST

    # Verify the base domain exists first
    try:
        base_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"\n❌ Cannot resolve base domain: {domain}")
        print("   Check the domain name and your internet connection.\n")
        return []

    print(f"\n{'='*58}")
    print(f"  🔍 SUBDOMAIN ENUMERATOR")
    print(f"{'='*58}")
    print(f"  Target   : {domain}")
    print(f"  Base IP  : {base_ip}")
    print(f"  Wordlist : {len(words)} subdomains to test")
    print(f"  Started  : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*58}\n")

    found = []
    start = time.time()
    tested = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(resolve_subdomain, word, domain): word
            for word in words
        }
        for future in concurrent.futures.as_completed(futures):
            tested += 1
            result = future.result()
            print(f"  Testing {tested}/{len(words)}...", end="\r")
            if result:
                full, ip = result
                found.append(result)
                print(f"  ✅ FOUND  {full:<40} {ip}")

    elapsed = time.time() - start

    print(f"\n{'='*58}")
    print(f"  ✅ Scan complete in {elapsed:.1f}s")
    print(f"  📂 Subdomains found: {len(found)} / {len(words)} tested")
    print(f"{'='*58}\n")

    if found:
        print("  🔒 Security Notes:")
        dangerous = ["admin", "db", "database", "internal", "intranet",
                     "jenkins", "gitlab", "staging", "dev", "backup"]
        for full, ip in found:
            subdomain = full.split('.')[0]
            if subdomain in dangerous:
                print(f"  ⚠️  {full} — sensitive subdomain exposed publicly!")
        print()

    return found

def explain_dns():
    """Educational explanation of how DNS works."""
    print("""
  📖 HOW DNS WORKS — Quick Explanation
  ══════════════════════════════════════════════════════
  DNS = Domain Name System — the internet's phone book.

  When you type "google.com" in a browser:
  1. Your computer asks a DNS resolver: "What's the IP for google.com?"
  2. The resolver checks its cache, then asks the root nameservers
  3. Eventually gets back: "google.com = 142.250.80.46"
  4. Your browser connects to that IP address

  Subdomains work the same way:
  - mail.google.com  → different IP → Gmail servers
  - drive.google.com → different IP → Drive servers
  - admin.google.com → might exist on a separate server

  WHY ATTACKERS ENUMERATE SUBDOMAINS:
  - Find forgotten/old servers still running outdated software
  - Discover admin panels accidentally left public
  - Find development servers with weaker security
  - Map the full attack surface before choosing a target

  This is called RECONNAISSANCE — the first step of any attack.
  ══════════════════════════════════════════════════════
""")

def lookup_single(domain):
    """Do a detailed DNS lookup on a single domain."""
    print(f"\n  🔎 DNS Lookup: {domain}")
    print(f"  {'─'*40}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"  IPv4 address  : {ip}")
    except socket.gaierror as e:
        print(f"  ❌ Could not resolve: {e}")
        return
    try:
        hostname, aliases, ips = socket.gethostbyaddr(ip)
        print(f"  Hostname      : {hostname}")
        if aliases:
            print(f"  Aliases       : {', '.join(aliases)}")
        if len(ips) > 1:
            print(f"  All IPs       : {', '.join(ips)}")
    except socket.herror:
        print(f"  Reverse DNS   : Not available")
    print()

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   SUBDOMAIN ENUMERATOR               ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Enumerate subdomains            ║")
        print("║  [2] Single DNS lookup               ║")
        print("║  [3] How DNS works (explanation)     ║")
        print("║  [4] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            print("\n  Safe domains to practice on:")
            print("  • scanme.nmap.org  (Nmap's public test server)")
            print("  • example.com      (IANA's example domain)\n")
            domain = input("  Enter domain (e.g. scanme.nmap.org): ").strip()
            if not domain:
                print("  No domain entered.")
                continue
            enumerate_subdomains(domain)

        elif choice == "2":
            domain = input("\n  Enter domain to look up: ").strip()
            if domain:
                lookup_single(domain)

        elif choice == "3":
            explain_dns()

        elif choice == "4":
            print("\nGoodbye! Map before you attack. 🔐\n")
            break
        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

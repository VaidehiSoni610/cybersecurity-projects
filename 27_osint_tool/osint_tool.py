"""
Project 27: OSINT Tool (Open Source Intelligence Gatherer)
Concepts: OSINT, passive reconnaissance, DNS enumeration, WHOIS,
          certificate transparency, Google dorking, attack surface mapping

What you'll learn:
- What OSINT is and why attackers spend most of their time here
- How to enumerate DNS records to map an organisation's infrastructure
- What certificate transparency logs reveal about subdomains
- How WHOIS exposes registrant details and organisation structure
- What Google dorking is and how to construct effective search queries
- The difference between passive recon (no target contact) and active recon

Builds on: Project 9 (subdomain enumeration), Project 10 (email headers),
           Project 12 (host discovery), Project 18 (DNS packets)
"""

import socket
import struct
import random
import re
import json
import urllib.request
import urllib.error
import urllib.parse
import time
from datetime import datetime

# ── DNS Query Engine ──────────────────────────────────────────────────────────

QTYPES = {'A': 1, 'AAAA': 28, 'MX': 15, 'NS': 2,
          'TXT': 16, 'SOA': 6, 'CNAME': 5}

def _build_dns_packet(domain, qtype_num):
    """Build a DNS query packet with EDNS0 (larger UDP buffer)."""
    txid = random.randint(1, 65535)
    # Encode domain in wire format
    question = b''
    for label in domain.split('.'):
        question += bytes([len(label)]) + label.encode()
    question += b'\x00' + struct.pack('>HH', qtype_num, 1)
    # EDNS0 OPT record — requests up to 4096-byte UDP responses
    edns = b'\x00' + struct.pack('>HIHH', 41, 4096, 0, 0)
    header = struct.pack('>HHHHHH', txid, 0x0100, 1, 0, 0, 1)
    return header + question + edns, txid


def _decode_name(data, offset):
    """
    Decode a DNS name from wire format, handling pointer compression.
    Returns (name_string, new_offset).
    """
    labels = []
    return_offset = -1

    while offset < len(data):
        length = data[offset]
        if length & 0xC0 == 0xC0:          # pointer
            if return_offset == -1:
                return_offset = offset + 2
            pointer = struct.unpack('>H', data[offset:offset+2])[0] & 0x3FFF
            offset  = pointer
            continue
        if length == 0:                     # end of name
            if return_offset == -1:
                return_offset = offset + 1
            break
        offset += 1
        labels.append(data[offset:offset+length].decode('utf-8', errors='replace'))
        offset += length

    return '.'.join(labels), (return_offset if return_offset != -1 else offset)


def _parse_dns_answers(data, ancount):
    """
    Extract human-readable strings from DNS answer records.
    Always decodes names from the FULL packet at their absolute offsets —
    this is essential for pointer compression to work correctly.
    """
    if ancount == 0 or len(data) < 12:
        return []

    # Skip the question section — find where answers start
    offset = 12
    while offset < len(data) and data[offset] != 0:
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
            break
        offset += data[offset] + 1
    else:
        if offset < len(data):
            offset += 1
    offset += 4  # skip QTYPE + QCLASS

    results = []
    for _ in range(min(ancount, 20)):
        if offset + 2 > len(data):
            break
        # Skip answer NAME field (may be pointer or inline name)
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 1   # skip null terminator

        if offset + 10 > len(data):
            break

        rtype, _, _, rdlength = struct.unpack('>HHIH', data[offset:offset+10])
        offset   += 10
        rdata_off = offset          # absolute offset of RDATA in the full packet
        rdata     = data[offset:offset+rdlength]
        offset   += rdlength

        try:
            if rtype == 1 and len(rdata) == 4:         # A — IPv4
                results.append(socket.inet_ntoa(rdata))

            elif rtype == 28 and len(rdata) == 16:     # AAAA — IPv6
                results.append(socket.inet_ntop(socket.AF_INET6, rdata))

            elif rtype in (2, 5):                       # NS, CNAME
                # Decode name from full packet at RDATA's absolute position
                name, _ = _decode_name(data, rdata_off)
                if name:
                    results.append(name)

            elif rtype == 15:                           # MX
                if len(rdata) >= 2:
                    pref = struct.unpack('>H', rdata[:2])[0]
                    name, _ = _decode_name(data, rdata_off + 2)
                    if name:
                        results.append(f"{name} (priority {pref})")

            elif rtype == 16:                           # TXT
                parts, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]; i += 1
                    parts.append(rdata[i:i+ln].decode('utf-8', errors='replace'))
                    i += ln
                results.append(' '.join(parts))

            elif rtype == 6:                            # SOA
                mname, pos = _decode_name(data, rdata_off)
                rname, _   = _decode_name(data, pos)
                results.append(f"primary={mname} admin={rname}")

        except Exception:
            continue

    return results


def dns_query(domain, rtype='A', server='8.8.8.8', timeout=3):
    """
    Send a DNS query and return human-readable answer strings.
    Uses EDNS0 for larger UDP payloads. Falls back to empty list on error.
    Note: TXT records on the root domain may be truncated (TC bit) due to
    UDP size limits — query specific subdomains like _dmarc.domain instead.
    """
    qtype_num = QTYPES.get(rtype.upper(), 1)
    pkt, txid = _build_dns_packet(domain, qtype_num)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(65535)
        s.close()
        ancount = struct.unpack('>H', data[6:8])[0]
        flags   = struct.unpack('>H', data[2:4])[0]
        truncated = bool((flags >> 9) & 1)
        if truncated:
            return [], True   # TC bit set — response truncated
        return _parse_dns_answers(data, ancount), False
    except Exception:
        return [], False


# ── DNS Record Enumeration ────────────────────────────────────────────────────

def enumerate_dns_records(domain):
    """
    Query all major DNS record types for a target domain.
    Builds a map of the organisation's DNS infrastructure.
    """
    print(f"\n  🔍 DNS Record Enumeration: {domain}")
    print(f"  {'─'*52}")

    findings = {}
    notes    = {}

    # Standard record types
    for rtype in ['A', 'AAAA', 'NS', 'MX', 'SOA']:
        results, truncated = dns_query(domain, rtype)
        findings[rtype] = results
        if results:
            print(f"\n  {rtype} records ({len(results)}):")
            for r in results[:8]:
                print(f"    • {r}")
        else:
            print(f"  {rtype:<6} — none found")

    # TXT records: query domain root + common TXT subdomains
    txt_all = []
    txt_subdomains = [
        domain,
        f"_dmarc.{domain}",
        f"_domainkey.{domain}",
        f"default._domainkey.{domain}",
    ]
    for subdomain in txt_subdomains:
        results, truncated = dns_query(subdomain, 'TXT')
        for r in results:
            label = f"[{subdomain}]" if subdomain != domain else ""
            txt_all.append(f"{r} {label}".strip())
        if truncated and subdomain == domain:
            notes['txt_truncated'] = True

    findings['TXT'] = txt_all
    if txt_all:
        print(f"\n  TXT records ({len(txt_all)}):")
        for r in txt_all[:6]:
            print(f"    • {r[:80]}")
    else:
        msg = " (response too large for UDP — use dig on your machine)" \
              if notes.get('txt_truncated') else ""
        print(f"  TXT   — none found{msg}")

    # Analyse TXT for security-relevant records
    spf   = [r for r in txt_all if 'v=spf1'     in r.lower()]
    dmarc = [r for r in txt_all if 'v=dmarc1'   in r.lower()]
    dkim  = [r for r in txt_all if 'v=dkim1'    in r.lower()]
    if spf or dmarc or dkim:
        print(f"\n  📧 Email Security Records:")
        if spf:   print(f"    ✅ SPF found   — controls who can send email for this domain")
        if dmarc: print(f"    ✅ DMARC found — policy for handling SPF/DKIM failures")
        if dkim:  print(f"    ✅ DKIM found  — cryptographic email signing in use")
    else:
        txt_searched = bool(txt_all) or notes.get('txt_truncated')
        if not txt_searched:
            print(f"\n  ⚠️  No SPF/DMARC found — domain may be vulnerable to email spoofing")

    return findings


# ── WHOIS Lookup ──────────────────────────────────────────────────────────────

WHOIS_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'io':  'whois.iana.org',
    'co':  'whois.iana.org',
    'uk':  'whois.nic.uk',
    'de':  'whois.denic.de',
    'ca':  'whois.cira.ca',
}

def whois_lookup(domain):
    """
    Perform a WHOIS lookup via direct TCP connection to port 43.
    WHOIS is one of the oldest internet protocols — a simple text exchange.
    The response contains registrant info, creation date, nameservers.
    """
    tld    = domain.rsplit('.', 1)[-1].lower()
    server = WHOIS_SERVERS.get(tld, 'whois.iana.org')
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(6)
        s.connect((server, 43))
        s.sendall(f"{domain}\r\n".encode())
        resp = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        return resp.decode('utf-8', errors='replace')
    except Exception as e:
        return f"[WHOIS lookup failed: {e}]"


def parse_whois(raw):
    """Extract security-relevant fields from a WHOIS response."""
    fields = {
        'Registrar':        None,
        'Registrant Org':   None,
        'Registrant Email': None,
        'Created':          None,
        'Expires':          None,
        'Name Servers':     [],
        'Status':           [],
        'Privacy':          False,
    }
    patterns = {
        'Registrar':        r'Registrar:\s*(.+)',
        'Registrant Org':   r'Registrant Organization:\s*(.+)',
        'Registrant Email': r'Registrant Email:\s*(.+)',
        'Created':          r'Creation Date:\s*([^\r\n]+)',
        'Expires':          r'(?:Registry Expiry Date|Registrar Registration Expiration Date):\s*([^\r\n]+)',
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            fields[key] = m.group(1).strip()

    fields['Name Servers'] = list(set(re.findall(r'Name Server:\s*(\S+)', raw, re.IGNORECASE)))
    fields['Status']       = re.findall(r'Domain Status:\s*([^\r\n]+)', raw, re.IGNORECASE)[:3]

    # Detect WHOIS privacy protection
    email = fields.get('Registrant Email') or ''
    org   = fields.get('Registrant Org')   or ''
    if any(kw in (email + org).lower()
           for kw in ['privacy', 'redacted', 'whoisguard', 'domains by proxy']):
        fields['Privacy'] = True

    return fields


def display_whois(domain, fields):
    print(f"\n  📋 WHOIS: {domain}")
    print(f"  {'─'*52}")

    if fields.get('Privacy'):
        print(f"  🔒 WHOIS privacy protection is active — registrant details hidden")

    for key in ['Registrar', 'Registrant Org', 'Registrant Email', 'Created', 'Expires']:
        val = fields.get(key)
        if val:
            print(f"  {key:<22}: {val[:60]}")
        else:
            print(f"  {key:<22}: Not disclosed")

    ns = fields.get('Name Servers', [])
    if ns:
        print(f"\n  Name Servers ({len(ns)}):")
        for n in sorted(ns)[:4]:
            print(f"    • {n.lower()}")

    status = fields.get('Status', [])
    if status:
        print(f"\n  Status:")
        for s in status[:2]:
            print(f"    • {s.strip()}")


# ── Certificate Transparency ──────────────────────────────────────────────────

def query_cert_transparency(domain):
    """
    Query crt.sh — a public index of all certificate transparency logs.
    Every SSL cert ever issued is logged here. This reveals subdomains
    even if they're not in public DNS — and it's 100% passive.
    """
    url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': 'Mozilla/5.0 (OSINT/Educational)'}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        subdomains = set()
        for entry in data:
            for name in entry.get('name_value', '').split('\n'):
                name = name.strip().lstrip('*.')
                if name.endswith(f'.{domain}') or name == domain:
                    subdomains.add(name.lower())

        return sorted(subdomains)
    except urllib.error.HTTPError as e:
        return None   # crt.sh blocked (e.g. in sandbox)
    except Exception:
        return None


# ── Email Pattern Analysis ────────────────────────────────────────────────────

def derive_email_patterns(domain, whois_raw=''):
    """
    Infer corporate email address formats from WHOIS and domain info.
    Social engineers use these patterns to target specific employees.
    """
    patterns = [
        f"firstname.lastname@{domain}",
        f"f.lastname@{domain}",
        f"firstname@{domain}",
        f"flastname@{domain}",
        f"firstname_lastname@{domain}",
    ]
    # Extract real emails visible in WHOIS (often redacted but sometimes not)
    real_emails = list(set(re.findall(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        whois_raw
    )))
    # Filter out placeholder emails from registrars — check local part only
    real_emails = [e for e in real_emails
                   if not any(kw in e.split('@')[0].lower()
                              for kw in ['abuse', 'noreply', 'no-reply',
                                         'registrar', 'privacy', 'proxy',
                                         'hostmaster', 'postmaster'])]
    return patterns, real_emails


# ── Google Dork Builder ───────────────────────────────────────────────────────

def build_google_dorks(domain):
    """
    Generate Google advanced search queries for a target domain.
    Google dorking uses search operators to find sensitive content that
    web servers accidentally exposed to search engine indexing.
    100% passive — only touches Google's servers, never the target.
    """
    return [
        (f'site:{domain} filetype:pdf',
         "PDFs — may contain internal documents, org charts, project plans"),
        (f'site:{domain} filetype:xlsx OR filetype:csv',
         "Spreadsheets — often contain customer data, financials, credentials"),
        (f'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard',
         "Admin panels and authentication pages"),
        (f'site:{domain} inurl:config OR inurl:.env OR inurl:backup',
         "Configuration files accidentally indexed by search engines"),
        (f'site:{domain} ext:log OR ext:bak OR ext:old OR ext:sql',
         "Backup and log files — often contain sensitive data"),
        (f'site:{domain} "index of" OR "directory listing"',
         "Open directory listings exposing server file structure"),
        (f'site:{domain} intext:password OR intext:"api key" OR intext:token',
         "Pages containing credentials or API tokens in their content"),
        (f'"@{domain}" site:linkedin.com',
         "Employee profiles — reveals names, titles, and email format"),
        (f'site:pastebin.com "{domain}"',
         "Paste sites — may contain leaked credentials or internal data"),
        (f'site:github.com "{domain}" password OR secret OR api_key',
         "GitHub — developers sometimes accidentally commit credentials"),
    ]


# ── IP Geolocation ────────────────────────────────────────────────────────────

def ip_geolocate(ip):
    """
    Query ipinfo.io for geolocation and hosting provider information.
    Reveals: country, city, ISP, cloud provider, ASN.
    """
    url = f"https://ipinfo.io/{ip}/json"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data
    except Exception:
        return {}


# ── Full OSINT Report ──────────────────────────────────────────────────────────

def run_osint(domain):
    """Orchestrate all OSINT modules and produce a structured report."""
    print(f"\n{'='*62}")
    print(f"  🕵️  OSINT TOOL — Passive Reconnaissance")
    print(f"{'='*62}")
    print(f"  Target  : {domain}")
    print(f"  Started : {datetime.now().strftime('%H:%M:%S')}")
    print(f"  Method  : Passive only — no direct target contact")
    print(f"{'='*62}")

    report = {'domain': domain, 'timestamp': datetime.now().isoformat()}

    # ── 1. DNS records ──────────────────────────────────────────────────
    print("\n  [1/5] DNS Records...")
    dns = enumerate_dns_records(domain)
    report['dns'] = {k: v for k, v in dns.items()}

    # Geolocate primary A record
    a_ips = dns.get('A', [])
    if a_ips:
        print(f"\n  🌐 Geolocating {a_ips[0]}...")
        geo = ip_geolocate(a_ips[0])
        if geo and geo.get('city'):
            print(f"    Location : {geo.get('city')}, {geo.get('region')}, {geo.get('country')}")
            print(f"    Hosting  : {geo.get('org', 'Unknown')}")
            report['geolocation'] = geo

    # ── 2. WHOIS ────────────────────────────────────────────────────────
    print(f"\n  [2/5] WHOIS Lookup...")
    whois_raw    = whois_lookup(domain)
    whois_fields = parse_whois(whois_raw)
    display_whois(domain, whois_fields)
    report['whois'] = whois_fields

    # ── 3. Certificate transparency ─────────────────────────────────────
    print(f"\n  [3/5] Certificate Transparency Logs (crt.sh)...")
    ct_subs = query_cert_transparency(domain)
    if ct_subs is None:
        print(f"  ⚠️  crt.sh not reachable in this environment.")
        print(f"      On your Mac, this will show all subdomains ever issued a cert.")
        ct_subs = []
    elif ct_subs:
        print(f"  Found {len(ct_subs)} subdomain(s) in CT logs:")
        for s in ct_subs[:12]:
            print(f"    • {s}")
        if len(ct_subs) > 12:
            print(f"    ... and {len(ct_subs)-12} more")
    else:
        print(f"  No subdomains found in CT logs.")
    report['ct_subdomains'] = ct_subs

    # ── 4. Email patterns ────────────────────────────────────────────────
    print(f"\n  [4/5] Email Pattern Analysis...")
    patterns, real_emails = derive_email_patterns(domain, whois_raw)
    print(f"  Likely email formats:")
    for p in patterns:
        print(f"    • {p}")
    if real_emails:
        print(f"\n  Emails found in WHOIS:")
        for e in real_emails[:5]:
            print(f"    • {e}")
    report['email_patterns'] = patterns

    # ── 5. Google dorks ─────────────────────────────────────────────────
    print(f"\n  [5/5] Google Dork Queries (paste into Google)...")
    dorks = build_google_dorks(domain)
    for dork, desc in dorks[:3]:
        print(f"\n  {dork}")
        print(f"  → {desc}")
    print(f"\n  (option [4] shows all {len(dorks)} dork queries)")
    report['dorks'] = dorks

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*62}")
    print(f"  📊 OSINT SUMMARY — {domain}")
    print(f"{'='*62}")
    print(f"  A records     : {len(dns.get('A', []))} IP address(es)")
    print(f"  Mail servers  : {len(dns.get('MX', []))} MX record(s)")
    print(f"  Name servers  : {len(dns.get('NS', []))} NS record(s)")
    print(f"  TXT records   : {len(dns.get('TXT', []))} (SPF/DKIM/DMARC)")
    print(f"  CT subdomains : {len(ct_subs)} discovered")
    print(f"  Registrar     : {(whois_fields.get('Registrar') or 'Unknown')[:40]}")
    print(f"  Domain age    : {whois_fields.get('Created', 'Unknown')[:20]}")
    print(f"  Dork queries  : {len(dorks)} ready")
    print(f"{'='*62}\n")

    return report


# ── Explainer ─────────────────────────────────────────────────────────────────

def explain_osint():
    print("""
  📖 OSINT — Open Source Intelligence
  ══════════════════════════════════════════════════════

  WHAT IS OSINT?
  Open Source Intelligence is collecting information from publicly
  available sources — search engines, DNS, WHOIS, certificate logs,
  social media, job postings, and more.

  Attackers spend 70–80% of their time in reconnaissance.
  Most of that is PASSIVE OSINT — they never touch the target
  directly, so there's no log, no alert, no trace.

  PASSIVE vs ACTIVE RECON:
  ┌──────────────────────────────────────────────────────┐
  │ PASSIVE (what this tool does)                        │
  │  Queries third-party services — DNS, crt.sh, WHOIS  │
  │  The target's servers never see your requests        │
  │  Completely undetectable by the target               │
  │  Examples: WHOIS, Google, Shodan, LinkedIn, CT logs  │
  ├──────────────────────────────────────────────────────┤
  │ ACTIVE (Projects 3, 9, 17, 24)                       │
  │  Directly contacts the target's systems              │
  │  Leaves server logs — may trigger IDS alerts         │
  │  Examples: port scan, directory bruteforce, fuzzing  │
  └──────────────────────────────────────────────────────┘

  CERTIFICATE TRANSPARENCY LOGS:
  Every CA must log issued certs to public CT logs (RFC 6962).
  This means every subdomain that ever had HTTPS is permanently
  discoverable — attackers find forgotten dev/staging servers this way.
  crt.sh indexes ALL CT logs and is free to query.

  GOOGLE DORKING — ADVANCED SEARCH FOR OSINT:
    site:company.com filetype:pdf        → internal PDFs
    site:company.com inurl:admin         → admin panels
    site:company.com ext:sql             → database dumps!
    "company.com" site:pastebin.com      → leaked credentials

  WHAT DNS RECORDS REVEAL:
  • A/AAAA  → server IPs → hosting provider, cloud region
  • MX      → email provider (Gmail? Exchange? Self-hosted?)
  • NS      → DNS provider (AWS Route53? Cloudflare?)
  • TXT     → SPF (who can send email), DKIM keys, domain verification
  • SOA     → primary nameserver + admin contact email

  WHY SPF/DMARC MATTER IN OSINT:
  If a domain has no SPF → attacker can send email spoofed as that domain.
  If DMARC is missing → even with SPF, no enforcement policy exists.
  These are easy wins for phishing campaigns.

  DEFENDERS DO OSINT ON THEMSELVES:
  • Run these queries on your own domain first
  • Remove sensitive files accidentally indexed by Google
  • Enable WHOIS privacy to hide registrant email
  • Monitor CT logs for unexpected certificates
  • Search LinkedIn to know what info employees expose
  ══════════════════════════════════════════════════════
""")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   OSINT TOOL                         ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Full OSINT scan on a domain     ║")
        print("║  [2] DNS record enumeration only     ║")
        print("║  [3] WHOIS lookup only               ║")
        print("║  [4] Google dork query builder       ║")
        print("║  [5] Certificate transparency lookup ║")
        print("║  [6] How OSINT works (explained)     ║")
        print("║  [7] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            domain = input("\n  Target domain (e.g. github.com): ").strip().lower()
            if not domain:
                print("  ❌ No domain entered.")
                continue
            run_osint(domain)

        elif choice == "2":
            domain = input("\n  Domain: ").strip().lower()
            if domain:
                enumerate_dns_records(domain)

        elif choice == "3":
            domain = input("\n  Domain: ").strip().lower()
            if not domain:
                continue
            print(f"\n  Querying WHOIS for {domain}...")
            raw    = whois_lookup(domain)
            fields = parse_whois(raw)
            display_whois(domain, fields)

        elif choice == "4":
            domain = input("\n  Domain: ").strip().lower()
            if not domain:
                continue
            dorks = build_google_dorks(domain)
            print(f"\n  📋 Google Dork Queries for {domain}")
            print(f"  Copy and paste each one directly into Google:\n")
            for i, (dork, desc) in enumerate(dorks, 1):
                print(f"  [{i:>2}] {dork}")
                print(f"       → {desc}\n")

        elif choice == "5":
            domain = input("\n  Domain: ").strip().lower()
            if not domain:
                continue
            print(f"\n  Querying crt.sh for *.{domain}...")
            subs = query_cert_transparency(domain)
            if subs is None:
                print("  ⚠️  crt.sh not reachable — try on your Mac directly.")
            elif subs:
                print(f"\n  {len(subs)} subdomain(s) found in certificate logs:")
                for s in subs:
                    print(f"    • {s}")
            else:
                print("  No subdomains found in CT logs.")
            print()

        elif choice == "6":
            explain_osint()

        elif choice == "7":
            print("\nGoodbye! Know what's public about you. 🔐\n")
            break

        else:
            print("\n❌ Invalid option.\n")


if __name__ == "__main__":
    main()

"""
Project 16: SSL Certificate Checker
Concepts: SSL/TLS, digital certificates, PKI, certificate chains,
          expiry monitoring, cipher suites, HTTPS security

What you'll learn:
- How HTTPS works and what an SSL/TLS certificate actually contains
- What PKI (Public Key Infrastructure) is and who issues certificates
- How to detect expired, self-signed, or misconfigured certificates
- What cipher suites are and why weak ones are dangerous
- How certificate pinning, SNI, and certificate transparency work
"""

import ssl
import socket
import json
from datetime import datetime, timezone

# ── Certificate Fetching ──────────────────────────────────────────────────────

def fetch_certificate(hostname, port=443, timeout=5):
    """
    Connect to a host over TLS and retrieve its certificate.
    Uses Python's built-in ssl module — no external libraries needed.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert      = tls_sock.getpeercert()
                cipher    = tls_sock.cipher()
                tls_ver   = tls_sock.version()
                return cert, cipher, tls_ver, None
    except ssl.SSLCertVerificationError as e:
        # Certificate is invalid — still try to grab it for analysis
        context_noverify = ssl.create_default_context()
        context_noverify.check_hostname = False
        context_noverify.verify_mode    = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context_noverify.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert    = tls_sock.getpeercert(binary_form=False)
                    cipher  = tls_sock.cipher()
                    tls_ver = tls_sock.version()
                    return cert, cipher, tls_ver, str(e)
        except Exception as inner_e:
            return None, None, None, str(inner_e)
    except socket.timeout:
        return None, None, None, f"Connection timed out after {timeout}s"
    except ConnectionRefusedError:
        return None, None, None, f"Connection refused on port {port}"
    except socket.gaierror:
        return None, None, None, f"DNS resolution failed for '{hostname}'"
    except Exception as e:
        return None, None, None, str(e)

# ── Certificate Parsing ───────────────────────────────────────────────────────

def parse_subject(cert):
    """Extract subject fields (who the cert belongs to) into a dict."""
    result = {}
    for field_list in cert.get('subject', []):
        for key, value in field_list:
            result[key] = value
    return result

def parse_issuer(cert):
    """Extract issuer fields (who signed the cert) into a dict."""
    result = {}
    for field_list in cert.get('issuer', []):
        for key, value in field_list:
            result[key] = value
    return result

def parse_expiry(cert):
    """
    Parse the certificate's notBefore and notAfter fields into datetime objects.
    Certificates use a specific string format: '%b %d %H:%M:%S %Y %Z'
    """
    fmt = '%b %d %H:%M:%S %Y %Z'
    try:
        not_before = datetime.strptime(cert['notBefore'], fmt).replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(cert['notAfter'],  fmt).replace(tzinfo=timezone.utc)
        return not_before, not_after
    except Exception:
        return None, None

def get_san(cert):
    """
    Extract Subject Alternative Names — the list of domains/IPs this cert is valid for.
    Modern certs use SANs rather than just the CN (Common Name).
    """
    sans = []
    for entry in cert.get('subjectAltName', []):
        sans.append(f"{entry[0]}: {entry[1]}")
    return sans

def is_self_signed(cert):
    """A cert is self-signed if the subject and issuer are identical."""
    return parse_subject(cert) == parse_issuer(cert)

# ── Security Grading ──────────────────────────────────────────────────────────

WEAK_CIPHERS = [
    'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT',
    'RC2', 'IDEA', 'ANON', 'ADH', 'AECDH'
]

def grade_cipher(cipher_name):
    """Flag cipher suites known to be weak or broken."""
    if not cipher_name:
        return "⚠️  Unknown"
    cipher_upper = cipher_name.upper()
    for weak in WEAK_CIPHERS:
        if weak in cipher_upper:
            return f"❌ WEAK ({weak} detected)"
    if 'ECDHE' in cipher_upper or 'DHE' in cipher_upper:
        return "✅ Strong (forward secrecy enabled)"
    return "🟡 Acceptable"

def grade_tls_version(version):
    """Score the TLS protocol version."""
    grades = {
        'TLSv1.3': "✅ TLS 1.3 — Current best",
        'TLSv1.2': "🟡 TLS 1.2 — Acceptable, consider upgrading",
        'TLSv1.1': "❌ TLS 1.1 — Deprecated, upgrade required",
        'TLSv1':   "❌ TLS 1.0 — Deprecated, upgrade required",
        'SSLv3':   "🚨 SSL 3.0 — Critically broken (POODLE attack)",
        'SSLv2':   "🚨 SSL 2.0 — Critically broken",
    }
    return grades.get(version, f"⚠️  Unknown version: {version}")

# ── Full Analysis & Report ────────────────────────────────────────────────────

def analyse_host(hostname, port=443):
    """Run a full SSL/TLS analysis and print a formatted report."""
    print(f"\n{'='*60}")
    print(f"  🔒 SSL CERTIFICATE CHECKER")
    print(f"{'='*60}")
    print(f"  Target  : {hostname}:{port}")
    print(f"  Checked : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    print("  Connecting...", end="\r")
    cert, cipher_info, tls_version, error = fetch_certificate(hostname, port)

    if cert is None:
        print(f"  ❌ Could not retrieve certificate.")
        print(f"  Error: {error}\n")
        return

    # ── Certificate Identity ────────────────────────────────
    subject = parse_subject(cert)
    issuer  = parse_issuer(cert)
    sans    = get_san(cert)
    self_signed = is_self_signed(cert)

    print(f"  📋 Certificate Identity")
    print(f"  {'─'*50}")
    print(f"  Common Name  : {subject.get('commonName', 'N/A')}")
    print(f"  Organisation : {subject.get('organizationName', 'N/A')}")
    print(f"  Country      : {subject.get('countryName', 'N/A')}")
    print(f"  Issued By    : {issuer.get('organizationName', 'N/A')}")
    print(f"  Issuer CN    : {issuer.get('commonName', 'N/A')}")

    if self_signed:
        print(f"\n  ⚠️  SELF-SIGNED CERTIFICATE — not trusted by browsers!")
    else:
        print(f"\n  ✅ Certificate signed by a trusted CA")

    if sans:
        print(f"\n  🌐 Valid for {len(sans)} domain(s) / SANs:")
        for san in sans[:8]:
            print(f"     • {san}")
        if len(sans) > 8:
            print(f"     ... and {len(sans) - 8} more")

    # ── Validity Period ─────────────────────────────────────
    not_before, not_after = parse_expiry(cert)
    now = datetime.now(timezone.utc)

    print(f"\n  📅 Validity Period")
    print(f"  {'─'*50}")

    if not_before and not_after:
        days_remaining = (not_after - now).days
        total_days     = (not_after - not_before).days

        print(f"  Valid From  : {not_before.strftime('%Y-%m-%d')}")
        print(f"  Valid Until : {not_after.strftime('%Y-%m-%d')}")

        if now < not_before:
            print(f"  Status      : ⚠️  NOT YET VALID (starts in {(not_before - now).days} days)")
        elif now > not_after:
            expired_days = (now - not_after).days
            print(f"  Status      : 🚨 EXPIRED {expired_days} day(s) ago!")
        elif days_remaining <= 14:
            print(f"  Status      : 🔴 CRITICAL — expires in {days_remaining} day(s)!")
        elif days_remaining <= 30:
            print(f"  Status      : 🟠 WARNING — expires in {days_remaining} day(s)")
        elif days_remaining <= 90:
            print(f"  Status      : 🟡 NOTICE — expires in {days_remaining} day(s)")
        else:
            print(f"  Status      : ✅ Valid — {days_remaining} day(s) remaining")

        print(f"  Duration    : {total_days} day(s) total validity")

    # ── TLS Connection Details ──────────────────────────────
    print(f"\n  🔐 TLS Connection")
    print(f"  {'─'*50}")

    if tls_version:
        print(f"  Protocol  : {tls_version}")
        print(f"  Rating    : {grade_tls_version(tls_version)}")

    if cipher_info:
        cipher_name, tls_proto, key_bits = cipher_info
        print(f"  Cipher    : {cipher_name}")
        print(f"  Key bits  : {key_bits}")
        print(f"  Rating    : {grade_cipher(cipher_name)}")

    # ── Security Alerts ─────────────────────────────────────
    alerts = []
    if error:
        alerts.append(f"🚨 Verification error: {error}")
    if self_signed:
        alerts.append("⚠️  Self-signed — not trusted by browsers/clients")
    if not_after and now > not_after:
        alerts.append("🚨 Certificate is EXPIRED")
    if not_after and 0 < (not_after - now).days <= 30:
        alerts.append(f"🟠 Certificate expires in {(not_after - now).days} days — renew soon")
    if cipher_info:
        grade = grade_cipher(cipher_info[0])
        if "WEAK" in grade or "❌" in grade:
            alerts.append(f"❌ Weak cipher suite in use: {cipher_info[0]}")
    if tls_version in ('TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3'):
        alerts.append(f"❌ Deprecated TLS version: {tls_version}")

    print(f"\n  {'='*58}")
    if alerts:
        print(f"  🚨 Security Alerts ({len(alerts)} found):")
        for alert in alerts:
            print(f"  {alert}")
    else:
        print(f"  ✅ No security issues detected — certificate looks healthy!")
    print(f"  {'='*58}\n")

# ── Bulk Checker ──────────────────────────────────────────────────────────────

def bulk_check(domains):
    """Check multiple domains and print a summary table."""
    print(f"\n  📋 Bulk Certificate Check — {len(domains)} domain(s)")
    print(f"  {'─'*60}")
    print(f"  {'Domain':<30} {'Expires':<15} {'Days Left':<12} Status")
    print(f"  {'─'*60}")

    now = datetime.now(timezone.utc)
    for domain in domains:
        cert, _, _, error = fetch_certificate(domain.strip())
        if cert is None:
            print(f"  {domain:<30} {'—':<15} {'—':<12} ❌ {error or 'Failed'}")
            continue
        _, not_after = parse_expiry(cert)
        if not_after:
            days = (not_after - now).days
            exp  = not_after.strftime('%Y-%m-%d')
            if days < 0:
                icon = "🚨 EXPIRED"
            elif days <= 14:
                icon = "🔴 CRITICAL"
            elif days <= 30:
                icon = "🟠 WARNING"
            elif days <= 90:
                icon = "🟡 NOTICE"
            else:
                icon = "✅ OK"
            print(f"  {domain:<30} {exp:<15} {str(days)+'d':<12} {icon}")
        else:
            print(f"  {domain:<30} {'Unknown':<15} {'—':<12} ⚠️  Parse error")
    print()

# ── Educational Explainer ─────────────────────────────────────────────────────

def explain_ssl_tls():
    print("""
  📖 HOW SSL / TLS CERTIFICATES WORK
  ══════════════════════════════════════════════════════

  WHAT IS A CERTIFICATE?
  A digital certificate is an identity document for a website.
  It proves: "This server really is google.com (not an impostor)"
  It's issued by a trusted third party called a CA (Certificate Authority).

  THE TLS HANDSHAKE (how HTTPS starts):
  1. Client: "Hello, I support these cipher suites and TLS versions"
  2. Server: "Here's my certificate (my identity)"
  3. Client: "I'll check your certificate with my trusted CA list"
  4. Client: "OK, I trust you. Let's agree on an encryption key"
  5. Both: Use that key to encrypt ALL further communication

  WHAT'S IN A CERTIFICATE:
  ┌──────────────────────────────────────────────────────┐
  │ Subject      → who the cert belongs to (the website) │
  │ Issuer       → the CA that signed it (e.g. DigiCert) │
  │ Valid From   → when the cert became valid             │
  │ Valid Until  → when it expires (usually 1 year)      │
  │ Public Key   → used to establish the encrypted link  │
  │ SANs         → all domain names this cert covers     │
  │ Signature    → CA's cryptographic proof of validity  │
  └──────────────────────────────────────────────────────┘

  WHAT IS PKI?
  Public Key Infrastructure — the whole system of CAs, certificates,
  and trust that makes HTTPS work. Your browser ships with ~100 trusted
  root CAs. If a cert is signed by one of them (or their delegates),
  your browser shows the padlock. Otherwise — red warning page.

  WHAT IS FORWARD SECRECY?
  Cipher suites with ECDHE/DHE generate a fresh encryption key for
  every session. Even if an attacker records all your traffic today
  and later steals the server's private key — past sessions can't
  be decrypted. Without forward secrecy, they could.

  COMMON CERTIFICATE PROBLEMS:
  ❌ Expired       → cert not renewed in time (common mistake)
  ❌ Self-signed   → no CA validated it — browsers won't trust it
  ❌ Wrong domain  → cert says example.com but you're on api.example.com
  ❌ Weak cipher   → using broken algorithms (RC4, MD5, DES)
  ❌ Old TLS       → TLS 1.0/1.1 deprecated, vulnerable to attacks
  ══════════════════════════════════════════════════════
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   SSL CERTIFICATE CHECKER            ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Check a single domain           ║")
        print("║  [2] Bulk check multiple domains     ║")
        print("║  [3] How SSL/TLS works (explanation) ║")
        print("║  [4] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            host = input("\n  Domain to check (e.g. github.com): ").strip()
            if not host:
                print("  ❌ No domain entered.")
                continue
            port_input = input("  Port (default 443): ").strip()
            port = int(port_input) if port_input.isdigit() else 443
            analyse_host(host, port)

        elif choice == "2":
            print("\n  Enter domains one per line.")
            print("  Type 'done' when finished:\n")
            domains = []
            while True:
                d = input("  Domain: ").strip()
                if d.lower() == 'done' or not d:
                    break
                domains.append(d)
            if domains:
                bulk_check(domains)

        elif choice == "3":
            explain_ssl_tls()

        elif choice == "4":
            print("\nGoodbye! Always check before you connect. 🔐\n")
            break

        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

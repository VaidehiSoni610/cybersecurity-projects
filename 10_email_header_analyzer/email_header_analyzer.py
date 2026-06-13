"""
Project 10: Email Header Analyzer
Concepts: email security, phishing detection, SMTP, SPF, DKIM, email spoofing

What you'll learn:
- How email actually travels across the internet (it's not direct!)
- What email headers contain and how to read them
- How attackers spoof "From" addresses to fake being someone else
- What SPF and DKIM records are and why they exist
- How to spot phishing emails by analyzing headers
"""

import re
from datetime import datetime

# ── Sample email headers for practice ────────────────────────────────────────
# These simulate a phishing email pretending to be from a bank

SAMPLE_PHISHING_HEADERS = """From: security@your-bank.com
To: victim@gmail.com
Subject: URGENT: Your account has been suspended
Date: Mon, 15 Jan 2024 03:22:11 +0000
Message-ID: <abc123@mail.suspicious-domain.ru>
X-Originating-IP: 185.220.101.45
X-Mailer: PHPMailer 5.2.0
Received: from mail.suspicious-domain.ru (185.220.101.45)
        by mx.gmail.com with SMTP id abc123
        for <victim@gmail.com>;
        Mon, 15 Jan 2024 03:22:15 +0000
Received: from localhost (localhost [127.0.0.1])
        by mail.suspicious-domain.ru with ESMTP
        Mon, 15 Jan 2024 03:22:10 +0000
Authentication-Results: mx.gmail.com;
        dkim=fail (signature verification failed);
        spf=fail (domain does not designate 185.220.101.45 as permitted sender)
Return-Path: <bounce@suspicious-domain.ru>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
"""

SAMPLE_LEGIT_HEADERS = """From: no-reply@google.com
To: user@gmail.com
Subject: Security alert for your Google Account
Date: Mon, 15 Jan 2024 10:05:33 +0000
Message-ID: <xyz789@accounts.google.com>
X-Originating-IP: 209.85.220.41
Received: from mail-sor-f41.google.com (209.85.220.41)
        by mx.gmail.com with SMTPS id abc456
        for <user@gmail.com>;
        Mon, 15 Jan 2024 10:05:35 +0000
Authentication-Results: mx.gmail.com;
        dkim=pass header.i=@google.com;
        spf=pass (google.com: domain designates 209.85.220.41 as permitted sender)
Return-Path: <3abc@accounts.google.com>
MIME-Version: 1.0
Content-Type: text/html
"""

# ── Header Parser ─────────────────────────────────────────────────────────────

def parse_headers(raw_headers):
    """
    Parse raw email headers into a structured dictionary.
    Email headers use the format: Key: Value
    Multi-line values are indented with whitespace.
    """
    headers = {}
    received = []
    current_key = None

    for line in raw_headers.strip().split('\n'):
        if line.startswith((' ', '\t')) and current_key:
            # Continuation of previous header
            headers[current_key] = headers.get(current_key, '') + ' ' + line.strip()
        elif ':' in line:
            key, _, value = line.partition(':')
            key   = key.strip()
            value = value.strip()
            current_key = key
            if key.lower() == 'received':
                received.append(value)
            else:
                headers[key] = value

    headers['_received'] = received
    return headers

def extract_email_address(field):
    """Pull just the email address from a field like 'John Doe <john@example.com>'"""
    match = re.search(r'<([^>]+)>', field)
    if match:
        return match.group(1)
    match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', field)
    return match.group(0) if match else field

def extract_ip(text):
    """Find an IP address in a string."""
    match = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text)
    return match.group(1) if match else None

def is_private_ip(ip):
    """Check if an IP is private/internal (not routable on the internet)."""
    if not ip:
        return False
    parts = list(map(int, ip.split('.')))
    return (parts[0] == 10 or
            (parts[0] == 172 and 16 <= parts[1] <= 31) or
            (parts[0] == 192 and parts[1] == 168) or
            parts[0] == 127)

# ── Analysis Engine ───────────────────────────────────────────────────────────

def analyze_headers(raw_headers):
    """
    Full analysis of email headers.
    Checks for spoofing, authentication failures, and suspicious patterns.
    """
    headers = parse_headers(raw_headers)
    red_flags  = []
    green_flags = []
    warnings   = []

    print(f"\n{'='*60}")
    print(f"  📧 EMAIL HEADER ANALYSIS")
    print(f"{'='*60}\n")

    # ── Basic fields ──────────────────────────────────────────
    from_field    = headers.get('From', 'Not found')
    to_field      = headers.get('To', 'Not found')
    subject       = headers.get('Subject', 'Not found')
    date          = headers.get('Date', 'Not found')
    message_id    = headers.get('Message-ID', 'Not found')
    return_path   = headers.get('Return-Path', 'Not found')
    originating_ip = headers.get('X-Originating-IP', None)
    mailer        = headers.get('X-Mailer', None)
    auth_results  = headers.get('Authentication-Results', '')

    print(f"  📌 Basic Information")
    print(f"  {'─'*50}")
    print(f"  From       : {from_field}")
    print(f"  To         : {to_field}")
    print(f"  Subject    : {subject}")
    print(f"  Date       : {date}")
    print(f"  Message-ID : {message_id}")

    # ── Spoofing check: From vs Return-Path ───────────────────
    print(f"\n  🔍 Spoofing Analysis")
    print(f"  {'─'*50}")

    from_email   = extract_email_address(from_field)
    return_email = extract_email_address(return_path)
    from_domain  = from_email.split('@')[-1] if '@' in from_email else ''
    return_domain = return_email.split('@')[-1] if '@' in return_email else ''
    msgid_domain = message_id.split('@')[-1].rstrip('>') if '@' in message_id else ''

    print(f"  From address    : {from_email}")
    print(f"  Return-Path     : {return_email}")
    print(f"  Message-ID host : {msgid_domain}")

    if from_domain and return_domain and from_domain != return_domain:
        red_flags.append(
            f"From domain ({from_domain}) ≠ Return-Path domain ({return_domain}) — likely spoofed!"
        )
    else:
        green_flags.append("From domain matches Return-Path domain")

    if msgid_domain and from_domain and msgid_domain != from_domain:
        red_flags.append(
            f"Message-ID domain ({msgid_domain}) doesn't match sender ({from_domain})"
        )

    # ── SPF / DKIM / DMARC ────────────────────────────────────
    print(f"\n  🔐 Authentication Results (SPF / DKIM)")
    print(f"  {'─'*50}")

    spf_match  = re.search(r'spf=(pass|fail|softfail|neutral|none)', auth_results, re.IGNORECASE)
    dkim_match = re.search(r'dkim=(pass|fail|none)', auth_results, re.IGNORECASE)

    spf_result  = spf_match.group(1).upper()  if spf_match  else "NOT FOUND"
    dkim_result = dkim_match.group(1).upper() if dkim_match else "NOT FOUND"

    spf_icon  = "✅" if spf_result  == "PASS" else "❌"
    dkim_icon = "✅" if dkim_result == "PASS" else "❌"

    print(f"  SPF  : {spf_icon} {spf_result}")
    print(f"  DKIM : {dkim_icon} {dkim_result}")

    if spf_result != "PASS":
        red_flags.append(f"SPF {spf_result} — server not authorized to send for this domain")
    else:
        green_flags.append("SPF passed — sender IP authorized by domain")

    if dkim_result != "PASS":
        red_flags.append("DKIM failed — email signature invalid or missing")
    else:
        green_flags.append("DKIM passed — email signature verified")

    # ── Originating IP ────────────────────────────────────────
    print(f"\n  🌐 Origin IP Analysis")
    print(f"  {'─'*50}")

    if originating_ip:
        print(f"  X-Originating-IP : {originating_ip}")
        if is_private_ip(originating_ip):
            warnings.append(f"Originating IP {originating_ip} is private/internal")
        else:
            print(f"  This is a public IP — could be looked up in threat intel databases")

    # Trace Received chain
    received_chain = headers.get('_received', [])
    if received_chain:
        print(f"\n  📬 Email Travel Path (Received chain — read bottom to top)")
        print(f"  {'─'*50}")
        for i, hop in enumerate(reversed(received_chain), 1):
            ip = extract_ip(hop)
            ip_note = f" (IP: {ip})" if ip else ""
            print(f"  Hop {i}: {hop[:70].strip()}{ip_note}")

    # ── Suspicious patterns ────────────────────────────────────
    print(f"\n  ⚠️  Pattern Checks")
    print(f"  {'─'*50}")

    # Urgent subject
    urgent_words = ['urgent', 'suspended', 'verify', 'immediately', 'alert',
                    'unusual', 'locked', 'confirm', 'expire', 'warning']
    if any(w in subject.lower() for w in urgent_words):
        red_flags.append(f"Subject uses urgency tactics: '{subject}'")

    # Suspicious mailer
    if mailer:
        print(f"  Mailer     : {mailer}")
        if 'phpmailer' in mailer.lower() or 'bulk' in mailer.lower():
            warnings.append(f"Suspicious mailer: {mailer} (common in spam/phishing)")

    # Russian/suspicious TLDs in domains
    suspicious_tlds = ['.ru', '.xyz', '.tk', '.ml', '.ga', '.cf', '.pw']
    all_text = raw_headers.lower()
    for tld in suspicious_tlds:
        if tld in all_text:
            red_flags.append(f"Suspicious TLD found in headers: '{tld}'")
            break

    # ── Verdict ───────────────────────────────────────────────
    print(f"\n  {'='*58}")
    print(f"  📊 VERDICT")
    print(f"  {'='*58}")

    if green_flags:
        for g in green_flags:
            print(f"  ✅ {g}")
    if warnings:
        for w in warnings:
            print(f"  🟡 {w}")
    if red_flags:
        for r in red_flags:
            print(f"  🔴 {r}")

    score = len(red_flags) * 2 + len(warnings)
    print()
    if score == 0:
        print("  🟢 LIKELY LEGITIMATE — No major red flags found")
    elif score <= 2:
        print("  🟡 SUSPICIOUS — Treat with caution")
    else:
        print("  🔴 HIGH RISK — Very likely phishing or spoofed email")
        print("  ⚠️  Do NOT click any links or open attachments.")
    print()

def explain_email_security():
    """Plain-English explanation of SPF, DKIM, and DMARC."""
    print("""
  📖 EMAIL SECURITY EXPLAINED
  ══════════════════════════════════════════════════════

  THE PROBLEM: Anyone can send an email claiming to be from any address.
  There's nothing in basic email (SMTP) that prevents this.
  This is called EMAIL SPOOFING.

  THE SOLUTION: Three DNS-based authentication systems:

  ┌─────────────────────────────────────────────────────┐
  │  SPF — Sender Policy Framework                      │
  │  "Which servers are allowed to send email for us?"  │
  │                                                     │
  │  Domain owners publish a list of approved IPs.      │
  │  Receiving servers check: is this email from an     │
  │  approved IP? If not → SPF FAIL                     │
  └─────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────┐
  │  DKIM — DomainKeys Identified Mail                  │
  │  "Is this email's content exactly as we sent it?"   │
  │                                                     │
  │  Sender cryptographically signs each email.         │
  │  Receiver checks the signature. If it changed       │
  │  in transit → DKIM FAIL                             │
  └─────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────┐
  │  DMARC — Domain-based Message Authentication        │
  │  "What should happen if SPF or DKIM fail?"          │
  │                                                     │
  │  Policy: reject / quarantine / none                 │
  │  Also sends reports of failed emails back to owner  │
  └─────────────────────────────────────────────────────┘

  A phishing email usually fails at least one of these.
  That's why your spam folder catches so much — it's working!
  ══════════════════════════════════════════════════════
""")

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   EMAIL HEADER ANALYZER              ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Analyze sample PHISHING email   ║")
        print("║  [2] Analyze sample LEGIT email      ║")
        print("║  [3] Paste your own headers          ║")
        print("║  [4] SPF / DKIM / DMARC explained    ║")
        print("║  [5] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            print("\n  Analyzing a simulated phishing email...")
            analyze_headers(SAMPLE_PHISHING_HEADERS)

        elif choice == "2":
            print("\n  Analyzing a simulated legitimate email...")
            analyze_headers(SAMPLE_LEGIT_HEADERS)

        elif choice == "3":
            print("\n  Paste raw email headers below.")
            print("  (In Gmail: open email → ... → Show original → copy headers)")
            print("  Type 'END' on a new line when done:\n")
            lines = []
            while True:
                line = input()
                if line.strip().upper() == 'END':
                    break
                lines.append(line)
            if lines:
                analyze_headers('\n'.join(lines))

        elif choice == "4":
            explain_email_security()

        elif choice == "5":
            print("\nGoodbye! Always check headers before clicking links. 🔐\n")
            break
        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

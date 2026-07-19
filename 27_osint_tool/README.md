# 🕵️ Project 27 — OSINT Tool (Open Source Intelligence Gatherer)

A passive reconnaissance tool that maps a target domain's infrastructure
using only publicly available sources — DNS records, WHOIS registration data,
certificate transparency logs, IP geolocation, and Google dork queries.
No direct contact with the target whatsoever.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| OSINT | Collecting intelligence from public sources only |
| Passive recon | Gathering info without contacting the target |
| DNS enumeration | Mapping A, AAAA, MX, NS, TXT, SOA records |
| WHOIS | Registrant info, creation dates, nameservers |
| Certificate transparency | Every SSL cert ever issued is publicly logged |
| Google dorking | Advanced search operators to find sensitive exposed content |
| Email pattern analysis | Inferring corporate email formats from public data |
| IP geolocation | Mapping IPs to hosting providers, cloud regions, countries |

## ▶️ How to Run

```bash
python3 osint_tool.py
```

Requires an internet connection. All queries go to third-party services —
DNS resolvers, crt.sh, ipinfo.io, WHOIS servers — the target never sees
a single request from you.

## 🔍 Features

- **DNS enumeration** — A, AAAA, MX, NS, TXT, SOA with SPF/DKIM/DMARC analysis
- **WHOIS lookup** — registrar, registrant org, creation/expiry dates, nameservers
- **WHOIS privacy detection** — flags when registrant details are protected
- **Certificate transparency** — queries crt.sh for every subdomain ever issued a cert
- **IP geolocation** — hosting provider, cloud region, ASN for the primary IP
- **Email pattern builder** — derives likely corporate email formats
- **Google dork generator** — 10 ready-to-run queries (PDFs, admin panels, credentials, pastes)
- Built-in explainer covering passive vs active recon (option 6)

## 🧪 Recommended Flow

1. Option 6 — read the OSINT explainer first
2. Option 2 → `github.com` — enumerate DNS records and read the SPF/DMARC analysis
3. Option 4 → any domain — generate dork queries and paste them into Google
4. Option 1 → full scan on a domain you own — see what attackers see about you
5. Option 5 → check CT logs for your domain — subdomains you forgot about

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Threats, Attacks & Vulnerabilities — reconnaissance techniques |
| CEH | Footprinting & Reconnaissance — passive OSINT, DNS, WHOIS, Google hacking |

## 📖 Key Terms

- **OSINT** — Open Source Intelligence — intelligence gathered from public sources
- **Passive recon** — gathering info without contacting the target directly
- **Active recon** — directly probing the target (leaves traces in logs)
- **DNS enumeration** — querying all DNS record types to map infrastructure
- **WHOIS** — protocol for querying domain registration databases (port 43)
- **Certificate transparency** — public log of every SSL cert ever issued
- **Google dorking** — advanced search operators to find sensitive content
- **SPF** — Sender Policy Framework — who is authorised to send email for a domain
- **DMARC** — policy for handling emails that fail SPF/DKIM checks
- **ASN** — Autonomous System Number — identifies the network/hosting provider
- **crt.sh** — public searchable index of all certificate transparency logs

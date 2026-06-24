# 🗂️ Project 17 — Directory Scanner (Web Path Enumerator)

A web enumeration tool that discovers hidden directories and files on web
servers by probing common paths — the same technique used in real penetration
tests with tools like DirBuster, Gobuster, and dirsearch.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| Web enumeration | Discovering hidden paths on a web server |
| HTTP status codes | Interpreting 200 / 301 / 401 / 403 / 500 responses |
| Forced browsing | Accessing pages not linked from the main site |
| robots.txt analysis | Extracting sensitive paths from a public file |
| Security headers | Checking for missing HSTS, X-Frame-Options, etc. |
| Attack surface | Understanding what a web server exposes publicly |

## ▶️ How to Run

```bash
python3 directory_scanner.py
```

Requires an internet connection for live scanning.

## 🔍 Features

- **Directory scan** — probes 100+ common paths × multiple file extensions
- **robots.txt analyser** — fetches and highlights sensitive disallowed paths
- **Security header check** — flags missing HSTS, X-Frame-Options, X-XSS-Protection
- **Concurrent scanning** — uses threading for speed (20 workers by default)
- **Status code reporting** — colour-coded results highlighting interesting finds
- Built-in explainer on how and why directory scanning works (option 4)

## 🧪 Recommended Flow

1. Run the explainer first (option 4) to understand the concept
2. Check robots.txt on a site you own (option 2) — see what's exposed
3. Run a full scan against `http://testphp.vulnweb.com` (option 1) —
   this is Acunetix's intentionally vulnerable test site, safe to scan
4. Check security headers on any site (option 3)

## ⚠️ Legal & Ethical Note

Only scan web servers you own or have **explicit written permission** to test.
Unauthorised web scanning may violate the Computer Fraud and Abuse Act (CFAA)
and equivalent laws. Always test on your own infrastructure or designated
practice sites like `testphp.vulnweb.com` or `OWASP WebGoat`.

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Application Security — web vulnerabilities, attack vectors |
| CEH | Web Application Hacking — enumeration, forced browsing, footprinting |

## 📖 Key Terms

- **Directory scanning / web enumeration** — probing for hidden files and folders
- **Forced browsing** — accessing URLs that aren't linked from the main navigation
- **HTTP status codes** — 200 (found), 403 (forbidden/exists), 404 (not found)
- **robots.txt** — file telling search engines what NOT to index (also tells attackers)
- **Security headers** — HTTP headers that harden browsers against common attacks
- **HSTS** — HTTP Strict Transport Security — forces HTTPS connections
- **Content discovery** — finding unlinked/unlisted content on a web server
- **DirBuster / Gobuster** — real-world tools doing the same thing at scale

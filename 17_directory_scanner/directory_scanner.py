"""
Project 17: Directory Scanner (Web Path Enumerator)
Concepts: web enumeration, HTTP status codes, attack surface discovery,
          robots.txt, forced browsing, content discovery

What you'll learn:
- How attackers discover hidden files and folders on web servers
- What HTTP status codes mean and how to interpret them
- Why "security through obscurity" fails (hidden ≠ protected)
- What robots.txt reveals and why it's a goldmine for attackers
- How real tools like DirBuster, Gobuster, and dirsearch work

⚠ Only scan web servers you own or have explicit permission to test.
"""

import urllib.request
import urllib.error
import concurrent.futures
import time
from datetime import datetime

# ── Wordlists ─────────────────────────────────────────────────────────────────

# Common directories attackers always check first
DIR_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "panel",
    "wp-admin", "wp-login", "phpmyadmin", "cpanel", "webmail",
    "api", "v1", "v2", "graphql", "rest",
    "backup", "backups", "bak", "old", "archive",
    "config", "configuration", "conf", "settings",
    "uploads", "upload", "files", "media", "images", "img",
    "static", "assets", "css", "js", "scripts",
    "test", "testing", "dev", "development", "staging",
    "tmp", "temp", "cache", "logs", "log",
    "db", "database", "sql", "mysql",
    "private", "secret", "hidden", "internal",
    "user", "users", "account", "accounts", "profile",
    "register", "signup", "forgot", "reset", "auth",
    ".git", ".env", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "server-status", "server-info",
]

# Common file extensions to append to directories
EXTENSIONS = ["", ".php", ".html", ".txt", ".bak", ".old", ".zip", ".sql"]

# HTTP status code meanings
STATUS_MEANINGS = {
    200: ("✅ FOUND",         "Page exists and is accessible"),
    201: ("✅ CREATED",       "Resource created"),
    204: ("🟡 NO CONTENT",   "Exists but empty"),
    301: ("🔀 REDIRECT",     "Permanently moved"),
    302: ("🔀 REDIRECT",     "Temporarily moved"),
    401: ("🔒 AUTH REQUIRED","Exists but needs login — interesting!"),
    403: ("⛔ FORBIDDEN",    "Exists but access denied — very interesting!"),
    404: ("—  NOT FOUND",    "Doesn't exist"),
    500: ("💥 SERVER ERROR", "Exists, triggered an error"),
}

# Status codes worth reporting (exclude 404)
INTERESTING_CODES = {200, 201, 204, 301, 302, 401, 403, 500}

# ── HTTP Probe ─────────────────────────────────────────────────────────────────

def probe_path(base_url, path, timeout=5):
    """
    Send an HTTP request to base_url/path and return the status code.
    Uses urllib from the standard library — no requests module needed.
    """
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Educational Scanner)',
                'Accept':     '*/*',
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return url, resp.status, len(resp.read())
    except urllib.error.HTTPError as e:
        # HTTP errors (403, 401, 500...) are still responses — worth recording
        return url, e.code, 0
    except urllib.error.URLError:
        return url, None, 0   # connection refused, timeout, DNS fail
    except Exception:
        return url, None, 0

def fetch_robots_txt(base_url, timeout=5):
    """
    Fetch and parse robots.txt — a file webmasters use to tell search engines
    which paths NOT to index. Ironically, it's a perfect map for attackers:
    'Disallow: /admin' tells everyone exactly where the admin panel is.
    """
    url = f"{base_url.rstrip('/')}/robots.txt"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode('utf-8', errors='replace')
            return content
    except Exception:
        return None

def get_server_banner(base_url, timeout=5):
    """Grab the Server header to identify the web server software."""
    try:
        req = urllib.request.Request(
            base_url,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {
                'Server':        resp.headers.get('Server', 'Not disclosed'),
                'X-Powered-By':  resp.headers.get('X-Powered-By', 'Not disclosed'),
                'Content-Type':  resp.headers.get('Content-Type', 'N/A'),
                'X-Frame-Options': resp.headers.get('X-Frame-Options', '❌ Missing'),
                'X-XSS-Protection': resp.headers.get('X-XSS-Protection', '❌ Missing'),
                'Strict-Transport-Security': resp.headers.get(
                    'Strict-Transport-Security', '❌ Missing (HSTS not set)'),
            }
    except Exception:
        return {}

# ── Scanner Engine ─────────────────────────────────────────────────────────────

def scan_directories(base_url, wordlist=None, extensions=None,
                     max_workers=20, timeout=5):
    """
    Main scan: probe all combinations of wordlist paths + extensions
    and report anything that returns an interesting HTTP status.
    """
    words  = wordlist or DIR_WORDLIST
    exts   = extensions or ["", ".php", ".html", ".txt"]

    # Build full path list — each word × each extension
    paths = []
    for word in words:
        for ext in exts:
            # Don't double-add extension if word already has one (robots.txt etc.)
            if '.' in word:
                paths.append(word)
                break
            paths.append(f"{word}{ext}")

    print(f"\n{'='*60}")
    print(f"  🔍 DIRECTORY SCANNER")
    print(f"{'='*60}")
    print(f"  Target  : {base_url}")
    print(f"  Paths   : {len(paths)} to probe")
    print(f"  Workers : {max_workers} concurrent")
    print(f"  Started : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}\n")

    found   = []
    tested  = 0
    start   = time.time()

    # Header for results
    print(f"  {'STATUS':<20} {'SIZE':>8}   URL")
    print(f"  {'─'*17} {'─'*7}   {'─'*35}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(probe_path, base_url, path, timeout): path
            for path in paths
        }
        for future in concurrent.futures.as_completed(futures):
            tested += 1
            url, code, size = future.result()
            print(f"  Scanning {tested}/{len(paths)}...", end="\r")

            if code in INTERESTING_CODES:
                label, _ = STATUS_MEANINGS.get(code, (f"  {code}", ""))
                size_str = f"{size:,}B" if size else "—"
                print(f"  [{code}] {label:<15} {size_str:>8}   {url}")
                found.append((code, url, size))

    elapsed = time.time() - start
    print(f"\n{'='*60}")
    print(f"  ✅ Scan done in {elapsed:.1f}s")
    print(f"  📂 Interesting paths: {len(found)} / {len(paths)} tested")
    print(f"{'='*60}\n")

    return found

# ── robots.txt Analyser ───────────────────────────────────────────────────────

def analyse_robots(base_url):
    """Fetch and highlight security-relevant paths from robots.txt."""
    print(f"\n  🤖 Fetching robots.txt from {base_url}...")
    content = fetch_robots_txt(base_url)

    if not content:
        print("  ⚠️  robots.txt not found or inaccessible.\n")
        return

    print(f"\n  📄 robots.txt content:")
    print(f"  {'─'*50}")
    for line in content.strip().split('\n'):
        print(f"  {line}")

    # Highlight sensitive-looking disallowed paths
    interesting = []
    sensitive   = ['admin', 'login', 'backup', 'config', 'private',
                   'secret', 'db', 'database', 'api', 'internal', 'dev']
    for line in content.split('\n'):
        if line.strip().lower().startswith('disallow:'):
            path = line.split(':', 1)[1].strip()
            for keyword in sensitive:
                if keyword in path.lower():
                    interesting.append(path)
                    break

    if interesting:
        print(f"\n  ⚠️  Sensitive paths exposed in robots.txt:")
        for path in interesting:
            print(f"  🎯 {path}")
        print(f"\n  💡 Robots.txt is public. Every path listed here is a hint")
        print(f"     to attackers — even 'Disallow' paths are visible to anyone.\n")
    else:
        print(f"\n  ✅ No obviously sensitive paths in robots.txt.\n")

# ── Header Security Check ─────────────────────────────────────────────────────

def check_security_headers(base_url):
    """Fetch server headers and flag missing security headers."""
    print(f"\n  🛡  Security Header Check: {base_url}")
    print(f"  {'─'*50}")

    headers = get_server_banner(base_url)
    if not headers:
        print("  ❌ Could not connect to server.\n")
        return

    security_headers = [
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
    ]

    for key, value in headers.items():
        icon = "✅" if "Missing" not in value and "Not" not in value else "❌"
        print(f"  {icon} {key:<30} : {value}")

    print(f"\n  💡 Missing security headers are low-hanging fruit for attackers:")
    print(f"     X-Frame-Options missing → clickjacking attacks possible")
    print(f"     HSTS missing           → SSL stripping attacks possible\n")

# ── Explainer ─────────────────────────────────────────────────────────────────

def explain_directory_scanning():
    print("""
  📖 DIRECTORY SCANNING — How & Why Attackers Do This
  ══════════════════════════════════════════════════════

  WHAT IS IT?
  Directory scanning (also: web enumeration, content discovery, forced
  browsing) is the process of trying common filenames and folder names
  on a web server to find pages that aren't linked anywhere.

  WHY IT WORKS:
  Developers often:
  • Leave old backup files on the server (login.php.bak)
  • Forget to remove test pages (/test, /dev, /staging)
  • Expose admin panels without thinking (/admin, /phpmyadmin)
  • Leave .git folders visible — attacker can download the entire source code!
  • Leave .env files accessible — contains database passwords and API keys!

  HOW HTTP STATUS CODES HELP:
  ┌──────┬──────────────────────────────────────────────┐
  │ Code │ What it means for scanning                   │
  ├──────┼──────────────────────────────────────────────┤
  │  200 │ ✅ Found! Page exists and is readable        │
  │  301 │ 🔀 Redirect — follow it, something is there  │
  │  401 │ 🔒 Needs login — EXISTS but protected        │
  │  403 │ ⛔ Forbidden — EXISTS but denied — try more! │
  │  404 │ Not found — move on                          │
  │  500 │ 💥 Server error — something broke but EXISTS │
  └──────┴──────────────────────────────────────────────┘

  403 is often MORE interesting than 200 — it means something is there
  but the server is trying to hide it. Attackers probe further.

  THE ROBOTS.TXT IRONY:
  Webmasters add paths to robots.txt to hide them from Google.
  But robots.txt is publicly readable — it's literally a list of
  "here are the paths we don't want people to find."
  Attackers check robots.txt FIRST.

  REAL TOOLS THAT DO THIS:
  • DirBuster — the classic (Java)
  • Gobuster  — fast, written in Go
  • dirsearch — Python-based, feature-rich
  • ffuf       — extremely fast fuzzer

  Our scanner is the same concept, built from scratch.
  ══════════════════════════════════════════════════════
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   DIRECTORY SCANNER                  ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Scan for hidden directories     ║")
        print("║  [2] Analyse robots.txt              ║")
        print("║  [3] Check security headers          ║")
        print("║  [4] How directory scanning works    ║")
        print("║  [5] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            print("\n  ⚠️  Only scan servers you own or have permission to test.")
            print("  Safe practice target: http://testphp.vulnweb.com\n")
            url = input("  Target URL (e.g. http://testphp.vulnweb.com): ").strip()
            if not url:
                print("  ❌ No URL entered.")
                continue
            if not url.startswith(("http://", "https://")):
                url = "http://" + url

            ext_input = input(
                "  Extensions to try (default: none .php .html .txt): "
            ).strip()
            exts = ext_input.split() if ext_input else ["", ".php", ".html", ".txt"]

            scan_directories(url, extensions=exts)

        elif choice == "2":
            url = input("\n  Target URL: ").strip()
            if not url:
                print("  ❌ No URL entered.")
                continue
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            analyse_robots(url)

        elif choice == "3":
            url = input("\n  Target URL: ").strip()
            if not url:
                print("  ❌ No URL entered.")
                continue
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            check_security_headers(url)

        elif choice == "4":
            explain_directory_scanning()

        elif choice == "5":
            print("\nGoodbye! Hidden ≠ protected. 🔐\n")
            break

        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

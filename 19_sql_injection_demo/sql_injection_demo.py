"""
Project 19: SQL Injection Demo (Educational)
Concepts: SQL injection, parameterized queries, input sanitization,
          UNION attacks, blind SQLi, authentication bypass, OWASP Top 10

What you'll learn:
- What SQL injection is and why it's been the #1 web vulnerability for decades
- How classic login bypass works (' OR '1'='1)
- How UNION-based injection extracts data from other database tables
- What blind SQL injection is and how it works without seeing output
- How parameterized queries (prepared statements) completely prevent SQLi

⚠ This project creates an INTENTIONALLY VULNERABLE system for learning.
  Never use vulnerable patterns in real applications.
  Only test SQL injection on systems you own or have permission to test.
"""

import sqlite3
import re

# ── Database Setup ─────────────────────────────────────────────────────────────

def setup_database():
    """
    Create an in-memory SQLite database with two tables:
    - users: login credentials (the target of our injection attacks)
    - secret_data: sensitive info users shouldn't be able to see directly
    """
    conn = sqlite3.connect(':memory:')   # in-memory: nothing written to disk
    cur  = conn.cursor()

    # Vulnerable users table (simulates a real login system)
    cur.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user'
        )
    """)

    # Sensitive table users aren't supposed to access
    cur.execute("""
        CREATE TABLE secret_data (
            id      INTEGER PRIMARY KEY,
            label   TEXT NOT NULL,
            value   TEXT NOT NULL
        )
    """)

    # Seed with realistic data
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ('alice',  'hunter2',      'user'),
            ('bob',    'password123',  'user'),
            ('admin',  'sup3rS3cr3t!', 'admin'),
            ('charlie','qwerty',       'user'),
        ]
    )
    cur.executemany(
        "INSERT INTO secret_data (label, value) VALUES (?, ?)",
        [
            ('API_KEY',        'sk-prod-Xk9mQ2zPL5rN8w'),
            ('DB_PASSWORD',    'R00t_P@ssw0rd_2024'),
            ('ADMIN_TOKEN',    'eyJhbGciOiJIUzI1NiJ9...'),
            ('INTERNAL_EMAIL', 'admin@corp-internal.net'),
        ]
    )
    conn.commit()
    return conn

# ── Vulnerable Login (the target) ─────────────────────────────────────────────

def vulnerable_login(conn, username, password):
    """
    ⚠️  INTENTIONALLY VULNERABLE — DO NOT USE IN REAL CODE.

    Builds a SQL query using Python string formatting.
    An attacker can inject SQL code through the username or password field.
    """
    # This is the dangerous pattern: user input directly concatenated into SQL
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    print(f"\n  🔴 Vulnerable query: {query}")

    try:
        cur = conn.cursor()
        cur.execute(query)
        result = cur.fetchone()
        return result
    except sqlite3.OperationalError as e:
        print(f"  ❌ SQL Error: {e}")
        return None

def safe_login(conn, username, password):
    """
    ✅ SAFE — Uses parameterized queries (prepared statements).

    The ? placeholders are filled in by the database driver, which
    NEVER interprets user input as SQL code. Injection is impossible.
    """
    query = "SELECT * FROM users WHERE username = ? AND password = ?"

    print(f"\n  🟢 Safe query template: {query}")
    print(f"  🟢 Parameters: ('{username}', '{password}')")

    cur = conn.cursor()
    cur.execute(query, (username, password))
    return cur.fetchone()

# ── Attack Demonstrations ─────────────────────────────────────────────────────

def demo_login_bypass(conn):
    """
    Classic SQL injection login bypass.
    The payload ' OR '1'='1 turns the WHERE clause always-true,
    returning the FIRST user in the database (usually admin).
    """
    print("\n" + "="*60)
    print("  💀 ATTACK 1: Authentication Bypass")
    print("="*60)
    print("""
  Goal: log in WITHOUT knowing any password.

  How it works:
  Normal query:
    SELECT * FROM users WHERE username = 'alice'
                          AND password = 'wrongpw'
    → Returns nothing (password is wrong) → login fails

  Injected query (username = admin'--)  :
    SELECT * FROM users WHERE username = 'admin'--'
                          AND password = '...'
    → The -- comments out the password check entirely!
    → Returns admin row → login succeeds without the password
""")

    payloads = [
        ("admin'--",       "anything",     "Comment-out attack: skips the password check"),
        ("' OR '1'='1'--", "anything",     "Always-true: returns first row in the table"),
        ("alice",          "' OR '1'='1",  "Inject through password field instead"),
    ]

    for username, password, description in payloads:
        print(f"  ─── Payload: {description} ───")
        print(f"  Username : {username}")
        print(f"  Password : {password}")
        result = vulnerable_login(conn, username, password)
        if result:
            print(f"  ✅ LOGIN SUCCEEDED → Got row: id={result[0]}, "
                  f"user={result[1]}, role={result[3]}")
        else:
            print(f"  ❌ Login failed")
        print()

def demo_union_attack(conn):
    """
    UNION-based SQL injection: extract data from OTHER tables.
    By appending a UNION SELECT, we can read tables we were never
    meant to access — like the secret_data table.
    """
    print("\n" + "="*60)
    print("  💀 ATTACK 2: UNION-Based Data Extraction")
    print("="*60)
    print("""
  Goal: read the secret_data table using only the login form.

  How it works:
  Normal query returns 4 columns (id, username, password, role).
  A UNION SELECT appends another result set — if we match 4 columns,
  the database happily combines both result sets and returns them all.

  username = ' UNION SELECT id, label, value, 'stolen' FROM secret_data--
""")

    # The injected username makes the query return secret_data rows
    payload = "' UNION SELECT id, label, value, 'stolen' FROM secret_data--"

    print(f"  Injected username: {payload}")
    query = f"SELECT * FROM users WHERE username = '{payload}' AND password = 'x'"
    print(f"  Full query: {query}\n")

    try:
        cur = conn.cursor()
        cur.execute(query)
        rows = cur.fetchall()
        if rows:
            print(f"  🚨 Extracted {len(rows)} row(s) from secret_data table:")
            print(f"  {'─'*50}")
            for row in rows:
                print(f"  [{row[0]}] {row[1]:<20} = {row[2]}")
        else:
            print("  No rows returned.")
    except sqlite3.OperationalError as e:
        print(f"  SQL Error: {e}")
    print()

def demo_blind_sqli(conn):
    """
    Blind SQL injection: extract info one TRUE/FALSE question at a time.
    Used when the application doesn't show query results directly,
    but behaves differently for true vs false conditions.
    """
    print("\n" + "="*60)
    print("  💀 ATTACK 3: Blind SQL Injection")
    print("="*60)
    print("""
  Goal: discover information even when the app shows no output.

  How it works:
  Ask YES/NO questions via SQL conditions:
    ' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='s'--
  → If admin's password starts with 's' → login succeeds (TRUE branch)
  → Otherwise → login fails (FALSE branch)

  By asking one character at a time, attackers reconstruct
  the full password — no output required.
""")

    # Simulate blind SQLi by asking character-by-character questions
    target_user   = 'admin'
    recovered     = ''
    max_length    = 12

    print(f"  Extracting admin password one character at a time...\n")
    print(f"  {'Attempt':<10} {'Question (SQL)':<45} {'Answer'}")
    print(f"  {'─'*8} {'─'*43} {'─'*6}")

    charset = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$_ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    for pos in range(1, max_length + 1):
        found_char = False
        for char in charset:
            # Ask: "is the character at position pos equal to char?"
            payload = (f"' AND (SELECT SUBSTR(password,{pos},1) "
                       f"FROM users WHERE username='{target_user}')='{char}'--")

            query = f"SELECT id FROM users WHERE username = '{payload}' AND password = 'x'"
            try:
                cur = conn.cursor()
                cur.execute(query)
                if cur.fetchone():   # TRUE branch → found the character
                    recovered += char
                    question  = f"pos={pos}, char='{char}'?"
                    print(f"  {pos:<10} {question:<45} ✅ YES → '{recovered}'")
                    found_char = True
                    break
            except sqlite3.OperationalError:
                break

        if not found_char:
            break   # End of password reached

    print(f"\n  🚨 Recovered password: '{recovered}'\n")

def demo_safe_defence(conn):
    """
    Show that parameterized queries completely block all injection attempts.
    The exact same payloads that worked against the vulnerable version
    are treated as literal strings — no SQL interpretation at all.
    """
    print("\n" + "="*60)
    print("  🛡  DEFENCE: Parameterized Queries")
    print("="*60)
    print("""
  Using parameterized queries (prepared statements), the database
  driver fills in the ? placeholders AFTER parsing the SQL structure.
  User input CANNOT change the query's structure — ever.
""")

    payloads = [
        ("admin'--",       "anything"),
        ("' OR '1'='1'--", "anything"),
        ("alice",          "' OR '1'='1"),
    ]

    for username, password in payloads:
        print(f"  Testing: username='{username}', password='{password}'")
        result = safe_login(conn, username, password)
        if result:
            print(f"  ⚠️  Login succeeded (legitimate match found)")
        else:
            print(f"  ✅ BLOCKED — injection payload treated as literal string\n")

# ── Injection Tester ──────────────────────────────────────────────────────────

def interactive_test(conn):
    """Let the user try their own payloads against both systems."""
    print("\n  🧪 Interactive SQL Injection Tester")
    print("  Try your own payloads against the vulnerable login.\n")
    print("  Hint payloads to try:")
    print("    Username: admin'--              Password: anything")
    print("    Username: ' OR '1'='1'--       Password: anything")
    print("    Username: alice                Password: ' OR '1'='1")
    print()

    username = input("  Username: ").strip()
    password = input("  Password: ").strip()

    print("\n  ── Vulnerable System ──")
    result_v = vulnerable_login(conn, username, password)
    if result_v:
        print(f"  ✅ VULNERABLE LOGIN SUCCEEDED → User: {result_v[1]}, Role: {result_v[3]}")
    else:
        print(f"  ❌ Vulnerable login: failed")

    print("\n  ── Safe System (parameterized) ──")
    result_s = safe_login(conn, username, password)
    if result_s:
        print(f"  ✅ Safe login succeeded → User: {result_s[1]}, Role: {result_s[3]}")
    else:
        print(f"  ✅ Safe login: blocked (payload treated as literal string)\n")

# ── Explainer ─────────────────────────────────────────────────────────────────

def explain_sql_injection():
    print("""
  📖 SQL INJECTION — The #1 Web Vulnerability
  ══════════════════════════════════════════════════════

  WHAT IS IT?
  SQL injection (SQLi) happens when user input is embedded directly
  into a SQL query without sanitization, letting attackers inject
  their own SQL code and change what the query does.

  SQL injection has been in the OWASP Top 10 most critical web
  vulnerabilities for over 20 years. Real breaches caused by SQLi:
  • 2008 Heartland Payment Systems  — 130M card numbers stolen
  • 2012 LinkedIn                   — 6.5M password hashes leaked
  • 2019 Capital One                — 100M customer records exposed

  THE ROOT CAUSE:
  Developers write queries like this:
    query = "SELECT * FROM users WHERE name='" + username + "'"

  If username = alice  → "SELECT * FROM users WHERE name='alice'"
  If username = '      → "SELECT * FROM users WHERE name='''"  → SYNTAX ERROR
  If username = ' OR '1'='1'-- → always-true WHERE clause → ALL rows returned

  TYPES OF SQL INJECTION:
  ┌─────────────────┬────────────────────────────────────────────┐
  │ Classic         │ Results visible in page output             │
  │ UNION-based     │ Append extra SELECT to steal other tables  │
  │ Blind (boolean) │ Infer data from true/false app behaviour   │
  │ Blind (time)    │ Infer data from response delay (SLEEP())   │
  │ Error-based     │ Extract data from database error messages  │
  │ Second-order    │ Payload stored then executed later         │
  └─────────────────┴────────────────────────────────────────────┘

  THE FIX — PARAMETERIZED QUERIES:
  cursor.execute("SELECT * FROM users WHERE name = ?", (username,))

  The ? is filled in by the database driver AFTER the SQL structure
  is parsed. User input can NEVER change the query structure.
  This is the ONLY reliable fix — never try to sanitize/escape manually.

  OTHER DEFENCES:
  • ORMs (SQLAlchemy, Django ORM) use parameterized queries by default
  • Least privilege — DB user should only have needed permissions
  • WAF (Web Application Firewall) can detect/block common patterns
  • Error handling — never show database errors to users
  ══════════════════════════════════════════════════════
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    conn = setup_database()

    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   SQL INJECTION DEMO                 ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Attack 1: Login bypass          ║")
        print("║  [2] Attack 2: UNION data extraction ║")
        print("║  [3] Attack 3: Blind SQL injection   ║")
        print("║  [4] Defence: parameterized queries  ║")
        print("║  [5] Try your own payloads           ║")
        print("║  [6] SQL injection explained         ║")
        print("║  [7] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if   choice == "1": demo_login_bypass(conn)
        elif choice == "2": demo_union_attack(conn)
        elif choice == "3": demo_blind_sqli(conn)
        elif choice == "4": demo_safe_defence(conn)
        elif choice == "5": interactive_test(conn)
        elif choice == "6": explain_sql_injection()
        elif choice == "7":
            print("\nGoodbye! Always use parameterized queries. 🔐\n")
            conn.close()
            break
        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

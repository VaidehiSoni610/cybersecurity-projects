# 💉 Project 19 — SQL Injection Demo (Educational)

A fully working SQL injection lab built with Python's built-in `sqlite3` module.
Demonstrates three classes of SQL injection attack against an intentionally
vulnerable login system, then shows exactly why parameterized queries prevent all of them.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| SQL injection (SQLi) | Injecting SQL code through user input fields |
| Login bypass | Using `' OR '1'='1` to authenticate without a password |
| UNION-based attack | Extracting data from tables you shouldn't access |
| Blind SQL injection | Inferring data one TRUE/FALSE question at a time |
| Parameterized queries | The fix — user input can never change query structure |
| OWASP Top 10 | SQLi has been a top web vulnerability for 20+ years |

## ▶️ How to Run

```bash
python3 sql_injection_demo.py
```

No internet connection required. The database is created in memory at runtime
and destroyed when the program exits — nothing is written to disk.

## 🔍 Features

- **Attack 1: Login bypass** — three payloads showing how to skip authentication
- **Attack 2: UNION extraction** — steal the `secret_data` table through the login form
- **Attack 3: Blind SQLi** — recover the admin password character by character
- **Defence demo** — exact same payloads, completely blocked by parameterized queries
- **Interactive tester** — type your own payloads and see live results
- Built-in explainer covering SQLi history, types, and defences (option 6)

## 🧪 Recommended Flow

1. Option 6 — read the explainer to understand the concept
2. Option 1 — watch login bypass work step by step
3. Option 2 — see the UNION attack extract the secret table
4. Option 3 — watch blind SQLi recover the admin password letter by letter
5. Option 4 — run the exact same payloads against the safe version and watch them all fail
6. Option 5 — try writing your own payload

## ⚠️ Legal & Ethical Note

This project creates an **intentionally vulnerable system for learning only**.
Never use string-concatenated SQL in real applications.
Only test SQL injection on systems you own or have explicit written permission to test.

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Application Security — injection attacks, secure coding |
| CEH | Web Application Hacking — SQL injection, OWASP Top 10 |

## 📖 Key Terms

- **SQL injection (SQLi)** — injecting SQL code via unsanitized user input
- **Authentication bypass** — logging in without valid credentials using injection
- **UNION attack** — appending a second SELECT to read other database tables
- **Blind SQLi** — inferring data from app behaviour without seeing output
- **Parameterized queries** — placeholders filled by DB driver after query parsing — the fix
- **Prepared statements** — another name for parameterized queries
- **OWASP Top 10** — list of the 10 most critical web application security risks
- **Tautology** — always-true condition (`'1'='1'`) used in injection payloads
- **Comment injection** — using `--` or `#` to comment out the rest of a query
- **WAF** — Web Application Firewall — can detect/block common SQLi patterns

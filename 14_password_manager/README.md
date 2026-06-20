# 🔑 Project 14 — Password Manager (Local, Encrypted Vault)

A command-line password manager that encrypts and stores credentials locally,
protected by a single master password. Built to understand how real password
managers like Bitwarden and 1Password work under the hood.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| Key derivation (PBKDF2) | Turning a master password into a strong encryption key |
| Key stretching | Repeating hash rounds (200,000x) to slow down attackers |
| Salting | Random value preventing rainbow table attacks |
| Symmetric encryption | XOR-stream cipher (built on Project 11) to protect stored passwords |
| Constant-time comparison | Preventing timing attacks during login |
| Secure random generation | Using `secrets` instead of `random` for password generation |

## ▶️ How to Run

```bash
python3 password_manager.py
```

First run creates a new encrypted vault (`vault.json`) protected by a master
password you choose. Every run after that asks you to unlock it.

## 🔍 Features

- **Master password protection** — one password to remember, verified via PBKDF2
- **Encrypted storage** — every saved password is encrypted before touching disk
- **Built-in password generator** — cryptographically secure, using `secrets`
- **Add / view / list / delete** entries
- **3-attempt lockout** on the master password (same concept as Project 7)
- **Security model walkthrough** built into the app (option 6)

## ⚠️ Educational Scope

This project uses XOR-stream encryption to stay within Python's standard
library so the full mechanism is visible and understandable. Production
password managers use **AES-256-GCM** via audited cryptography libraries.
Never use hand-rolled encryption to protect real secrets — this project is
for learning the concepts, not for storing your actual passwords.

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Cryptography — key derivation, salting, symmetric encryption |
| CEH | Cryptography Concepts — PBKDF2, key stretching, secure storage |

## 📖 Key Terms

- **PBKDF2** — Password-Based Key Derivation Function 2; stretches a password into a strong key
- **Key stretching** — repeating a hash function many times to slow brute-force attacks
- **Master password** — the single password that unlocks everything else
- **Salt** — random value mixed into hashing to defeat precomputed attacks
- **Symmetric encryption** — same key encrypts and decrypts (here: XOR stream)
- **Constant-time comparison** — comparison that takes the same time regardless of input, preventing timing attacks
- **secrets module** — Python's cryptographically secure random number source

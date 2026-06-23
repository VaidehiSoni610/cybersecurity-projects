# 🔒 Project 16 — SSL Certificate Checker

A command-line tool that connects to any HTTPS server, retrieves its SSL/TLS
certificate, and produces a full security report — including expiry status,
cipher suite rating, TLS version grading, and self-signed detection.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| SSL / TLS | The protocol that encrypts HTTPS traffic |
| Digital certificates | Identity documents for websites, issued by CAs |
| PKI | Public Key Infrastructure — the system of trust behind HTTPS |
| Certificate expiry | Monitoring when certs need renewal |
| Cipher suite grading | Identifying weak or broken encryption algorithms |
| TLS version checking | Detecting deprecated protocol versions |
| Self-signed detection | Flagging certs not trusted by browsers |
| Subject Alternative Names | The list of domains a certificate covers |

## ▶️ How to Run

```bash
python3 ssl_cert_checker.py
```

Requires an internet connection to check live certificates.

## 🔍 Features

- **Full certificate report** — subject, issuer, SANs, validity period, days remaining
- **Expiry status** — colour-coded: OK / Notice / Warning / Critical / Expired
- **TLS version grading** — flags TLS 1.0/1.1, SSL 2/3 as deprecated/broken
- **Cipher suite grading** — detects RC4, DES, 3DES, MD5, NULL, EXPORT ciphers
- **Self-signed detection** — identifies certificates not backed by a trusted CA
- **Bulk checker** — check multiple domains in one table view
- Built-in explainer covering the full TLS handshake and PKI (option 3)

## 🧪 Recommended Flow

1. Check a well-known site like `github.com` or `google.com` (option 1)
2. Observe the TLS version, cipher suite, and expiry
3. Try `expired.badssl.com` and `self-signed.badssl.com` — sites deliberately
   misconfigured to test security tools (option 1)
4. Use bulk check (option 2) to scan several domains at once

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Cryptography & PKI — certificates, CAs, TLS |
| CEH | Cryptography — SSL/TLS internals, cipher suites, certificate attacks |

## 📖 Key Terms

- **SSL / TLS** — Secure Sockets Layer / Transport Layer Security (TLS replaced SSL)
- **Certificate** — digitally signed identity document for a server
- **CA (Certificate Authority)** — trusted organisation that issues certificates
- **PKI** — Public Key Infrastructure — the full system of CAs, certs, and trust
- **SANs** — Subject Alternative Names — domains the certificate is valid for
- **Cipher suite** — the combination of algorithms used to secure a TLS connection
- **Forward secrecy** — ECDHE/DHE ciphers ensure past sessions stay safe even if keys are compromised later
- **Self-signed** — certificate signed by itself rather than a trusted CA
- **TLS handshake** — the negotiation process that sets up an encrypted connection
- **Root CA** — top-level certificate authority trusted directly by browsers/OSes

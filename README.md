# 🔐 Cybersecurity Learning Projects

A collection of 4 hands-on Python projects to build foundational cybersecurity skills.
Each project maps to real-world concepts tested in **CompTIA Security+**, **CEH**, and similar certifications.

---

## 📁 Project Structure

```
cybersec-projects/
├── README.md                          ← You are here
├── 1_password_checker/
│   └── password_checker.py            ← Password entropy & strength analysis
├── 2_caesar_cipher/
│   └── caesar_cipher.py              ← Encryption, decryption, brute force
├── 3_port_scanner/
│   └── port_scanner.py               ← TCP socket port scanning
└── 4_file_integrity_checker/
    └── file_integrity.py             ← SHA-256 file hashing & tamper detection
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- No external libraries needed (all standard library)

### Run any project:
```bash
python 1_password_checker/password_checker.py
python 2_caesar_cipher/caesar_cipher.py
python 3_port_scanner/port_scanner.py
python 4_file_integrity_checker/file_integrity.py
```

---

## 📘 Projects Overview

| # | Project | Key Concepts |
|---|---------|-------------|
| 1 | Password Strength Analyzer | Entropy, character diversity, common password detection |
| 2 | Caesar Cipher Tool | Substitution cipher, encryption, brute-force cracking |
| 3 | TCP Port Scanner | Networking, sockets, service fingerprinting |
| 4 | File Integrity Checker | Hashing, MD5/SHA256, tamper detection, digital forensics |

---

## ⚙️ Git Setup (Step-by-Step)

### 1. Initialize Git in this folder
```bash
cd cybersec-projects
git init
```

### 2. Add a .gitignore
```bash
echo "__pycache__/" >> .gitignore
echo "*.pyc"        >> .gitignore
echo "*.pyo"        >> .gitignore
echo "baseline_hashes.json" >> .gitignore
echo ".env"         >> .gitignore
```

### 3. Stage all files
```bash
git add .
```

### 4. First commit
```bash
git commit -m "feat: add 4 cybersecurity learning projects"
```

### 5. Create a repo on GitHub
- Go to https://github.com/new
- Name it `cybersec-projects` (or similar)
- Leave it **empty** (no README, no .gitignore)
- Click **Create repository**

### 6. Connect and push
```bash
git remote add origin https://github.com/YOUR_USERNAME/cybersec-projects.git
git branch -M main
git push -u origin main
```

### 7. Future commits (standard workflow)
```bash
git add .
git commit -m "feat: describe what you changed"
git push
```

---

## 🔒 Legal & Ethical Reminder

> **Port Scanner**: Only scan hosts you own or have **explicit written permission** to scan.
> Unauthorized port scanning may violate laws such as the CFAA (US) or Computer Misuse Act (UK).

---

## 🎓 Certification Mapping

| Project | Security+ Domain | CEH Topic |
|---------|-----------------|-----------|
| Password Checker | Identity & Access Management | Password Attacks |
| Caesar Cipher | Cryptography | Encryption Algorithms |
| Port Scanner | Network Security | Reconnaissance / Footprinting |
| File Integrity | Threats, Attacks & Vulnerabilities | Malware / Forensics |

---

*Built as a learning portfolio for cybersecurity certification prep.*

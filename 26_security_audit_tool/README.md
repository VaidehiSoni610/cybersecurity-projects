# 🔒 Project 26 — Security Audit Tool (Capstone)

A comprehensive security audit tool that checks your Mac against a
security baseline inspired by the CIS Apple macOS Benchmark — covering
user accounts, network configuration, system hardening, filesystem
permissions, and running processes — and produces a scored compliance
report with remediation guidance.

This is the capstone project, tying together techniques from all 25
previous projects into one complete system-level security assessment.

## 💡 What This Project Covers

| Concept | Description |
|---------|-------------|
| Security baseline | A documented set of required security settings (CIS Benchmark) |
| Compliance scoring | Weighted pass/fail scoring across all checks (0–100, grade A–F) |
| System hardening | FileVault, SIP, Gatekeeper, automatic updates, screen lock |
| User account auditing | UID 0 checks, guest account, auto-login, login shell inventory |
| Network auditing | Firewall status, stealth mode, remote login, suspicious ports |
| Filesystem auditing | World-writable files, sticky bit, home dir permissions, .ssh |
| Process auditing | Suspicious processes, unknown LaunchAgents |

## ▶️ How to Run

```bash
python3 security_audit_tool.py
```

No internet connection or root access required. Reads system configuration
via `defaults`, `systemsetup`, `fdesetup`, `csrutil`, and `spctl` commands,
plus Python's `os.stat()` for file permission checks.

## 🔍 Features

- **17 audit checks** across 5 categories — each with a control ID,
  severity, evidence, and specific remediation guidance
- **Weighted compliance score** — CRITICAL failures hurt more than LOW ones
- **Letter grade (A–F)** — instant readability of overall posture
- **Remediation priority list** — failed checks sorted Critical → Low
- **File output** — save report as a `.txt` file (option 2)
- **Category-specific audits** — run just user accounts or just hardening
- Built-in explainer covering CIS Benchmarks, compliance frameworks,
  and the hardening lifecycle (option 5)

## 🧪 Recommended Flow

1. Option 5 — read the explainer (especially the hardening lifecycle diagram)
2. Option 1 — run a full audit on your Mac
3. Read the failed checks and understand what each one means
4. Option 4 — run just the hardening checks to focus on the most impactful fixes
5. Option 2 — save the report to a file to track your progress over time

## 🎓 Certification Relevance

| Exam | Domain |
|------|--------|
| CompTIA Security+ | Security Operations — hardening, baselines, compliance |
| CEH | System Hacking — privilege escalation, system config, hardening countermeasures |

## 🔗 How This Ties All 26 Projects Together

| Previous project | Technique reused |
|-----------------|-----------------|
| Projects 3, 12 | Port scanning for NET-005 |
| Projects 4, 5 | File hashing and integrity concepts |
| Project 20 | `subprocess` pattern for reading system state |
| Project 21 | IOC matching for PROC-001 |
| Project 22 | Detection rule framework |
| Project 23 | LaunchAgent scanning for PROC-002 |
| Project 25 | Report structure, severity scoring, remediation guidance |

## 📖 Key Terms

- **Security baseline** — documented set of required security configurations
- **CIS Benchmark** — industry-standard hardening guide (Centre for Internet Security)
- **Hardening** — reducing a system's attack surface by disabling/restricting unnecessary features
- **Compliance score** — quantified measure of how well a system meets its baseline
- **FileVault** — Mac full-disk encryption — protects data if device is stolen
- **SIP (System Integrity Protection)** — prevents modification of critical macOS files
- **Gatekeeper** — Mac feature verifying apps are from identified developers
- **Auto-login** — logging in without a password — significant physical security risk
- **World-writable** — file/directory anyone can write to — dangerous on shared systems
- **Sticky bit** — on directories, prevents users deleting files owned by others
- **SOC 2 / ISO 27001 / PCI DSS** — compliance frameworks that require hardened baselines

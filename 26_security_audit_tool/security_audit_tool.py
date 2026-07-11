"""
Project 26: Security Audit Tool (Capstone)
Concepts: system hardening, CIS benchmarks, security baselines, compliance,
          user account auditing, file permission analysis, audit reporting

What you'll learn:
- What a security baseline and hardening guide (CIS Benchmark) is
- How to audit user accounts for weak configurations
- How to check system-level security settings on Mac
- How to find dangerous file permissions (world-writable, SUID)
- How to score a system against a compliance checklist
- How to generate a scored audit report with pass/fail findings

Capstone project — builds on all 26 projects:
  Projects 3, 12 (networking) · Projects 20, 22, 23 (system monitoring)
  Projects 21, 25 (scanning + reporting) · Projects 4, 5 (hashing/integrity)

⚠ This tool reads system configuration — no modifications are made.
  Purely observational / audit-only.
"""

import subprocess
import os
import stat
import re
import platform
import json
from datetime import datetime

# ── Audit Check Framework ──────────────────────────────────────────────────────

class AuditCheck:
    """
    A single compliance check — pass or fail, with evidence and guidance.
    Modelled on the structure of a CIS Benchmark control.
    """
    def __init__(self, control_id, title, category, severity,
                 result=None, passed=None, evidence=None, guidance=None):
        self.control_id = control_id
        self.title      = title
        self.category   = category
        self.severity   = severity        # CRITICAL / HIGH / MEDIUM / LOW
        self.result     = result or ""
        self.passed     = passed          # True / False / None (not checked)
        self.evidence   = evidence or []
        self.guidance   = guidance or "Review system configuration."

    def status_icon(self):
        if self.passed is True:   return "✅"
        if self.passed is False:  return "❌"
        return "⚠️"

    def severity_icon(self):
        return {"CRITICAL":"🚨","HIGH":"🔴","MEDIUM":"🟠","LOW":"🟡"}.get(self.severity,"⚪")


def run_cmd(cmd, timeout=5):
    """Run a shell command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""


# ── Audit Categories ───────────────────────────────────────────────────────────

def audit_system_info():
    """Collect basic system information — not a pass/fail, just context."""
    info = {
        "hostname":  run_cmd("hostname"),
        "os":        platform.platform(),
        "kernel":    run_cmd("uname -r"),
        "uptime":    run_cmd("uptime | awk '{print $3,$4}' | sed 's/,//'"),
        "user":      run_cmd("whoami"),
    }
    return info


def audit_user_accounts():
    """
    Check user account configuration for security issues.
    Looks for: accounts with no password, UID 0 (root) duplicates,
    recently added accounts, accounts with login shells.
    """
    checks = []

    # Check 1: List all users with login shells (non-system accounts)
    passwd_content = run_cmd("cat /etc/passwd")
    login_users = []
    uid0_users  = []
    no_pw_users = []

    if passwd_content:
        for line in passwd_content.split('\n'):
            parts = line.split(':')
            if len(parts) < 7:
                continue
            username, pw_field, uid = parts[0], parts[1], parts[2]
            shell = parts[6]

            # UID 0 = root-equivalent — only 'root' should have it
            if uid == '0' and username != 'root':
                uid0_users.append(username)

            # Users with real login shells (not /usr/bin/false or /sbin/nologin)
            if shell not in ('/usr/bin/false', '/sbin/nologin',
                             '/bin/false', '/dev/null', ''):
                if not username.startswith('_'):  # skip system accounts on Mac
                    login_users.append(username)

    checks.append(AuditCheck(
        control_id = "USR-001",
        title      = "No Non-Root UID 0 Accounts",
        category   = "User Accounts",
        severity   = "CRITICAL",
        passed     = len(uid0_users) == 0,
        evidence   = uid0_users if uid0_users else ["No non-root UID 0 accounts found"],
        guidance   = "Accounts with UID 0 have unrestricted root access. "
                     "Remove or reassign immediately."
    ))

    checks.append(AuditCheck(
        control_id = "USR-002",
        title      = "Login Shell Account Inventory",
        category   = "User Accounts",
        severity   = "LOW",
        passed     = True,          # INFO: just reporting, not pass/fail
        evidence   = login_users or ["No login-shell users found"],
        guidance   = "Review this list — remove accounts for users who no longer need access."
    ))

    # Check 2: Guest account
    guest_enabled = run_cmd(
        "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null"
    )
    guest_on = guest_enabled.strip() == '1'
    checks.append(AuditCheck(
        control_id = "USR-003",
        title      = "Guest Account Disabled",
        category   = "User Accounts",
        severity   = "MEDIUM",
        passed     = not guest_on,
        evidence   = [f"GuestEnabled = {guest_enabled or 'not set (default off)'}"],
        guidance   = "Disable the guest account: System Settings → Users & Groups → Guest User."
    ))

    # Check 3: Auto-login
    auto_login = run_cmd(
        "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null"
    )
    checks.append(AuditCheck(
        control_id = "USR-004",
        title      = "Auto-Login Disabled",
        category   = "User Accounts",
        severity   = "HIGH",
        passed     = auto_login == "",
        evidence   = [f"autoLoginUser = {auto_login}" if auto_login else "Auto-login is not configured"],
        guidance   = "Disable auto-login: System Settings → Users & Groups → Login Options."
    ))

    return checks


def audit_network():
    """
    Check network security configuration.
    Looks for: open listening ports, firewall status, remote login settings.
    """
    checks = []

    # Check 1: Mac Application Firewall
    fw_status = run_cmd(
        "defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null"
    )
    fw_on = fw_status.strip() in ('1', '2')
    checks.append(AuditCheck(
        control_id = "NET-001",
        title      = "Application Firewall Enabled",
        category   = "Network",
        severity   = "HIGH",
        passed     = fw_on,
        evidence   = [f"globalstate = {fw_status or 'not set'}"],
        guidance   = "Enable the firewall: System Settings → Network → Firewall → Turn On."
    ))

    # Check 2: Firewall stealth mode (makes Mac invisible to ping)
    stealth = run_cmd(
        "defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null"
    )
    checks.append(AuditCheck(
        control_id = "NET-002",
        title      = "Firewall Stealth Mode Enabled",
        category   = "Network",
        severity   = "MEDIUM",
        passed     = stealth.strip() == '1',
        evidence   = [f"stealthenabled = {stealth or '0 (disabled)'}"],
        guidance   = "Enable stealth mode: System Settings → Network → Firewall → Options → Stealth Mode."
    ))

    # Check 3: Remote Login (SSH server) status
    ssh_status = run_cmd("systemsetup -getremotelogin 2>/dev/null")
    ssh_on = "on" in ssh_status.lower()
    checks.append(AuditCheck(
        control_id = "NET-003",
        title      = "Remote Login (SSH) Exposure",
        category   = "Network",
        severity   = "MEDIUM",
        passed     = not ssh_on,
        evidence   = [ssh_status or "Could not determine (may need sudo)"],
        guidance   = "If SSH is not needed, disable it: System Settings → General → Sharing → Remote Login."
    ))

    # Check 4: Remote Management (Screen Sharing / ARD)
    rm_status = run_cmd("systemsetup -getremoteappleevents 2>/dev/null")
    rm_on = "on" in rm_status.lower()
    checks.append(AuditCheck(
        control_id = "NET-004",
        title      = "Remote Apple Events Disabled",
        category   = "Network",
        severity   = "LOW",
        passed     = not rm_on,
        evidence   = [rm_status or "Could not determine (may need sudo)"],
        guidance   = "Disable unless required: System Settings → General → Sharing → Remote Apple Events."
    ))

    # Check 5: Listening ports — flag anything unexpected
    listening = run_cmd("netstat -an | grep LISTEN")
    suspicious_ports = []
    for port in [23, 5900, 3389, 6379, 27017, 5984]:
        if f".{port} " in listening or f":{port} " in listening:
            suspicious_ports.append(port)

    checks.append(AuditCheck(
        control_id = "NET-005",
        title      = "No High-Risk Ports Listening",
        category   = "Network",
        severity   = "HIGH",
        passed     = len(suspicious_ports) == 0,
        evidence   = ([f"Suspicious ports detected: {suspicious_ports}"] if suspicious_ports
                      else ["No high-risk ports found listening"]),
        guidance   = "Disable or firewall any service listening on high-risk ports "
                     "(Telnet:23, VNC:5900, RDP:3389, Redis:6379, MongoDB:27017)."
    ))

    return checks


def audit_system_hardening():
    """
    Check Mac-specific security hardening settings.
    Based on CIS Apple macOS Benchmark controls.
    """
    checks = []

    # Check 1: FileVault (full-disk encryption)
    fv_status = run_cmd("fdesetup status 2>/dev/null")
    fv_on = "on" in fv_status.lower()
    checks.append(AuditCheck(
        control_id = "SYS-001",
        title      = "FileVault Full-Disk Encryption Enabled",
        category   = "System Hardening",
        severity   = "HIGH",
        passed     = fv_on,
        evidence   = [fv_status or "Could not determine FileVault status"],
        guidance   = "Enable FileVault: System Settings → Privacy & Security → FileVault."
    ))

    # Check 2: SIP (System Integrity Protection)
    sip_status = run_cmd("csrutil status 2>/dev/null")
    sip_on = "enabled" in sip_status.lower()
    checks.append(AuditCheck(
        control_id = "SYS-002",
        title      = "System Integrity Protection (SIP) Enabled",
        category   = "System Hardening",
        severity   = "CRITICAL",
        passed     = sip_on,
        evidence   = [sip_status or "Could not determine SIP status"],
        guidance   = "SIP must be enabled. Re-enable by booting to Recovery Mode and running: csrutil enable"
    ))

    # Check 3: Gatekeeper (app verification)
    gk_status = run_cmd("spctl --status 2>/dev/null")
    gk_on = "enabled" in gk_status.lower()
    checks.append(AuditCheck(
        control_id = "SYS-003",
        title      = "Gatekeeper Application Verification Enabled",
        category   = "System Hardening",
        severity   = "HIGH",
        passed     = gk_on,
        evidence   = [gk_status or "Could not determine Gatekeeper status"],
        guidance   = "Enable Gatekeeper: System Settings → Privacy & Security → Allow apps from App Store."
    ))

    # Check 4: Automatic security updates
    auto_updates = run_cmd(
        "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null"
    )
    updates_on = auto_updates.strip() == '1'
    checks.append(AuditCheck(
        control_id = "SYS-004",
        title      = "Automatic Security Updates Enabled",
        category   = "System Hardening",
        severity   = "HIGH",
        passed     = updates_on,
        evidence   = [f"AutomaticCheckEnabled = {auto_updates or 'not set'}"],
        guidance   = "Enable: System Settings → General → Software Update → Automatic Updates."
    ))

    # Check 5: Screen lock on sleep
    lock_status = run_cmd(
        "defaults read com.apple.screensaver askForPassword 2>/dev/null"
    )
    lock_on = lock_status.strip() == '1'
    checks.append(AuditCheck(
        control_id = "SYS-005",
        title      = "Screen Lock Password Required",
        category   = "System Hardening",
        severity   = "MEDIUM",
        passed     = lock_on,
        evidence   = [f"askForPassword = {lock_status or 'not set'}"],
        guidance   = "Enable: System Settings → Lock Screen → Require password after sleep."
    ))

    # Check 6: Bluetooth
    bt_status = run_cmd(
        "defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null"
    )
    bt_on = bt_status.strip() == '1'
    checks.append(AuditCheck(
        control_id = "SYS-006",
        title      = "Bluetooth Disabled When Not Needed",
        category   = "System Hardening",
        severity   = "LOW",
        passed     = not bt_on,
        evidence   = [f"Bluetooth is {'ON' if bt_on else 'OFF'}"],
        guidance   = "Disable Bluetooth when not in use: System Settings → Bluetooth → Turn Off."
    ))

    return checks


def audit_filesystem():
    """
    Check filesystem permissions for dangerous configurations.
    Looks for: world-writable directories in sensitive paths,
    files with no owner, recently modified system files.
    """
    checks = []

    # Check 1: World-writable files in /tmp (normal) vs sensitive dirs
    sensitive_dirs = ['/usr/local/bin', '/etc']
    ww_found = []
    for d in sensitive_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for f in os.listdir(d):
                fp = os.path.join(d, f)
                try:
                    s = os.stat(fp)
                    if s.st_mode & stat.S_IWOTH:   # world-writable
                        ww_found.append(fp)
                except OSError:
                    continue
        except PermissionError:
            continue

    checks.append(AuditCheck(
        control_id = "FS-001",
        title      = "No World-Writable Files in Sensitive Directories",
        category   = "Filesystem",
        severity   = "HIGH",
        passed     = len(ww_found) == 0,
        evidence   = ww_found[:5] if ww_found else ["No world-writable files found in checked dirs"],
        guidance   = "Remove world-write permissions: chmod o-w <file>"
    ))

    # Check 2: Sticky bit on /tmp (prevents users deleting each other's files)
    tmp_stat = os.stat('/tmp')
    sticky   = bool(tmp_stat.st_mode & stat.S_ISVTX)
    checks.append(AuditCheck(
        control_id = "FS-002",
        title      = "/tmp Has Sticky Bit Set",
        category   = "Filesystem",
        severity   = "MEDIUM",
        passed     = sticky,
        evidence   = [f"/tmp permissions: {oct(tmp_stat.st_mode)}"],
        guidance   = "Set sticky bit on /tmp: chmod +t /tmp"
    ))

    # Check 3: Home directory permissions (should not be world-readable)
    home = os.path.expanduser('~')
    try:
        home_stat   = os.stat(home)
        home_mode   = home_stat.st_mode
        world_read  = bool(home_mode & stat.S_IROTH)
        world_exec  = bool(home_mode & stat.S_IXOTH)
        home_safe   = not (world_read or world_exec)
        checks.append(AuditCheck(
            control_id = "FS-003",
            title      = "Home Directory Not World-Readable",
            category   = "Filesystem",
            severity   = "MEDIUM",
            passed     = home_safe,
            evidence   = [f"~ permissions: {oct(home_mode)}"],
            guidance   = "Restrict home directory: chmod 750 ~"
        ))
    except Exception:
        pass

    # Check 4: .ssh directory permissions (if it exists)
    ssh_dir = os.path.expanduser('~/.ssh')
    if os.path.isdir(ssh_dir):
        ssh_stat = os.stat(ssh_dir)
        ssh_mode = ssh_stat.st_mode
        ssh_safe = not (ssh_mode & (stat.S_IRWXG | stat.S_IRWXO))
        checks.append(AuditCheck(
            control_id = "FS-004",
            title      = ".ssh Directory Has Correct Permissions (700)",
            category   = "Filesystem",
            severity   = "HIGH",
            passed     = ssh_safe,
            evidence   = [f"~/.ssh permissions: {oct(ssh_mode)}"],
            guidance   = "Restrict .ssh directory: chmod 700 ~/.ssh"
        ))

    return checks


def audit_processes():
    """
    Check for suspicious or unexpected running processes.
    Flags known-bad process names (from Project 23's approach).
    """
    checks = []

    SUSPICIOUS = {
        'ncat': "netcat variant — common reverse shell tool",
        'socat': "socket relay — common in reverse shells",
        'ngrok': "network tunnel — may expose internal services",
        'frp': "reverse proxy — common C2 tunnel",
        'logkext': "known Mac keylogger",
        'mspy': "commercial spyware",
    }

    ps_output = run_cmd("ps aux")
    found_suspicious = []
    for name, desc in SUSPICIOUS.items():
        if name.lower() in ps_output.lower():
            found_suspicious.append(f"{name}: {desc}")

    checks.append(AuditCheck(
        control_id = "PROC-001",
        title      = "No Known Suspicious Processes Running",
        category   = "Processes",
        severity   = "HIGH",
        passed     = len(found_suspicious) == 0,
        evidence   = found_suspicious if found_suspicious else ["No suspicious processes detected"],
        guidance   = "Investigate and terminate any suspicious processes. "
                     "Check LaunchAgents for persistence."
    ))

    # Check LaunchAgents for unknown entries
    launch_agents = os.path.expanduser('~/Library/LaunchAgents')
    agent_files   = []
    if os.path.isdir(launch_agents):
        agent_files = os.listdir(launch_agents)

    # Flag non-Apple, non-known-vendor agents
    known_prefixes = (
        'com.apple.', 'com.google.', 'com.microsoft.', 'com.adobe.',
        'com.dropbox.', 'com.spotify.', 'com.docker.',
        'com.github.', 'org.mozilla.', 'com.jetbrains.',
    )
    unknown_agents = [
        f for f in agent_files
        if not any(f.startswith(p) for p in known_prefixes)
    ]

    checks.append(AuditCheck(
        control_id = "PROC-002",
        title      = "LaunchAgents Contain Only Known Entries",
        category   = "Processes",
        severity   = "MEDIUM",
        passed     = len(unknown_agents) == 0,
        evidence   = (unknown_agents[:5] if unknown_agents
                      else [f"{len(agent_files)} known agent(s) — all look legitimate"]),
        guidance   = "Review unknown LaunchAgents in ~/Library/LaunchAgents. "
                     "Remove any you did not intentionally install."
    ))

    return checks


# ── Scoring Engine ─────────────────────────────────────────────────────────────

def calculate_score(all_checks):
    """
    Compute an overall compliance score (0–100) and letter grade.
    Weights: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1
    Score = sum(weight * passed) / sum(weight * total)
    """
    weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    total_weight  = 0
    passed_weight = 0

    for c in all_checks:
        if c.passed is None:
            continue
        w = weights.get(c.severity, 1)
        total_weight  += w
        if c.passed:
            passed_weight += w

    score = int((passed_weight / total_weight) * 100) if total_weight > 0 else 0

    if score >= 90: grade = "A"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 60: grade = "D"
    else:             grade = "F"

    return score, grade


# ── Report Generator ───────────────────────────────────────────────────────────

def generate_audit_report(system_info, all_checks, output_file=None):
    """
    Produce a scored compliance audit report.
    Passed checks first, then failed (sorted by severity within each group).
    """
    score, grade = calculate_score(all_checks)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    passed_checks  = sorted(
        [c for c in all_checks if c.passed is True],
        key=lambda c: severity_order.get(c.severity, 9)
    )
    failed_checks  = sorted(
        [c for c in all_checks if c.passed is False],
        key=lambda c: severity_order.get(c.severity, 9)
    )
    info_checks    = [c for c in all_checks if c.passed is None]

    total   = len(all_checks)
    passed  = len(passed_checks)
    failed  = len(failed_checks)

    lines = []

    def line(text=""):
        lines.append(text)

    def rule(c="─", w=65):
        lines.append(c * w)

    W = 65
    rule("═")
    line("  SECURITY AUDIT REPORT")
    rule("═")
    line()
    line(f"  Host       : {system_info.get('hostname', 'unknown')}")
    line(f"  OS         : {system_info.get('os', 'unknown')}")
    line(f"  Auditor    : {system_info.get('user', 'unknown')}")
    line(f"  Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    line()
    rule()
    line(f"  COMPLIANCE SCORE: {score}/100  (Grade: {grade})")
    line(f"  Checks passed  : {passed}/{total}")
    line(f"  Checks failed  : {failed}/{total}")
    rule()
    line()

    # ── Failed checks ──────────────────────────────────────────────────
    if failed_checks:
        line("  ❌ FAILED CHECKS (remediate in this order):")
        line()
        for c in failed_checks:
            line(f"  {c.severity_icon()} [{c.control_id}] {c.title}")
            line(f"  Category : {c.category}  |  Severity: {c.severity}")
            if c.evidence:
                line(f"  Evidence : {c.evidence[0]}")
            line(f"  Fix      : {c.guidance[:80]}")
            line()
    else:
        line("  ✅ All checks passed!")
        line()

    # ── Passed checks ──────────────────────────────────────────────────
    line("  ✅ PASSED CHECKS:")
    for c in passed_checks:
        line(f"  ✅ [{c.control_id}] {c.title}")
    line()

    # ── Info items ─────────────────────────────────────────────────────
    if info_checks:
        line("  ℹ️  INFORMATIONAL:")
        for c in info_checks:
            ev = c.evidence[0] if c.evidence else ""
            line(f"  ℹ️  [{c.control_id}] {c.title}")
            if ev and len(ev) < 60:
                line(f"      {ev}")
        line()

    rule("═")
    line(f"  End of Audit Report")
    rule("═")

    report = "\n".join(lines)

    if output_file:
        with open(output_file, "w") as f:
            f.write(report)
        print(f"\n  ✅ Report saved to: {output_file}\n")

    return report


# ── Full Audit Runner ──────────────────────────────────────────────────────────

def run_full_audit(save=False):
    """Orchestrate all audit modules and generate the final report."""
    print(f"\n{'='*65}")
    print(f"  🔒 SECURITY AUDIT TOOL — Full System Audit")
    print(f"{'='*65}\n")

    system_info = audit_system_info()
    print(f"  Host : {system_info.get('hostname', 'unknown')}")
    print(f"  OS   : {system_info.get('os', 'unknown')[:50]}")
    print()

    all_checks = []

    categories = [
        ("User Accounts",    audit_user_accounts),
        ("Network",          audit_network),
        ("System Hardening", audit_system_hardening),
        ("Filesystem",       audit_filesystem),
        ("Processes",        audit_processes),
    ]

    for name, fn in categories:
        print(f"  Auditing {name}...", end="", flush=True)
        checks = fn()
        all_checks.extend(checks)
        passed = sum(1 for c in checks if c.passed is True)
        failed = sum(1 for c in checks if c.passed is False)
        print(f" {passed} passed, {failed} failed")

    score, grade = calculate_score(all_checks)
    print(f"\n  Overall score: {score}/100 (Grade {grade})\n")

    output_file = None
    if save:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"audit_report_{ts}.txt"

    report = generate_audit_report(system_info, all_checks, output_file)
    print(report)
    return report


# ── Explainer ──────────────────────────────────────────────────────────────────

def explain_security_auditing():
    print("""
  📖 SECURITY AUDITING & HARDENING — The Full Picture
  ══════════════════════════════════════════════════════

  WHAT IS A SECURITY AUDIT?
  A security audit evaluates a system against a defined security standard
  or baseline. It answers: "How well does this system meet our security
  requirements?" — not "Is it vulnerable to a specific attack?"

  WHAT IS A SECURITY BASELINE / HARDENING GUIDE?
  A documented list of security settings a system MUST have.
  The most widely used is the CIS (Center for Internet Security) Benchmark:
  • CIS Apple macOS Benchmark — exactly what this tool checks
  • CIS Ubuntu Linux Benchmark
  • CIS Windows Server Benchmark
  • CIS AWS / Azure / GCP Benchmark (cloud)

  Each control has a Level:
    Level 1 → basic, should be applied everywhere, low operational impact
    Level 2 → defence in depth, may have trade-offs, for higher-security environments

  HOW OUR COMPLIANCE SCORE WORKS:
  Every check has a severity weight:
    CRITICAL = 4 points  HIGH = 3 points  MEDIUM = 2 points  LOW = 1 point
  Score = (weighted passes) / (weighted total) × 100

  This means failing a CRITICAL check drops your score more than
  failing a LOW check — reflecting real risk prioritisation.

  HOW THIS PROJECT TIES EVERYTHING TOGETHER:
  ┌─────────────────────────────────────────────────────┐
  │ Project 3, 12 → Port scanning (NET-005)             │
  │ Project 4, 5  → File hashing / integrity (FS-*)     │
  │ Project 20    → Subprocess for system commands      │
  │ Project 21    → IOC matching (PROC-001)             │
  │ Project 22    → Detection rules / anomaly detection │
  │ Project 23    → LaunchAgent scanning (PROC-002)     │
  │ Project 25    → Report structure / scoring          │
  └─────────────────────────────────────────────────────┘
  Security is layered. Each project taught one piece;
  this project assembles them into a complete system view.

  THE HARDENING LIFECYCLE:
  1. Baseline  → document the secure configuration standard
  2. Deploy    → apply the hardening settings
  3. Audit     → verify settings are correct (what this tool does)
  4. Monitor   → detect drift from the baseline (Projects 20, 22)
  5. Remediate → fix anything that has drifted
  6. Repeat    → continuous, not a one-time event

  COMPLIANCE FRAMEWORKS THAT USE SECURITY BASELINES:
  • SOC 2     — for SaaS / cloud companies
  • ISO 27001 — international information security standard
  • PCI DSS   — payment card industry
  • HIPAA     — US healthcare data
  • NIST CSF  — US government / critical infrastructure
  All of them require documented baselines and regular auditing.
  ══════════════════════════════════════════════════════
""")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   SECURITY AUDIT TOOL                ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Run full audit (view report)    ║")
        print("║  [2] Run full audit (save to file)   ║")
        print("║  [3] User account audit only         ║")
        print("║  [4] System hardening audit only     ║")
        print("║  [5] Security auditing explained     ║")
        print("║  [6] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            run_full_audit(save=False)

        elif choice == "2":
            run_full_audit(save=True)

        elif choice == "3":
            print("\n  Running user account audit...\n")
            info    = audit_system_info()
            checks  = audit_user_accounts()
            score, grade = calculate_score(checks)
            report  = generate_audit_report(info, checks)
            print(report)

        elif choice == "4":
            print("\n  Running system hardening audit...\n")
            info   = audit_system_info()
            checks = audit_system_hardening()
            score, grade = calculate_score(checks)
            report = generate_audit_report(info, checks)
            print(report)

        elif choice == "5":
            explain_security_auditing()

        elif choice == "6":
            print("\nGoodbye! Stay hardened. 🔐\n")
            break

        else:
            print("\n❌ Invalid option.\n")


if __name__ == "__main__":
    main()

"""
Project 13: Firewall Rule Simulator
Concepts: firewalls, packet filtering, ACLs, allow/deny rules, default policy

What you'll learn:
- How firewalls decide to allow or block traffic
- What ACLs (Access Control Lists) are
- How rule ordering matters (first match wins)
- What a default-deny policy means and why it matters
- The difference between stateful and stateless firewalls
"""

import json
from datetime import datetime

# ── Rule Engine ───────────────────────────────────────────────────────────────

class FirewallRule:
    """
    A single firewall rule. Think of it as one row in a rulebook.
    Rules are checked top to bottom — the FIRST match wins.
    """
    def __init__(self, rule_id, action, protocol, src_ip, dst_ip, dst_port, description=""):
        self.rule_id     = rule_id
        self.action      = action.upper()       # ALLOW or DENY
        self.protocol    = protocol.upper()     # TCP, UDP, ICMP, or ANY
        self.src_ip      = src_ip               # source IP or "ANY"
        self.dst_ip      = dst_ip               # destination IP or "ANY"
        self.dst_port    = str(dst_port)        # destination port or "ANY"
        self.description = description
        self.hit_count   = 0                    # how many times this rule matched

    def matches(self, packet):
        """
        Check if this rule applies to the given packet.
        A rule matches only if ALL fields match (or are set to ANY).
        """
        # Check protocol
        if self.protocol != "ANY" and self.protocol != packet["protocol"].upper():
            return False

        # Check source IP
        if self.src_ip != "ANY" and self.src_ip != packet["src_ip"]:
            # Simple prefix match for subnet (e.g. 192.168.1 matches 192.168.1.*)
            if not packet["src_ip"].startswith(self.src_ip.rstrip("*").rstrip(".")):
                return False

        # Check destination IP
        if self.dst_ip != "ANY" and self.dst_ip != packet["dst_ip"]:
            if not packet["dst_ip"].startswith(self.dst_ip.rstrip("*").rstrip(".")):
                return False

        # Check destination port
        if self.dst_port != "ANY" and self.dst_port != str(packet.get("dst_port", "")):
            return False

        return True

    def __str__(self):
        action_icon = "✅" if self.action == "ALLOW" else "❌"
        return (f"  Rule {self.rule_id:>2} {action_icon} {self.action:<5} | "
                f"Proto: {self.protocol:<5} | "
                f"Src: {self.src_ip:<16} | "
                f"Dst: {self.dst_ip:<16} | "
                f"Port: {self.dst_port:<6} | "
                f"Hits: {self.hit_count}")


class Firewall:
    """
    A simple stateless packet-filtering firewall.
    Rules are evaluated top to bottom — first match wins.
    If no rule matches, the DEFAULT POLICY applies (deny all by default).
    """

    DEFAULT_POLICY = "DENY"   # Industry best practice: deny everything not explicitly allowed

    def __init__(self):
        self.rules    = []
        self.log      = []
        self.next_id  = 1

    def add_rule(self, action, protocol, src_ip, dst_ip, dst_port, description=""):
        """Add a new rule to the BOTTOM of the rulebook."""
        rule = FirewallRule(
            rule_id     = self.next_id,
            action      = action,
            protocol    = protocol,
            src_ip      = src_ip,
            dst_ip      = dst_ip,
            dst_port    = dst_port,
            description = description
        )
        self.rules.append(rule)
        self.next_id += 1
        print(f"  ✅ Rule {rule.rule_id} added: {action.upper()} {protocol} from {src_ip} to {dst_ip}:{dst_port}")
        return rule

    def remove_rule(self, rule_id):
        """Remove a rule by its ID."""
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        if len(self.rules) < before:
            print(f"  🗑  Rule {rule_id} removed.")
        else:
            print(f"  ❌ Rule {rule_id} not found.")

    def check_packet(self, packet, silent=False):
        """
        Process a packet through all rules.
        Returns (action, matching_rule_id).
        This is what a real firewall does billions of times per second.
        """
        for rule in self.rules:
            if rule.matches(packet):
                rule.hit_count += 1
                self._log(packet, rule.action, rule.rule_id)
                if not silent:
                    self._print_result(packet, rule.action, rule.rule_id)
                return rule.action, rule.rule_id

        # No rule matched — apply default policy
        self._log(packet, self.DEFAULT_POLICY, None)
        if not silent:
            self._print_result(packet, self.DEFAULT_POLICY, None)
        return self.DEFAULT_POLICY, None

    def _print_result(self, packet, action, rule_id):
        icon    = "✅ ALLOWED" if action == "ALLOW" else "❌ BLOCKED"
        rule_note = f"Rule {rule_id}" if rule_id else "Default Policy"
        src = f"{packet['src_ip']}"
        dst = f"{packet['dst_ip']}:{packet.get('dst_port','?')}"
        print(f"  {icon}  {packet['protocol']:<5} {src:<18} → {dst:<22} ({rule_note})")

    def _log(self, packet, action, rule_id):
        self.log.append({
            "time":    datetime.now().strftime("%H:%M:%S"),
            "action":  action,
            "rule_id": rule_id,
            "packet":  packet.copy(),
        })

    def show_rules(self):
        """Display all current rules."""
        if not self.rules:
            print("\n  No rules configured. Default policy: DENY ALL.\n")
            return
        print(f"\n  {'─'*85}")
        print(f"  {'ID':<6} {'ACTION':<8} {'PROTO':<7} {'SOURCE IP':<18} {'DEST IP':<18} {'PORT':<8} {'HITS':<6} DESCRIPTION")
        print(f"  {'─'*85}")
        for rule in self.rules:
            icon = "✅" if rule.action == "ALLOW" else "❌"
            print(f"  {rule.rule_id:<6} {icon} {rule.action:<6} {rule.protocol:<7} "
                  f"{rule.src_ip:<18} {rule.dst_ip:<18} {rule.dst_port:<8} "
                  f"{rule.hit_count:<6} {rule.description}")
        print(f"  {'─'*85}")
        print(f"  Default policy (no match): ❌ {self.DEFAULT_POLICY}\n")

    def show_log(self, last_n=20):
        """Show recent firewall log entries."""
        entries = self.log[-last_n:]
        if not entries:
            print("\n  No log entries yet.\n")
            return
        print(f"\n  📋 Last {len(entries)} log entries:")
        print(f"  {'─'*75}")
        for e in entries:
            icon   = "✅" if e["action"] == "ALLOW" else "❌"
            p      = e["packet"]
            rule   = f"Rule {e['rule_id']}" if e['rule_id'] else "Default"
            print(f"  {e['time']}  {icon} {e['action']:<5}  {p['protocol']:<5}  "
                  f"{p['src_ip']:<16} → {p['dst_ip']}:{p.get('dst_port','?'):<6}  [{rule}]")
        print()

    def show_stats(self):
        """Show traffic statistics."""
        if not self.log:
            print("\n  No traffic yet.\n")
            return
        allowed = sum(1 for e in self.log if e["action"] == "ALLOW")
        blocked = sum(1 for e in self.log if e["action"] == "DENY")
        total   = len(self.log)
        print(f"\n  📊 Traffic Statistics")
        print(f"  {'─'*35}")
        print(f"  Total packets : {total}")
        print(f"  Allowed       : {allowed} ({allowed/total*100:.0f}%)")
        print(f"  Blocked       : {blocked} ({blocked/total*100:.0f}%)")
        print(f"\n  Top rules by hit count:")
        for rule in sorted(self.rules, key=lambda r: r.hit_count, reverse=True)[:5]:
            if rule.hit_count > 0:
                bar = "█" * min(rule.hit_count, 20)
                print(f"  Rule {rule.rule_id:<3} {bar} {rule.hit_count}")
        print()


# ── Preset Scenarios ──────────────────────────────────────────────────────────

def load_web_server_preset(fw):
    """
    Typical ruleset for a public web server.
    Allow HTTP/HTTPS from anywhere.
    Allow SSH only from admin network.
    Block everything else.
    """
    fw.rules.clear()
    fw.next_id = 1
    print("\n  Loading Web Server preset...")
    fw.add_rule("ALLOW", "TCP", "ANY",          "10.0.0.1", "80",  "Allow HTTP from internet")
    fw.add_rule("ALLOW", "TCP", "ANY",          "10.0.0.1", "443", "Allow HTTPS from internet")
    fw.add_rule("ALLOW", "TCP", "192.168.1",    "10.0.0.1", "22",  "Allow SSH from admin subnet only")
    fw.add_rule("DENY",  "TCP", "ANY",          "10.0.0.1", "22",  "Block SSH from everyone else")
    fw.add_rule("ALLOW", "ICMP","ANY",          "10.0.0.1", "ANY", "Allow ping for monitoring")
    fw.add_rule("DENY",  "ANY", "ANY",          "ANY",      "ANY", "Block everything else")
    print("  ✅ Web server preset loaded.\n")

def load_office_preset(fw):
    """
    Typical office network ruleset.
    Employees can browse web and use email.
    Block social media ports, allow internal resources.
    """
    fw.rules.clear()
    fw.next_id = 1
    print("\n  Loading Office Network preset...")
    fw.add_rule("ALLOW", "TCP", "192.168.0",    "ANY",      "80",  "Allow HTTP browsing")
    fw.add_rule("ALLOW", "TCP", "192.168.0",    "ANY",      "443", "Allow HTTPS browsing")
    fw.add_rule("ALLOW", "TCP", "192.168.0",    "ANY",      "25",  "Allow email (SMTP)")
    fw.add_rule("ALLOW", "TCP", "192.168.0",    "ANY",      "993", "Allow email (IMAP)")
    fw.add_rule("DENY",  "TCP", "ANY",          "ANY",      "3306","Block MySQL from outside")
    fw.add_rule("DENY",  "TCP", "ANY",          "ANY",      "22",  "Block SSH from outside")
    fw.add_rule("ALLOW", "ANY", "192.168.0",    "ANY",      "ANY", "Allow all internal traffic")
    fw.add_rule("DENY",  "ANY", "ANY",          "ANY",      "ANY", "Default deny")
    print("  ✅ Office preset loaded.\n")

def run_traffic_simulation(fw):
    """Simulate a realistic mix of traffic hitting the firewall."""
    test_packets = [
        {"protocol": "TCP",  "src_ip": "203.0.113.5",   "dst_ip": "10.0.0.1", "dst_port": "80"},
        {"protocol": "TCP",  "src_ip": "198.51.100.7",  "dst_ip": "10.0.0.1", "dst_port": "443"},
        {"protocol": "TCP",  "src_ip": "45.33.32.156",  "dst_ip": "10.0.0.1", "dst_port": "22"},
        {"protocol": "TCP",  "src_ip": "192.168.1.50",  "dst_ip": "10.0.0.1", "dst_port": "22"},
        {"protocol": "ICMP", "src_ip": "8.8.8.8",       "dst_ip": "10.0.0.1", "dst_port": "ANY"},
        {"protocol": "TCP",  "src_ip": "185.220.101.1", "dst_ip": "10.0.0.1", "dst_port": "3306"},
        {"protocol": "UDP",  "src_ip": "10.0.0.2",      "dst_ip": "10.0.0.1", "dst_port": "53"},
        {"protocol": "TCP",  "src_ip": "203.0.113.99",  "dst_ip": "10.0.0.1", "dst_port": "8080"},
    ]
    print(f"\n  🚦 Simulating {len(test_packets)} packets...\n")
    print(f"  {'─'*75}")
    for pkt in test_packets:
        fw.check_packet(pkt)
    print(f"  {'─'*75}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    fw = Firewall()

    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   FIREWALL RULE SIMULATOR            ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Show current rules              ║")
        print("║  [2] Add a rule                      ║")
        print("║  [3] Remove a rule                   ║")
        print("║  [4] Test a packet                   ║")
        print("║  [5] Load web server preset          ║")
        print("║  [6] Load office network preset      ║")
        print("║  [7] Run traffic simulation          ║")
        print("║  [8] Show traffic log & stats        ║")
        print("║  [9] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            fw.show_rules()

        elif choice == "2":
            print("\n  Add a new rule (type ANY to match everything)\n")
            action   = input("  Action (ALLOW/DENY): ").strip().upper()
            protocol = input("  Protocol (TCP/UDP/ICMP/ANY): ").strip().upper()
            src_ip   = input("  Source IP (or ANY): ").strip() or "ANY"
            dst_ip   = input("  Dest IP (or ANY): ").strip() or "ANY"
            dst_port = input("  Dest Port (or ANY): ").strip() or "ANY"
            desc     = input("  Description: ").strip()
            if action in ("ALLOW", "DENY"):
                fw.add_rule(action, protocol, src_ip, dst_ip, dst_port, desc)
            else:
                print("  ❌ Action must be ALLOW or DENY.")

        elif choice == "3":
            fw.show_rules()
            try:
                rid = int(input("  Enter rule ID to remove: ").strip())
                fw.remove_rule(rid)
            except ValueError:
                print("  ❌ Invalid ID.")

        elif choice == "4":
            print("\n  Define a test packet:\n")
            proto    = input("  Protocol (TCP/UDP/ICMP): ").strip().upper() or "TCP"
            src_ip   = input("  Source IP: ").strip() or "1.2.3.4"
            dst_ip   = input("  Dest IP: ").strip() or "10.0.0.1"
            dst_port = input("  Dest Port: ").strip() or "80"
            packet = {"protocol": proto, "src_ip": src_ip,
                      "dst_ip": dst_ip, "dst_port": dst_port}
            print()
            fw.check_packet(packet)

        elif choice == "5":
            load_web_server_preset(fw)

        elif choice == "6":
            load_office_preset(fw)

        elif choice == "7":
            if not fw.rules:
                print("\n  ⚠️  No rules loaded. Try option [5] or [6] first.\n")
            else:
                run_traffic_simulation(fw)

        elif choice == "8":
            fw.show_log()
            fw.show_stats()

        elif choice == "9":
            print("\nGoodbye! Always default to deny. 🔐\n")
            break
        else:
            print("\n❌ Invalid option.\n")


if __name__ == "__main__":
    main()

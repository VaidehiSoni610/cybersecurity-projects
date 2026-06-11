"""
Project 7: Brute Force Login Simulator
Concepts: brute force attacks, account lockout, rate limiting, password policies
"""
import hashlib, time
from datetime import datetime

def make_hash(p): return hashlib.sha256(p.encode()).hexdigest()

USER_DATABASE = {
    "alice":   make_hash("sunshine"),
    "bob":     make_hash("qwerty123"),
    "charlie": make_hash("dragon"),
    "admin":   make_hash("admin123"),
}

WORDLIST = ["password","123456","password123","admin","letmein","qwerty","abc123",
    "monkey","dragon","sunshine","iloveyou","welcome","admin123","login","master",
    "hello","shadow","qwerty123","1234567","princess","football","baseball"]

class LoginSystem:
    MAX_ATTEMPTS = 5
    LOCKOUT_TIME = 30

    def __init__(self, enforce_lockout=True):
        self.failed   = {}
        self.locked   = {}
        self.enforce  = enforce_lockout

    def attempt(self, username, password, silent=False):
        now = time.time()
        if self.enforce and self.locked.get(username, 0) > now:
            remaining = int(self.locked[username] - now)
            if not silent: print(f"  🔒 Locked — {remaining}s remaining")
            return False, "LOCKED"
        if username not in USER_DATABASE:
            return False, "Unknown user"
        if make_hash(password) == USER_DATABASE[username]:
            self.failed[username] = 0
            if not silent: print("  ✅ Login successful!")
            return True, "SUCCESS"
        self.failed[username] = self.failed.get(username, 0) + 1
        count = self.failed[username]
        if self.enforce and count >= self.MAX_ATTEMPTS:
            self.locked[username] = now + self.LOCKOUT_TIME
            if not silent: print(f"  🔒 Account locked for {self.LOCKOUT_TIME}s!")
            return False, "LOCKED"
        if not silent: print(f"  ❌ Wrong password ({count}/{self.MAX_ATTEMPTS})")
        return False, f"Failure #{count}"

def run_attack(username, system):
    print(f"\n{'='*55}\n  💀 Brute Force Attack on '{username}'\n"
          f"  Lockout: {'Enabled' if system.enforce else 'Disabled'}\n{'='*55}\n")
    start = time.time()
    for i, password in enumerate(WORDLIST, 1):
        print(f"  [{i:>2}/{len(WORDLIST)}] Trying: {password:<20}", end=" ")
        success, msg = system.attempt(username, password, silent=True)
        if success:
            print(f"✅ CRACKED!")
            print(f"\n  🚨 Password cracked: '{password}' in {i} attempts ({time.time()-start:.2f}s)\n")
            return
        elif msg == "LOCKED":
            print(f"🔒 BLOCKED")
            print(f"\n  🛡 Attack stopped by lockout after {i} attempts!\n")
            return
        else:
            print("✗")
    print(f"\n  ❌ Password not in wordlist — strong passwords resist attacks.\n")

def comparison_demo():
    print("\n🔬 Same attack — no lockout vs with lockout\n")
    input("  Press Enter for Attack #1 (NO lockout)...")
    run_attack("charlie", LoginSystem(enforce_lockout=False))
    input("  Press Enter for Attack #2 (WITH lockout)...")
    run_attack("charlie", LoginSystem(enforce_lockout=True))
    print("  📊 Without lockout → unlimited attempts.")
    print("  📊 With lockout    → stopped after 5 failures. 🛡\n")

def show_countermeasures():
    measures = [
        ("Account Lockout", "Lock after N failed attempts"),
        ("Rate Limiting",   "Add delay between login attempts"),
        ("CAPTCHA",         "Humans pass, bots fail"),
        ("MFA",             "Second factor — password alone isn't enough"),
        ("Strong Passwords","Long passwords won't appear in any wordlist"),
        ("IP Blocking",     "Block IPs exceeding failure thresholds"),
    ]
    print("\n🛡  Brute Force Countermeasures:\n")
    for name, desc in measures:
        print(f"  ✅ {name:<20} — {desc}")
    print()

def manual_login():
    print("\n🔐 Manual Login Demo")
    print("  Accounts:", ", ".join(USER_DATABASE.keys()))
    print("  Hint: passwords are common words. You get 5 tries.\n")
    system = LoginSystem(enforce_lockout=True)
    while True:
        u = input("  Username (or 'quit'): ").strip()
        if u.lower() == 'quit': break
        p = input("  Password: ").strip()
        system.attempt(u, p, silent=False)
        print()

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   BRUTE FORCE LOGIN SIMULATOR        ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Run attack  [2] Compare lockout ║")
        print("║  [3] Manual login  [4] Countermeasures║")
        print("║  [5] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")
        choice = input("Choose: ").strip()
        if choice == '1':
            print("Users:", ", ".join(USER_DATABASE.keys()))
            u = input("Target username: ").strip()
            if u not in USER_DATABASE: print("❌ Unknown user."); continue
            lockout = input("Enable lockout? (y/n): ").strip().lower() == 'y'
            run_attack(u, LoginSystem(enforce_lockout=lockout))
        elif choice == '2': comparison_demo()
        elif choice == '3': manual_login()
        elif choice == '4': show_countermeasures()
        elif choice == '5': print("\nGoodbye! Always enable MFA. 🔐\n"); break

if __name__ == "__main__":
    main()

"""
Project 14: Password Manager (Local, Encrypted Vault)
Concepts: key derivation (PBKDF2), salting, master password verification,
          symmetric encryption, secure local storage

What you'll learn:
- How real password managers (1Password, Bitwarden) work under the hood
- What key derivation functions (KDFs) are and why hashing alone isn't enough
- How a single master password can securely protect many other passwords
- Why "key stretching" (many hash rounds) slows down attackers
- The difference between hashing for verification vs encryption for storage

⚠ EDUCATIONAL NOTE: This uses XOR-stream encryption (built on Project 11)
  for learning purposes. Production password managers use AES-256-GCM via
  audited crypto libraries — never hand-roll encryption for real secrets.
"""

import hashlib
import hmac
import os
import json
import base64
import getpass
import secrets
import string
from datetime import datetime

VAULT_FILE = "vault.json"

# ── Key Derivation (PBKDF2) ───────────────────────────────────────────────────

def derive_key(master_password, salt, iterations=200_000, key_length=32):
    """
    Derive an encryption key from the master password using PBKDF2.

    Why not just hash the password once?
    A single SHA-256 hash takes microseconds — attackers can try billions
    per second on GPUs. PBKDF2 deliberately repeats the hash thousands of
    times, making each guess 200,000x slower. This is called KEY STRETCHING.
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        master_password.encode(),
        salt,
        iterations,
        dklen=key_length
    )

def hash_master_password(master_password, salt=None):
    """
    Create a verifiable hash of the master password (for login checks).
    This is SEPARATE from the encryption key — never use the same derived
    value for both verification and encryption.
    """
    if salt is None:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 200_000)
    return pwd_hash, salt

# ── Encryption Layer (built on XOR stream cipher from Project 11) ────────────

def xor_stream(data: bytes, key: bytes) -> bytes:
    """
    Stream-cipher style XOR: repeats the derived key to cover the full
    data length. Same logic you built in Project 11 — XOR is its own inverse.
    """
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def encrypt_entry(plaintext, encryption_key):
    """Encrypt a password entry. Returns base64-encoded ciphertext."""
    ciphertext = xor_stream(plaintext.encode(), encryption_key)
    return base64.b64encode(ciphertext).decode()

def decrypt_entry(ciphertext_b64, encryption_key):
    """Decrypt a base64-encoded ciphertext back to plaintext."""
    ciphertext = base64.b64decode(ciphertext_b64)
    return xor_stream(ciphertext, encryption_key).decode(errors='replace')

# ── Vault Storage ──────────────────────────────────────────────────────────────

def vault_exists():
    return os.path.exists(VAULT_FILE)

def load_vault_file():
    with open(VAULT_FILE, "r") as f:
        return json.load(f)

def save_vault_file(vault_data):
    with open(VAULT_FILE, "w") as f:
        json.dump(vault_data, f, indent=2)

def create_new_vault():
    """First-time setup: create master password and empty vault."""
    print("\n  🆕 No vault found. Let's create one.")
    print("  Choose a strong master password — this is the ONLY password")
    print("  you'll need to remember. Everything else gets encrypted with it.\n")

    while True:
        pwd1 = getpass.getpass("  New master password: ")
        pwd2 = getpass.getpass("  Confirm master password: ")
        if pwd1 != pwd2:
            print("  ❌ Passwords don't match. Try again.\n")
            continue
        if len(pwd1) < 8:
            print("  ⚠️  Password should be at least 8 characters. Try again.\n")
            continue
        break

    pwd_hash, salt = hash_master_password(pwd1)
    vault_data = {
        "master_hash": base64.b64encode(pwd_hash).decode(),
        "salt":        base64.b64encode(salt).decode(),
        "created_at":  datetime.now().isoformat(),
        "entries":     {}
    }
    save_vault_file(vault_data)
    print("\n  ✅ Vault created and locked with your master password.\n")
    return pwd1, vault_data

def unlock_vault():
    """Prompt for master password and verify it against stored hash."""
    vault_data = load_vault_file()
    stored_hash = base64.b64decode(vault_data["master_hash"])
    salt        = base64.b64decode(vault_data["salt"])

    for attempt in range(3):
        entered = getpass.getpass("\n  🔒 Master password: ")
        check_hash, _ = hash_master_password(entered, salt)

        # Constant-time comparison — prevents timing attacks
        if hmac.compare_digest(check_hash, stored_hash):
            print("  ✅ Vault unlocked.\n")
            return entered, vault_data
        else:
            remaining = 2 - attempt
            if remaining > 0:
                print(f"  ❌ Incorrect. {remaining} attempt(s) remaining.")

    print("\n  🔒 Too many failed attempts. Exiting for security.\n")
    return None, None

# ── Password Generator ────────────────────────────────────────────────────────

def generate_password(length=16, use_symbols=True):
    """
    Generate a cryptographically secure random password.
    Uses `secrets` module — NOT `random` — because `random` is predictable
    and unsuitable for anything security-related.
    """
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# ── Vault Operations ──────────────────────────────────────────────────────────

def add_entry(vault_data, encryption_key):
    print("\n  ➕ Add a new password entry")
    site     = input("  Site/Service name (e.g. github.com): ").strip()
    username = input("  Username/Email: ").strip()

    use_gen = input("  Generate a secure password? (y/n): ").strip().lower()
    if use_gen == 'y':
        length = input("  Length (default 16): ").strip()
        length = int(length) if length.isdigit() else 16
        password = generate_password(length)
        print(f"  Generated: {password}")
    else:
        password = getpass.getpass("  Password: ")

    encrypted_pwd = encrypt_entry(password, encryption_key)

    vault_data["entries"][site] = {
        "username":   username,
        "password":   encrypted_pwd,
        "added_at":   datetime.now().isoformat(),
    }
    save_vault_file(vault_data)
    print(f"\n  ✅ Entry for '{site}' saved and encrypted.\n")

def view_entry(vault_data, encryption_key):
    if not vault_data["entries"]:
        print("\n  📭 Vault is empty.\n")
        return
    site = input("\n  Site name to view: ").strip()
    entry = vault_data["entries"].get(site)
    if not entry:
        print(f"  ❌ No entry found for '{site}'.\n")
        return
    decrypted_pwd = decrypt_entry(entry["password"], encryption_key)
    print(f"\n  🔓 {site}")
    print(f"  {'─'*40}")
    print(f"  Username : {entry['username']}")
    print(f"  Password : {decrypted_pwd}")
    print(f"  Added    : {entry['added_at'][:10]}\n")

def list_entries(vault_data):
    entries = vault_data["entries"]
    if not entries:
        print("\n  📭 Vault is empty.\n")
        return
    print(f"\n  🗂  {len(entries)} saved entries:")
    print(f"  {'─'*40}")
    for site, entry in entries.items():
        print(f"  • {site:<25} ({entry['username']})")
    print()

def delete_entry(vault_data):
    list_entries(vault_data)
    if not vault_data["entries"]:
        return
    site = input("  Site name to delete: ").strip()
    if site in vault_data["entries"]:
        del vault_data["entries"][site]
        save_vault_file(vault_data)
        print(f"  🗑  Deleted entry for '{site}'.\n")
    else:
        print(f"  ❌ No entry found for '{site}'.\n")

def explain_security_model():
    print("""
  📖 HOW THIS PASSWORD MANAGER WORKS
  ══════════════════════════════════════════════════════
  1. You set ONE master password.

  2. We NEVER store your master password. Instead we store:
     - A PBKDF2 hash of it (200,000 rounds) → used to VERIFY login
     - A random salt → makes the hash unique even for common passwords

  3. When you unlock the vault, your master password is run through
     PBKDF2 again to derive an ENCRYPTION KEY (separate from the
     verification hash — different purpose, different output).

  4. Every stored password is encrypted using that derived key with
     XOR-stream encryption, then saved to vault.json.

  5. The encryption key only exists in memory while the program runs.
     It's never saved to disk. Close the program → key is gone →
     vault.json is unreadable without re-entering the master password.

  WHY 200,000 PBKDF2 ROUNDS?
  A single guess now takes meaningfully longer to compute. If an attacker
  steals vault.json, they must run 200,000 hash rounds for EVERY password
  guess — turning a billion-guesses-per-second attack into a crawl.

  ⚠️  PRODUCTION NOTE:
  Real password managers (Bitwarden, 1Password) use AES-256-GCM, which
  provides both encryption AND tamper detection. We use XOR here because
  it's what you can build from the standard library and understand fully —
  but never use hand-rolled XOR encryption for real secrets.
  ══════════════════════════════════════════════════════
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n╔══════════════════════════════════════╗")
    print("║   PASSWORD MANAGER                   ║")
    print("║   Cybersecurity Learning Project     ║")
    print("╚══════════════════════════════════════╝")

    if vault_exists():
        master_password, vault_data = unlock_vault()
        if master_password is None:
            return
    else:
        master_password, vault_data = create_new_vault()

    salt = base64.b64decode(vault_data["salt"])
    encryption_key = derive_key(master_password, salt)

    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║  [1] Add entry      [2] View entry   ║")
        print("║  [3] List all       [4] Delete entry ║")
        print("║  [5] Generate password               ║")
        print("║  [6] How this works (security model) ║")
        print("║  [7] Lock vault & exit                ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            add_entry(vault_data, encryption_key)
        elif choice == "2":
            view_entry(vault_data, encryption_key)
        elif choice == "3":
            list_entries(vault_data)
        elif choice == "4":
            delete_entry(vault_data)
        elif choice == "5":
            length = input("\n  Password length (default 16): ").strip()
            length = int(length) if length.isdigit() else 16
            pwd = generate_password(length)
            print(f"  Generated: {pwd}\n")
        elif choice == "6":
            explain_security_model()
        elif choice == "7":
            print("\n  🔒 Vault locked. Goodbye!\n")
            break
        else:
            print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

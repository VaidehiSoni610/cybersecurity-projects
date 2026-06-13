"""
Project 11: XOR Cipher & One-Time Pad
Concepts: binary operations, XOR encryption, stream ciphers, malware obfuscation,
          perfect secrecy, why key reuse is catastrophic

What you'll learn:
- What XOR is and why it's the building block of modern encryption
- How the One-Time Pad achieves perfect secrecy (mathematically unbreakable)
- Why malware uses XOR to hide its code from antivirus
- Why reusing a key destroys security (the "two-time pad" attack)
- How AES, ChaCha20, and other modern ciphers use XOR internally
"""

import os
import random
import string

# ── XOR Core ──────────────────────────────────────────────────────────────────

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    XOR each byte of data with the corresponding byte of key.
    Key repeats if shorter than data (repeating-key XOR).
    This is the EXACT same function used for both encrypt and decrypt —
    XOR is its own inverse: A XOR B XOR B = A
    """
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

def xor_encrypt(plaintext: str, key: str) -> bytes:
    """Encrypt a string using XOR with a text key."""
    return xor_bytes(plaintext.encode(), key.encode())

def xor_decrypt(ciphertext: bytes, key: str) -> str:
    """Decrypt XOR ciphertext back to a string."""
    return xor_bytes(ciphertext, key.encode()).decode(errors='replace')

def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to a readable hex string (like 0x48 0x65 0x6c...)"""
    return ' '.join(f'0x{b:02X}' for b in data)

def bytes_to_binary(data: bytes) -> str:
    """Convert bytes to binary string."""
    return ' '.join(f'{b:08b}' for b in data[:8])  # first 8 bytes only

# ── One-Time Pad ──────────────────────────────────────────────────────────────

def generate_otp_key(length: int) -> bytes:
    """
    Generate a cryptographically random key of given length.
    For a One-Time Pad, key must be:
    1. Truly random
    2. Same length as the message
    3. Used exactly ONCE — never reused
    """
    return os.urandom(length)  # os.urandom uses the OS's cryptographic RNG

def otp_encrypt(plaintext: str) -> tuple:
    """Encrypt using One-Time Pad. Returns (ciphertext_bytes, key_bytes)."""
    data = plaintext.encode()
    key  = generate_otp_key(len(data))
    ct   = xor_bytes(data, key)
    return ct, key

def otp_decrypt(ciphertext: bytes, key: bytes) -> str:
    """Decrypt One-Time Pad ciphertext."""
    return xor_bytes(ciphertext, key).decode(errors='replace')

# ── XOR Demo ──────────────────────────────────────────────────────────────────

def xor_bit_demo():
    """Show exactly how XOR works at the bit level."""
    print("""
  ⚡ HOW XOR WORKS — Bit Level Demo
  ════════════════════════════════════════════════════
  XOR (eXclusive OR) rule:
    Same bits   → 0  (0⊕0=0, 1⊕1=0)
    Different   → 1  (0⊕1=1, 1⊕0=1)

  Example: Encrypt 'H' (ASCII 72) with key 'K' (ASCII 75)

    'H'  = 01001000  (decimal 72)
  ⊕ 'K'  = 01001011  (decimal 75)
    ────────────────
    result= 00000011  (decimal 3)  ← ciphertext byte

  To DECRYPT — XOR with the same key again:
    0x03 = 00000011  (ciphertext)
  ⊕ 'K'  = 01001011  (key)
    ────────────────
    'H'  = 01001000  ← back to original!

  KEY INSIGHT: XOR is its own inverse.
  The SAME operation encrypts AND decrypts. 🔐
  ════════════════════════════════════════════════════
""")

def repeating_key_demo():
    """Demonstrate basic repeating-key XOR encryption."""
    print("\n🔒 REPEATING-KEY XOR ENCRYPTION")
    print("="*55)

    plaintext = input("\n  Enter message to encrypt: ").strip()
    key       = input("  Enter key (any word, e.g. 'SECRET'): ").strip()

    if not plaintext or not key:
        print("  Need both message and key.")
        return

    encrypted = xor_encrypt(plaintext, key)
    decrypted = xor_decrypt(encrypted, key)

    print(f"\n  Plaintext  : {plaintext}")
    print(f"  Key        : {key} (repeats every {len(key)} chars)")
    print(f"\n  Encrypted (hex) : {encrypted.hex()}")
    print(f"  Encrypted (raw) : {bytes_to_hex(encrypted[:10])}{'...' if len(encrypted)>10 else ''}")
    print(f"\n  Decrypted  : {decrypted}")
    print(f"\n  ✅ XOR is its own inverse — same key encrypts AND decrypts.\n")

def otp_demo():
    """Demonstrate the One-Time Pad."""
    print("\n🔐 ONE-TIME PAD (OTP) DEMO")
    print("="*55)
    print("  The OTP is the ONLY cipher with mathematically proven")
    print("  perfect secrecy — impossible to crack even with unlimited")
    print("  computing power, IF used correctly.\n")

    plaintext = input("  Enter message: ").strip()
    if not plaintext:
        return

    ciphertext, key = otp_encrypt(plaintext)
    recovered = otp_decrypt(ciphertext, key)

    print(f"\n  Plaintext  : {plaintext}")
    print(f"  OTP Key    : {key.hex()}")
    print(f"  Ciphertext : {ciphertext.hex()}")
    print(f"  Recovered  : {recovered}")

    print(f"\n  📏 Key length = Message length = {len(plaintext)} bytes")
    print(f"  🎲 Key is randomly generated — never reused")
    print(f"\n  WHY IT'S UNBREAKABLE:")
    print(f"  Without the key, EVERY possible plaintext is equally likely.")
    print(f"  The ciphertext reveals zero information about the message.\n")

def key_reuse_attack():
    """
    Demonstrate why reusing a key completely destroys OTP security.
    The 'two-time pad' attack: if C1 = P1 ⊕ K and C2 = P2 ⊕ K,
    then C1 ⊕ C2 = P1 ⊕ P2 (key cancels out!)
    This is exactly how the Venona project cracked Soviet ciphers.
    """
    print("\n💀 KEY REUSE ATTACK — Why OTP Must Never Be Reused")
    print("="*55)
    print("  Historical fact: The NSA's VENONA project (1943–1980)")
    print("  cracked Soviet spy communications because they reused OTP keys.\n")

    msg1 = "ATTACK AT DAWN"
    msg2 = "RETREAT NORTH "  # padded to same length

    # Use the SAME key for both (this is the mistake!)
    key = os.urandom(len(msg1))

    ct1 = xor_bytes(msg1.encode(), key)
    ct2 = xor_bytes(msg2.encode(), key)

    # Attacker XORs the two ciphertexts together — key cancels out!
    xor_of_ciphertexts = xor_bytes(ct1, ct2)
    xor_of_plaintexts  = xor_bytes(msg1.encode(), msg2.encode())

    print(f"  Message 1   : {msg1}")
    print(f"  Message 2   : {msg2}")
    print(f"  (Both encrypted with the SAME key)\n")
    print(f"  CT1 ⊕ CT2  : {xor_of_ciphertexts.hex()}")
    print(f"  P1 ⊕ P2    : {xor_of_plaintexts.hex()}")
    print(f"\n  They're IDENTICAL! The key completely cancelled out.")
    print(f"  An attacker who intercepts both messages can XOR them")
    print(f"  together and work backwards to recover both plaintexts.")
    print(f"\n  🚨 RULE: A key used more than once is not a One-Time Pad.")
    print(f"     It becomes a 'two-time pad' — and it's completely broken.\n")

def malware_xor_demo():
    """Show how malware uses XOR to hide from antivirus."""
    print("\n🦠 HOW MALWARE USES XOR (Educational Only)")
    print("="*55)
    print("""
  Antivirus software works by scanning files for known
  'signatures' — byte patterns that match known malware.

  Malware authors use XOR to OBFUSCATE (hide) their code:

  ORIGINAL malicious string:
    "This is definitely malware"  ← AV would flag this

  XOR encrypted with key 0x42:
    → looks like random garbage  ← AV sees nothing suspicious

  At runtime, the malware decrypts itself in memory:
    encrypted_bytes XOR 0x42 → original malicious code
    then executes it

  This is called "XOR obfuscation" and it's one of the
  most common techniques in real-world malware.

  Tools like:
  - CyberChef (browser-based)
  - x64dbg (debugger)
  ...are used by analysts to detect and reverse XOR obfuscation.
""")
    # Simulate it
    payload = "SIMULATED_MALWARE_PAYLOAD"
    key     = 0x42
    obfuscated  = bytes(ord(c) ^ key for c in payload)
    deobfuscated = bytes(b ^ key for b in obfuscated).decode()

    print(f"  Original : {payload}")
    print(f"  XOR 0x42 : {obfuscated.hex()}")
    print(f"  Restored : {deobfuscated}")
    print(f"\n  AV sees the hex above — not the original string.")
    print(f"  Simple XOR obfuscation is easily detected by modern AV,")
    print(f"  but remains widely used because it's easy to implement.\n")

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   XOR CIPHER & ONE-TIME PAD          ║")
        print("║   Cybersecurity Learning Project     ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] How XOR works (bit level)       ║")
        print("║  [2] Repeating-key XOR encryption    ║")
        print("║  [3] One-Time Pad demo               ║")
        print("║  [4] Key reuse attack                ║")
        print("║  [5] How malware uses XOR            ║")
        print("║  [6] Exit                            ║")
        print("╚══════════════════════════════════════╝\n")

        choice = input("Choose an option: ").strip()

        if choice == "1":   xor_bit_demo()
        elif choice == "2": repeating_key_demo()
        elif choice == "3": otp_demo()
        elif choice == "4": key_reuse_attack()
        elif choice == "5": malware_xor_demo()
        elif choice == "6": print("\nGoodbye! XOR is everywhere. 🔐\n"); break
        else: print("\n❌ Invalid option.\n")

if __name__ == "__main__":
    main()

"""
Project 6: Vigenère Cipher — Polyalphabetic Encryption
Concepts: key-based encryption, polyalphabetic ciphers, why Caesar is weak
"""
import string
from collections import Counter

def clean_key(key): return ''.join(c.upper() for c in key if c.isalpha())

def vigenere_encrypt(text, key):
    key = clean_key(key)
    if not key: return text, []
    result, key_chars, ki = [], [], 0
    for char in text:
        if char.upper() in string.ascii_uppercase:
            shift = ord(key[ki % len(key)]) - ord('A')
            key_chars.append(key[ki % len(key)])
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(char); key_chars.append(' ')
    return ''.join(result), key_chars

def vigenere_decrypt(text, key):
    key = clean_key(key)
    if not key: return text
    result, ki = [], 0
    for char in text:
        if char.upper() in string.ascii_uppercase:
            shift = ord(key[ki % len(key)]) - ord('A')
            base  = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
            ki += 1
        else: result.append(char)
    return ''.join(result)

def show_alignment(plaintext, key, ciphertext, key_chars):
    letters = [(p,k,c) for p,k,c in zip(plaintext, key_chars, ciphertext) if p.isalpha()]
    print(f"\n  📊 Encryption table (first 15 letters):")
    print(f"  {'Plaintext':<12} {'Key letter':<12} {'Shift':<8} Ciphertext")
    print(f"  {'-'*9:<12} {'-'*9:<12} {'-'*5:<8} {'-'*9}")
    for p, k, c in letters[:15]:
        print(f"  {p.upper():<12} {k.upper():<12} +{ord(k.upper())-ord('A'):<7} {c.upper()}")
    print(f"\n  💡 Same plaintext letter → different ciphertext each time!")
    print(f"     That's what makes Vigenère much stronger than Caesar.\n")

def comparison_demo():
    msg = "ATTACKATDAWN" * 2
    caesar_enc = ''.join(chr((ord(c)-ord('A')+3)%26+ord('A')) if c.isalpha() else c for c in msg)
    vig_enc, _ = vigenere_encrypt(msg, "LEMON")
    print(f"\n  Plaintext   : {msg}")
    print(f"\n  Caesar (shift=3) : {caesar_enc}")
    print(f"  → 'A' always becomes 'D'. Easy to crack with frequency analysis.\n")
    print(f"  Vigenère (key=LEMON) : {vig_enc}")
    print(f"  → 'A' becomes {vig_enc[0]}, {vig_enc[5]}, {vig_enc[11]}... different every time!")
    print(f"\n  This is why Vigenère was unbreakable for 300 years.\n")

def main():
    while True:
        print("\n╔══════════════════════════════════════╗")
        print("║   VIGENÈRE CIPHER TOOL               ║")
        print("╠══════════════════════════════════════╣")
        print("║  [1] Encrypt  [2] Decrypt            ║")
        print("║  [3] Caesar vs Vigenère  [4] Exit    ║")
        print("╚══════════════════════════════════════╝\n")
        choice = input("Choose: ").strip()
        if choice == '1':
            text, key = input("Plaintext: "), input("Key (letters only, e.g. LEMON): ")
            if not clean_key(key): print("❌ Key must have letters."); continue
            enc, key_chars = vigenere_encrypt(text, key)
            print(f"\n  🔒 Encrypted: {enc}")
            show_alignment(text, key, enc, key_chars)
        elif choice == '2':
            text, key = input("Ciphertext: "), input("Key: ")
            print(f"\n  🔓 Decrypted: {vigenere_decrypt(text, key)}\n")
        elif choice == '3': comparison_demo()
        elif choice == '4': print("\nGoodbye! 🔐\n"); break

if __name__ == "__main__":
    main()

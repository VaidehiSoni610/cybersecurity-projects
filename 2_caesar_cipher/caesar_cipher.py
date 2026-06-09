"""
Project 2: Caesar Cipher & ROT13 Encryption Tool
Concepts: substitution ciphers, encryption, decryption, brute-force cracking
"""

import string

def caesar_encrypt(text, shift):
    """Encrypt text using Caesar cipher with the given shift."""
    result = []
    shift = shift % 26  # Normalize shift

    for char in text:
        if char in string.ascii_uppercase:
            shifted = (ord(char) - ord('A') + shift) % 26
            result.append(chr(shifted + ord('A')))
        elif char in string.ascii_lowercase:
            shifted = (ord(char) - ord('a') + shift) % 26
            result.append(chr(shifted + ord('a')))
        else:
            result.append(char)  # Non-alpha chars unchanged

    return ''.join(result)

def caesar_decrypt(text, shift):
    """Decrypt by reversing the shift."""
    return caesar_encrypt(text, -shift)

def rot13(text):
    """ROT13 is just Caesar with shift=13 (self-inverse)."""
    return caesar_encrypt(text, 13)

def brute_force_crack(ciphertext):
    """Try all 25 possible shifts and display results."""
    print("\n🔓 Brute Force — All 25 Shifts:")
    print("-" * 50)
    for shift in range(1, 26):
        decrypted = caesar_decrypt(ciphertext, shift)
        print(f"  Shift {shift:>2}: {decrypted}")
    print("-" * 50)
    print("⚡ Key insight: Only 25 possible keys — trivially crackable!\n")

def frequency_analysis(text):
    """Show letter frequencies (helps crack substitution ciphers)."""
    text_upper = text.upper()
    letters_only = [c for c in text_upper if c in string.ascii_uppercase]

    if not letters_only:
        print("No letters found in text.\n")
        return

    total = len(letters_only)
    freq = {}
    for c in letters_only:
        freq[c] = freq.get(c, 0) + 1

    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)

    print("\n📊 Letter Frequency Analysis:")
    print("-" * 40)
    print(f"  {'Letter':<8} {'Count':<8} {'%':<8} Bar")
    print("-" * 40)

    for letter, count in sorted_freq:
        pct = (count / total) * 100
        bar = "█" * int(pct)
        print(f"  {letter:<8} {count:<8} {pct:<7.1f}% {bar}")

    top = sorted_freq[0][0] if sorted_freq else '?'
    print(f"\n💡 Most frequent letter: '{top}'")
    print("   In English, 'E' is most common (~12.7%).")
    likely_shift = (ord(top) - ord('E')) % 26
    print(f"   Guessed shift: {likely_shift}")
    guessed = caesar_decrypt(text, likely_shift)
    print(f"   Decrypted guess: {guessed}\n")

def display_menu():
    print("\n╔══════════════════════════════════════╗")
    print("║   CAESAR CIPHER TOOL                 ║")
    print("║   Cybersecurity Learning Project     ║")
    print("╚══════════════════════════════════════╝")
    print("\n  [1] Encrypt a message")
    print("  [2] Decrypt a message")
    print("  [3] ROT13 encode/decode")
    print("  [4] Brute-force crack ciphertext")
    print("  [5] Frequency analysis")
    print("  [6] Exit\n")

def main():
    while True:
        display_menu()
        choice = input("Choose an option: ").strip()

        if choice == '1':
            text = input("\nEnter plaintext: ")
            shift = int(input("Enter shift (1–25): "))
            encrypted = caesar_encrypt(text, shift)
            print(f"\n🔒 Encrypted: {encrypted}")
            print(f"   (Shift used: {shift})\n")

        elif choice == '2':
            text = input("\nEnter ciphertext: ")
            shift = int(input("Enter shift key: "))
            decrypted = caesar_decrypt(text, shift)
            print(f"\n🔓 Decrypted: {decrypted}\n")

        elif choice == '3':
            text = input("\nEnter text (ROT13 is self-inverse): ")
            result = rot13(text)
            print(f"\n🔁 ROT13 Result: {result}")
            print(f"   Apply again:   {rot13(result)}\n")

        elif choice == '4':
            text = input("\nEnter ciphertext to crack: ")
            brute_force_crack(text)

        elif choice == '5':
            text = input("\nEnter ciphertext for frequency analysis: ")
            frequency_analysis(text)

        elif choice == '6':
            print("\nGoodbye! Keep learning cryptography. 🔐\n")
            break
        else:
            print("\n❌ Invalid choice. Please try again.\n")

if __name__ == "__main__":
    main()

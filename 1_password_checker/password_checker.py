"""
Project 1: Password Strength Analyzer
Concepts: entropy, character diversity, common password detection
"""

import re
import math
import string

COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "iloveyou",
    "welcome", "sunshine", "master", "dragon", "passw0rd"
]

def calculate_entropy(password):
    """Calculate password entropy in bits."""
    charset = 0
    if any(c in string.ascii_lowercase for c in password): charset += 26
    if any(c in string.ascii_uppercase for c in password): charset += 26
    if any(c in string.digits for c in password):          charset += 10
    if any(c in string.punctuation for c in password):     charset += 32
    if charset == 0:
        return 0
    return len(password) * math.log2(charset)

def check_patterns(password):
    """Detect weak patterns in the password."""
    warnings = []
    if re.search(r'(.)\1{2,}', password):
        warnings.append("⚠ Repeated characters detected (e.g. 'aaa')")
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        warnings.append("⚠ Sequential numbers detected")
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
        warnings.append("⚠ Sequential letters detected")
    if re.search(r'(qwert|asdf|zxcv)', password.lower()):
        warnings.append("⚠ Keyboard pattern detected")
    return warnings

def analyze_password(password):
    """Full analysis of password strength."""
    print("\n" + "="*50)
    print(f"  Analyzing: {'*' * len(password)}")
    print("="*50)

    # Basic length check
    length = len(password)
    print(f"\n📏 Length: {length} characters")

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        print("🚨 CRITICAL: This is one of the most common passwords!")
        print("   Score: 0/100 — Change this immediately.\n")
        return

    # Character diversity
    has_lower  = bool(re.search(r'[a-z]', password))
    has_upper  = bool(re.search(r'[A-Z]', password))
    has_digit  = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    print("\n🔡 Character Types:")
    print(f"   Lowercase letters : {'✅' if has_lower  else '❌'}")
    print(f"   Uppercase letters : {'✅' if has_upper  else '❌'}")
    print(f"   Numbers           : {'✅' if has_digit  else '❌'}")
    print(f"   Special symbols   : {'✅' if has_symbol else '❌'}")

    # Entropy
    entropy = calculate_entropy(password)
    print(f"\n🔐 Entropy: {entropy:.1f} bits")
    if entropy < 28:
        entropy_label = "Very Weak"
    elif entropy < 36:
        entropy_label = "Weak"
    elif entropy < 60:
        entropy_label = "Moderate"
    elif entropy < 80:
        entropy_label = "Strong"
    else:
        entropy_label = "Very Strong"
    print(f"   Rating: {entropy_label}")

    # Pattern checks
    warnings = check_patterns(password)
    if warnings:
        print("\n⚠️  Pattern Warnings:")
        for w in warnings:
            print(f"   {w}")

    # Score (0–100)
    score = 0
    score += min(length * 4, 40)             # up to 40 pts for length
    score += 10 if has_lower  else 0
    score += 10 if has_upper  else 0
    score += 10 if has_digit  else 0
    score += 15 if has_symbol else 0
    score += min(int(entropy / 4), 15)       # up to 15 pts for entropy
    score -= len(warnings) * 10              # deduct for patterns
    score = max(0, min(score, 100))

    bar_filled = int(score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    print(f"\n📊 Strength Score: {score}/100")
    print(f"   [{bar}]")

    if score < 30:
        verdict = "🔴 VERY WEAK  — Easily cracked"
    elif score < 50:
        verdict = "🟠 WEAK       — Vulnerable to attacks"
    elif score < 70:
        verdict = "🟡 MODERATE   — Could be better"
    elif score < 85:
        verdict = "🟢 STRONG     — Good password"
    else:
        verdict = "🔵 VERY STRONG — Excellent password!"

    print(f"\n   Verdict: {verdict}\n")

    # Suggestions
    tips = []
    if length < 12:       tips.append("Use at least 12 characters")
    if not has_upper:     tips.append("Add uppercase letters (A–Z)")
    if not has_symbol:    tips.append("Add special characters (!@#$...)")
    if not has_digit:     tips.append("Include numbers")
    if warnings:          tips.append("Avoid predictable patterns")

    if tips:
        print("💡 Tips to improve:")
        for t in tips:
            print(f"   → {t}")
        print()

def main():
    print("\n╔══════════════════════════════════╗")
    print("║   PASSWORD STRENGTH ANALYZER     ║")
    print("║   Cybersecurity Learning Project ║")
    print("╚══════════════════════════════════╝")
    print("\nType 'quit' to exit.\n")

    while True:
        password = input("Enter a password to analyze: ").strip()
        if password.lower() == 'quit':
            print("\nGoodbye! Stay secure. 🔒\n")
            break
        if not password:
            print("Please enter a password.\n")
            continue
        analyze_password(password)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Password Strength Checker (simple, educational)

Usage:
  python3 password_strength_checker.py "P@ssw0rd123!"
  python3 password_strength_checker.py --file passwords.txt

Notes:
- Designed for educational/defensive use (help users create stronger passwords).
- No external dependencies (pure Python 3.6+).
"""

import argparse
import math
import re
from collections import Counter

# A small list of very common passwords to penalize (extendable)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "12345678",
    "111111", "1234567", "sunshine", "iloveyou", "princess",
    "admin", "welcome", "monkey", "login", "abc123"
}

SEQUENTIAL_LOWER = "abcdefghijklmnopqrstuvwxyz"
SEQUENTIAL_UPPER = SEQUENTIAL_LOWER.upper()
SEQUENTIAL_DIGITS = "01234567890"

def char_classes(password):
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))
    return has_lower, has_upper, has_digit, has_symbol

def estimate_entropy(password):
    # estimate charset size based on char classes present
    has_lower, has_upper, has_digit, has_symbol = char_classes(password)
    charset = 0
    if has_lower:
        charset += 26
    if has_upper:
        charset += 26
    if has_digit:
        charset += 10
    if has_symbol:
        # rough approximation for symbols set
        charset += 32
    if charset == 0:
        return 0.0
    entropy = len(password) * math.log2(charset)
    return entropy

def count_sequences(password, seq_len=3):
    # count basic sequential substrings of length seq_len
    pw = password
    lower = pw.lower()
    count = 0
    for i in range(len(lower) - seq_len + 1):
        chunk = lower[i:i+seq_len]
        if chunk in SEQUENTIAL_LOWER or chunk in SEQUENTIAL_LOWER[::-1]:
            count += 1
        if chunk in SEQUENTIAL_DIGITS or chunk in SEQUENTIAL_DIGITS[::-1]:
            count += 1
    return count

def repeated_chars_penalty(password):
    # ratio of repeated characters (more repeats -> worse)
    if not password:
        return 0.0
    freq = Counter(password)
    most_common = freq.most_common(1)[0][1]
    repeat_ratio = most_common / len(password)
    return repeat_ratio  # between 0 and 1

def score_password(password):
    pwd = password or ""
    length = len(pwd)
    has_lower, has_upper, has_digit, has_symbol = char_classes(pwd)
    entropy = estimate_entropy(pwd)

    # Base points from length
    if length == 0:
        return {
            "score": 0, "category": "Empty", "entropy": 0.0,
            "suggestions": ["Enter a password."]
        }

    # length score (0..40)
    if length < 6:
        length_score = 5
    elif length < 8:
        length_score = 15
    elif length < 12:
        length_score = 25
    elif length < 16:
        length_score = 32
    else:
        length_score = 40

    # variety score (0..30)
    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    variety_score = {1: 5, 2: 12, 3: 22, 4: 30}.get(variety, 0)

    # entropy contribution (0..15) scaled (cap at 60 bits)
    entropy_cap = min(entropy, 60.0)
    entropy_score = int((entropy_cap / 60.0) * 15)

    # penalties
    penalty = 0
    suggestions = []

    # common password check (heavy penalty)
    if pwd.lower() in COMMON_PASSWORDS:
        penalty += 40
        suggestions.append("Password is too common. Use a unique passphrase.")

    # sequential patterns penalty
    seq_count = count_sequences(pwd, seq_len=3)
    if seq_count > 0:
        penalty += min(seq_count * 3, 12)
        suggestions.append("Avoid sequential characters like 'abcd' or '1234'.")

    # repeated char penalty
    repeat_ratio = repeated_chars_penalty(pwd)
    if repeat_ratio > 0.5:
        penalty += 12
        suggestions.append("Avoid many repeated characters (e.g., 'aaaaaa').")

    # dictionary-ish short passwords
    if length < 8 and variety < 3:
        penalty += 8
        suggestions.append("Make your password longer and mix character types.")

    # combine scores
    raw_score = length_score + variety_score + entropy_score
    final_score = max(0, min(100, raw_score - penalty))

    # Category mapping
    if final_score < 20:
        category = "Very Weak"
    elif final_score < 40:
        category = "Weak"
    elif final_score < 60:
        category = "Fair"
    elif final_score < 80:
        category = "Good"
    else:
        category = "Strong"

    # Add positive suggestions if few present
    if length < 12 and "Make your password longer" not in " ".join(suggestions):
        suggestions.append("Use a passphrase (4+ random words) or make it at least 12+ characters.")
    if not has_symbol:
        suggestions.append("Add symbols (e.g., !@#$%) to increase complexity.")
    if not has_digit:
        suggestions.append("Include digits to increase strength.")
    if not (has_upper and has_lower):
        suggestions.append("Mix uppercase and lowercase letters.")

    # unique suggestions de-dup and limit
    unique_suggestions = []
    for s in suggestions:
        if s not in unique_suggestions:
            unique_suggestions.append(s)
    unique_suggestions = unique_suggestions[:6]

    return {
        "password": pwd,
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "entropy_bits": round(entropy, 2),
        "raw_score_components": {
            "length_score": length_score,
            "variety_score": variety_score,
            "entropy_score": entropy_score,
            "penalty": penalty
        },
        "score": final_score,
        "category": category,
        "suggestions": unique_suggestions
    }

def pretty_print(result):
    if result.get("category") == "Empty":
        print("[!] No password provided.")
        return
    print("Password analysis:")
    print(f"- Length: {result['length']}")
    print(f"- Classes: lower={result['has_lower']}, upper={result['has_upper']}, digit={result['has_digit']}, symbol={result['has_symbol']}")
    print(f"- Estimated entropy: {result['entropy_bits']} bits")
    print(f"- Score: {result['score']} / 100 ({result['category']})")
    comps = result["raw_score_components"]
    print(f"  breakdown -> length: {comps['length_score']}, variety: {comps['variety_score']}, entropy: {comps['entropy_score']}, penalty: {comps['penalty']}")
    if result["suggestions"]:
        print("Suggestions to improve:")
        for s in result["suggestions"]:
            print(f" - {s}")

def check_file(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            pw = line.rstrip("\n")
            if not pw:
                continue
            res = score_password(pw)
            print("="*60)
            print(f"Password: {pw}")
            pretty_print(res)
            print()

def main():
    parser = argparse.ArgumentParser(description="Simple Password Strength Checker")
    parser.add_argument("password", nargs="?", help="Password to check (wrap in quotes if needed)")
    parser.add_argument("--file", "-f", help="File with passwords (one per line)")
    args = parser.parse_args()

    if args.file:
        check_file(args.file)
    elif args.password is not None:
        res = score_password(args.password)
        pretty_print(res)
    else:
        # interactive prompt when no args provided
        try:
            while True:
                pw = input("Enter a password to check (or press Enter to quit): ").strip()
                if pw == "":
                    print("Exiting.")
                    break
                res = score_password(pw)
                pretty_print(res)
                print()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")

if __name__ == "__main__":
    main()
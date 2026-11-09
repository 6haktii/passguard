"""
PassGuard - Password Strength & Breach Checker
Author: Bhakti Deshmukh

A small command-line tool that:
  1. Rates how strong a password is (entropy + pattern checks).
  2. Checks if the password has appeared in real data breaches using the
     Have I Been Pwned "Pwned Passwords" API. It uses k-anonymity, so the
     password itself (or even its full hash) never leaves your computer.
  3. Generates strong random passwords.

Run:  python passguard.py
      python passguard.py --offline     (skip the online breach check)
"""

import hashlib
import math
import re
import secrets
import string
import sys
import urllib.error
import urllib.request
from getpass import getpass
from pathlib import Path

COMMON_PASSWORDS_FILE = Path(__file__).parent / "common_passwords.txt"
HIBP_RANGE_API = "https://api.pwnedpasswords.com/range/"

# Rows of a QWERTY keyboard, used to spot lazy patterns like "qwerty" or "asdf"
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]


# ---------------------------------------------------------------------------
# Strength analysis
# ---------------------------------------------------------------------------

def load_common_passwords(path=COMMON_PASSWORDS_FILE):
    """Read the list of commonly used passwords into a set (fast lookups)."""
    try:
        with open(path, encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def charset_size(password):
    """How many possible characters an attacker has to try per position."""
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(c in string.punctuation or c == " " for c in password):
        size += len(string.punctuation) + 1
    return size


def calculate_entropy(password):
    """Entropy in bits = length * log2(charset size).

    It's a rough upper estimate of how hard the password is to brute-force.
    """
    size = charset_size(password)
    if size == 0:
        return 0.0
    return len(password) * math.log2(size)


def has_sequence(password, run=3):
    """True if the password has 3+ characters in a row like 'abc', '123', 'cba'."""
    p = password.lower()
    for i in range(len(p) - run + 1):
        chunk = p[i:i + run]
        diffs = {ord(chunk[j + 1]) - ord(chunk[j]) for j in range(run - 1)}
        if diffs == {1} or diffs == {-1}:
            return True
    return False


def has_repeats(password, run=3):
    """True if the same character repeats 3+ times in a row, like 'aaa'."""
    for i in range(len(password) - run + 1):
        if len(set(password[i:i + run])) == 1:
            return True
    return False


def has_keyboard_pattern(password, run=4):
    """True if the password contains 4+ neighbouring keys, like 'qwer' or 'asdf'."""
    p = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run + 1):
            pattern = row[i:i + run]
            if pattern in p or pattern[::-1] in p:
                return True
    return False


def has_year(password):
    """True if the password contains a year like 1998 or 2006 (birth years are
    one of the first things attackers guess)."""
    return re.search(r"(19|20)\d\d", password) is not None


def analyze_password(password, common_passwords=None):
    """Return a dict with score (0-4), label, entropy and improvement tips."""
    if common_passwords is None:
        common_passwords = load_common_passwords()

    entropy = calculate_entropy(password)
    tips = []

    # Base score from entropy
    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 80:
        score = 3
    else:
        score = 4

    # Penalties for patterns attackers try first
    if has_sequence(password):
        score -= 1
        tips.append("Avoid sequences like 'abc' or '123'.")
    if has_repeats(password):
        score -= 1
        tips.append("Avoid repeating the same character (e.g. 'aaa').")
    if has_keyboard_pattern(password):
        score -= 1
        tips.append("Avoid keyboard patterns like 'qwerty' or 'asdf'.")
    if has_year(password):
        score -= 1
        tips.append("Avoid years (like your birth year) - they are easy to guess.")

    # Hard caps
    if len(password) < 8:
        score = min(score, 1)
        tips.append("Use at least 12 characters.")
    elif len(password) < 12:
        tips.append("Longer is stronger - aim for 12+ characters.")

    if password.lower() in common_passwords:
        score = 0
        tips.insert(0, "This is one of the most common passwords - never use it.")

    # Missing character types
    if not any(c.isupper() for c in password):
        tips.append("Add uppercase letters.")
    if not any(c.islower() for c in password):
        tips.append("Add lowercase letters.")
    if not any(c.isdigit() for c in password):
        tips.append("Add numbers.")
    if not any(c in string.punctuation for c in password):
        tips.append("Add symbols like ! @ # $ %.")

    score = max(0, min(score, 4))
    return {
        "score": score,
        "label": STRENGTH_LABELS[score],
        "entropy": round(entropy, 1),
        "tips": tips,
    }


# ---------------------------------------------------------------------------
# Breach check (Have I Been Pwned, k-anonymity)
# ---------------------------------------------------------------------------

def count_in_range_response(body, suffix):
    """Find our hash suffix in the API response and return how often it was seen.

    Each line of the response looks like:  SUFFIX:COUNT
    """
    for line in body.splitlines():
        if ":" not in line:
            continue
        line_suffix, count = line.strip().split(":", 1)
        if line_suffix.upper() == suffix.upper():
            return int(count)
    return 0


def check_pwned(password, timeout=10):
    """Return how many times the password appears in known breaches.

    Only the first 5 characters of the SHA-1 hash are sent to the API.
    The API returns every hash starting with those 5 characters, and we
    compare the rest locally. Returns None if the check couldn't be done.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    request = urllib.request.Request(
        HIBP_RANGE_API + prefix,
        headers={
            "User-Agent": "PassGuard-Student-Project",
            "Add-Padding": "true",  # hides the real response size
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None

    return count_in_range_response(body, suffix)


# ---------------------------------------------------------------------------
# Password generator
# ---------------------------------------------------------------------------

def generate_password(length=16):
    """Generate a strong random password using the cryptographically secure
    `secrets` module (not `random`, which is predictable)."""
    if length < 8:
        raise ValueError("Password length should be at least 8.")

    pools = [string.ascii_lowercase, string.ascii_uppercase,
             string.digits, "!@#$%^&*-_=+?"]
    # Guarantee at least one character from every pool
    chars = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    chars += [secrets.choice(all_chars) for _ in range(length - len(pools))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

def strength_bar(score):
    filled = (score + 1) * 2
    return "[" + "#" * filled + "." * (10 - filled) + "]"


def run_check(offline=False):
    password = getpass("Enter password to check (input is hidden): ")
    if not password:
        print("No password entered.\n")
        return

    result = analyze_password(password)
    print(f"\nStrength : {strength_bar(result['score'])} {result['label']}")
    print(f"Entropy  : {result['entropy']} bits")

    if offline:
        print("Breaches : skipped (offline mode)")
    else:
        count = check_pwned(password)
        if count is None:
            print("Breaches : could not reach the breach database (check internet)")
        elif count > 0:
            print(f"Breaches : FOUND {count:,} times in data breaches - do not use it!")
        else:
            print("Breaches : not found in known breaches")

    if result["tips"]:
        print("\nHow to improve:")
        for tip in result["tips"]:
            print(f"  - {tip}")
    print()


def run_generate():
    raw = input("Length (press Enter for 16): ").strip()
    try:
        length = int(raw) if raw else 16
        password = generate_password(length)
    except ValueError as e:
        print(f"Invalid length: {e}\n")
        return
    result = analyze_password(password)
    print(f"\nGenerated: {password}")
    print(f"Strength : {strength_bar(result['score'])} {result['label']}\n")


def main():
    offline = "--offline" in sys.argv
    print("=" * 50)
    print("  PassGuard - Password Strength & Breach Checker")
    print("=" * 50)

    while True:
        print("1. Check a password")
        print("2. Generate a strong password")
        print("3. Exit")
        choice = input("Choose (1-3): ").strip()
        print()
        if choice == "1":
            run_check(offline)
        elif choice == "2":
            run_generate()
        elif choice == "3":
            print("Stay safe!")
            break
        else:
            print("Please enter 1, 2 or 3.\n")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nBye!")

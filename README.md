# 🔐 PassGuard — Password Strength & Breach Checker

A command-line tool written in Python that tells you **how strong a password is**, checks whether it has **appeared in real-world data breaches**, and **generates strong random passwords** — without ever sending your password over the internet.

Built as a beginner cybersecurity project to learn how password attacks work and how to defend against them.

---

## ✨ Features

- **Strength rating (0–4)** — Very Weak → Very Strong, with a visual strength bar
- **Entropy calculation** — estimates how many guesses a brute-force attack would need
- **Pattern detection** — flags the shortcuts attackers try first:
  - common passwords (`password123`, `qwerty`, `admin@123`…)
  - sequences (`abc`, `123`, `cba`)
  - repeated characters (`aaa`)
  - keyboard patterns (`qwer`, `asdf`)
  - years (`2006`, `1999`) — birth years are easy to guess
- **Breach check** — looks up the password in the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) database of hundreds of millions of leaked passwords
- **Privacy-safe** — uses *k-anonymity*: only the first 5 characters of the password's SHA-1 hash are sent
- **Password generator** — uses Python's cryptographically secure `secrets` module
- **Hidden input** — password is never shown on screen while typing
- **Zero dependencies** — only the Python standard library
- **Unit tested** — 14 tests with `unittest`

---

## 🛡️ How the breach check stays private (k-anonymity)

Sending your password to a website to "check if it was leaked" would be a terrible idea. PassGuard never does that:

```
Your password ──SHA-1──▶ 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
                         └─┬─┘└───────────────┬───────────────────┘
                        prefix              suffix
                     (sent to API)     (stays on your computer)
```

1. The password is hashed with SHA-1 on your machine.
2. Only the **first 5 characters** (`5BAA6`) are sent to the API.
3. The API returns **every** leaked hash that starts with those 5 characters (hundreds of them).
4. PassGuard compares the **suffix locally** to see if yours is in the list.

The server never learns which password you checked. An `Add-Padding` header is also sent so the response size can't give anything away.

---

## 🚀 Getting started

**Requirements:** Python 3.8 or newer

```bash
git clone https://github.com/6haktii/passguard.git
cd passguard
python passguard.py
```

Skip the online breach check (works without internet):

```bash
python passguard.py --offline
```

Run the tests:

```bash
python -m unittest -v
```

---

## 📸 Sample output

```
==================================================
  PassGuard - Password Strength & Breach Checker
==================================================
1. Check a password
2. Generate a strong password
3. Exit
Choose (1-3): 1

Enter password to check (input is hidden):

Strength : [##........] Very Weak
Entropy  : 56.9 bits
Breaches : FOUND 2,xxx,xxx times in data breaches - do not use it!

How to improve:
  - This is one of the most common passwords - never use it.
  - Avoid sequences like 'abc' or '123'.
  - Longer is stronger - aim for 12+ characters.
  - Add uppercase letters.
  - Add symbols like ! @ # $ %.
```

```
Choose (1-3): 2

Length (press Enter for 16):
Generated: y7-bu-nBbnF47%H!
Strength : [##########] Very Strong
```

---

## 📂 Project structure

```
passguard/
├── passguard.py            # main program
├── common_passwords.txt    # list of frequently used passwords
├── test_passguard.py       # unit tests
└── README.md
```

---

## 🧠 What I learned

- How **hashing** (SHA-1) works and why passwords are stored as hashes
- What **password entropy** is and why length matters more than complexity
- How attackers use **dictionary attacks** and common patterns
- The **k-anonymity** technique for checking sensitive data without exposing it
- Why `secrets` should be used instead of `random` for anything security-related
- Calling a **REST API** with `urllib` and handling network errors
- Writing **unit tests** with `unittest`

---

## 🔮 Future improvements

- [ ] Bigger common-password list (e.g. top 10,000 from SecLists)
- [ ] Estimate "time to crack" for different attack speeds
- [ ] Passphrase generator (e.g. `correct-horse-battery-staple` style)
- [ ] Simple GUI with Tkinter or a web version with Flask
- [ ] Check a whole file of passwords at once (for password audits)

---

## ⚠️ Disclaimer

This tool is for learning and personal use. Don't paste other people's passwords into any tool, and never reuse a password that has appeared in a breach.

## 👩‍💻 Author

**Bhakti Deshmukh** — BTech CSE student, interested in cybersecurity.

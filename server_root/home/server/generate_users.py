#!/usr/bin/env python3
"""
Run this once to generate users.json with hashed passwords.
Original plaintext passwords are preserved for reference below.
"""
import bcrypt
import json

# original accounts from the baseline
users = {
    "alice":   "password123",
    "bob":     "password123",
    "charlie": "password123",
    "mitm":    "mitm123",
}

hashed = {}
for username, password in users.items():
    hashed[username] = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    print(f"[+] hashed password for {username}")

with open("users.json", "w") as f:
    json.dump(hashed, f, indent=4)

print("\n[+] users.json written with hashed passwords")

"""
HireSignal — Encryption Key Generator
Run this ONCE to generate your encryption key.
Copy the output into your .env as ENCRYPTION_KEY=...

Usage: python security/keygen.py
"""

from cryptography.fernet import Fernet
import os

def generate_key():
    key = Fernet.generate_key()
    print("\n✅ Encryption key generated:")
    print(f"\nENCRYPTION_KEY={key.decode()}\n")
    print("📋 Copy the line above into your .env file.")
    print("⚠️  Never share or commit this key.\n")
    return key

if __name__ == "__main__":
    generate_key()

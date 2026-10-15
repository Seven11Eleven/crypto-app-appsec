#!/usr/bin/env python3

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import sys
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_FILE = "users.json"

N, R, P = 2**14, 8, 1
MAGIC = b"LAB5"  # file header


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def kdf(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=N, r=R, p=P, dklen=32,
                          maxmem=64 * 1024 * 1024)


# --------------------------------------------------------------------------
# CASE 1: password storage
# --------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = os.urandom(16)  # unique per user -> defeats rainbow tables
    dk = kdf(password, salt)
    return f"scrypt${N}${R}${P}${b64e(salt)}${b64e(dk)}"


def verify_password(password: str, stored: str) -> bool:
    _, _n, _r, _p, salt_b64, dk_b64 = stored.split("$")
    candidate = kdf(password, b64d(salt_b64))
    return hmac.compare_digest(candidate, b64d(dk_b64))  # constant-time compare


def load_db() -> dict:
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE) as f:
        return json.load(f)


def save_db(db: dict) -> None:
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


def register(username: str, password: str) -> None:
    db = load_db()
    if username in db:
        print("[-] user already exists")
        return
    db[username] = hash_password(password)
    save_db(db)
    print(f"[+] registered {username}\n    stored record: {db[username]}")


def login(username: str, password: str) -> bool:
    db = load_db()
    stored = db.get(username)
    if stored is None:
        # dummy hash to keep timing similar (avoid user enumeration)
        verify_password(password, hash_password("dummy"))
        ok = False
    else:
        ok = verify_password(password, stored)
    print("[+] login OK" if ok else "[-] login FAILED")
    return ok


# --------------------------------------------------------------------------
# CASE 2: authenticated file encryption
# File format: MAGIC(4) | salt(16) | nonce(12) | ciphertext+tag
# --------------------------------------------------------------------------
def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)  # MUST be unique per key; random 96-bit is fine here
    key = kdf(password, salt)
    ct = AESGCM(key).encrypt(nonce, data, MAGIC)  # MAGIC authenticated as AAD
    return MAGIC + salt + nonce + ct


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    if blob[:4] != MAGIC:
        raise ValueError("not a LAB5 encrypted file")
    salt, nonce, ct = blob[4:20], blob[20:32], blob[32:]
    key = kdf(password, salt)
    return AESGCM(key).decrypt(nonce, ct, MAGIC)  # raises InvalidTag if tampered / wrong pw


def encrypt_file(path: str, password: str) -> str:
    with open(path, "rb") as f:
        blob = encrypt_bytes(f.read(), password)
    out = path + ".enc"
    with open(out, "wb") as f:
        f.write(blob)
    print(f"[+] encrypted -> {out}")
    return out


def decrypt_file(path: str, password: str) -> str:
    with open(path, "rb") as f:
        blob = f.read()
    try:
        data = decrypt_bytes(blob, password)
    except InvalidTag:
        print("[-] DECRYPTION FAILED: wrong password or file was modified")
        sys.exit(1)
    out = path + ".dec"
    with open(out, "wb") as f:
        f.write(data)
    print(f"[+] decrypted -> {out}")
    return out


# --------------------------------------------------------------------------
# DEMONSTRATON
# --------------------------------------------------------------------------
def demo() -> None:
    print("=" * 60)
    print("CASE 1: PASSWORD STORAGE")
    print("=" * 60)
    pw = "sunshine1"

    print("\n[A] BAD: unsalted MD5")
    bad = hashlib.md5(pw.encode()).hexdigest()
    print("    stored hash:", bad)
    wordlist = ["123456", "password", "qwerty", "letmein", "sunshine1", "admin"]
    t = time.time()
    for w in wordlist:
        if hashlib.md5(w.encode()).hexdigest() == bad:
            print(f"    CRACKED in {time.time() - t:.6f}s -> '{w}'  (precomputed table / wordlist)")
            break

    print("\n[B] GOOD: scrypt + random salt")
    h1, h2 = hash_password(pw), hash_password(pw)
    print("    hash #1:", h1)
    print("    hash #2:", h2)
    print("    same password, different hashes (unique salt):", h1 != h2)
    t = time.time()
    verify_password(pw, h1)
    print(f"    one verification costs {time.time() - t:.3f}s  -> brute force is expensive")
    print("    correct password verifies:", verify_password(pw, h1))
    print("    wrong password verifies:  ", verify_password("wrong", h1))

    print("\n" + "=" * 60)
    print("CASE 2: AUTHENTICATED FILE ENCRYPTION (AES-256-GCM)")
    print("=" * 60)
    plaintext = b"Top secret: grades database dump"
    blob = encrypt_bytes(plaintext, "StrongPassphrase!")
    print("\n    plaintext :", plaintext)
    print("    encrypted :", blob.hex()[:80] + "...")
    print("    decrypted :", decrypt_bytes(blob, "StrongPassphrase!"))

    print("\n    [test] wrong password:")
    try:
        decrypt_bytes(blob, "WrongPassphrase")
    except InvalidTag:
        print("    -> rejected (InvalidTag)")

    print("    [test] attacker flips 1 bit of ciphertext:")
    tampered = bytearray(blob)
    tampered[-5] ^= 0x01
    try:
        decrypt_bytes(bytes(tampered), "StrongPassphrase!")
    except InvalidTag:
        print("    -> tampering DETECTED (integrity protected by GCM tag)")

    print("    [test] encrypting same data twice gives different output (random salt+nonce):")
    print("    ->", encrypt_bytes(plaintext, "x") != encrypt_bytes(plaintext, "x"))


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo")
    for name in ("register", "login"):
        sub.add_parser(name).add_argument("username")
    for name in ("encrypt", "decrypt"):
        sub.add_parser(name).add_argument("path")
    a = ap.parse_args()

    if a.cmd == "demo":
        demo()
    elif a.cmd == "register":
        register(a.username, getpass.getpass("Password: "))
    elif a.cmd == "login":
        login(a.username, getpass.getpass("Password: "))
    elif a.cmd == "encrypt":
        encrypt_file(a.path, getpass.getpass("Password: "))
    elif a.cmd == "decrypt":
        decrypt_file(a.path, getpass.getpass("Password: "))


if __name__ == "__main__":
    main()

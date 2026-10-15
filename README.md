# Lab #5 — Cryptography app

Small demo app showing two real-world uses of cryptography, plus a test of an open-source crypto tool (GnuPG).

## Run

```bash
pip install cryptography
python crypto_app.py demo
```

## Case 1 — Password storage (authentication systems)

**Real-world problem:** databases get leaked (LinkedIn 2012, Adobe 2013). If passwords are stored in plaintext or fast unsalted hashes (MD5/SHA1), attackers recover them instantly.

**What the app does:**
- `scrypt` (memory-hard KDF) instead of MD5/SHA — each guess costs CPU *and* RAM, so GPU/ASIC brute-force is slow.
- Random 16-byte **salt** per user — identical passwords produce different hashes, rainbow tables are useless.
- Parameters stored in the record (`scrypt$N$r$p$salt$hash`) — cost can be raised later without breaking old users.
- `hmac.compare_digest` — constant-time comparison, no timing side-channel.
- Dummy hash for unknown usernames — mitigates user enumeration via response time.

**Demo result:** MD5 cracked in microseconds with a wordlist; scrypt: ~50 ms per single guess and different hash for the same password.

## Case 2 — File encryption (data at rest / confidentiality + integrity)

**Real-world problem:** stolen laptop, leaked backup, tampered file on a shared drive.

**What the app does:**
- **AES-256-GCM** — AEAD cipher: encrypts *and* authenticates. Any modification of the ciphertext → `InvalidTag`.
- Key derived from passphrase via scrypt with random per-file salt (never use the password directly as a key).
- Random 96-bit **nonce** per encryption — reusing a nonce with the same key breaks GCM, so it is never reused.
- Header (`LAB5`) is passed as AAD — authenticated but not encrypted.
- File format: `MAGIC | salt | nonce | ciphertext+tag`.

**Demo result:** wrong password → rejected; 1 flipped bit → tampering detected; same plaintext encrypted twice → different output.

## Open-source tool test — GnuPG (OpenPGP)

GnuPG is free software whose main feature is cryptography (encryption, signatures, key management).

Install: `sudo apt install gnupg` / `brew install gnupg` / Gpg4win on Windows.

```bash
# 1. Generate a key pair (use test name/email, ed25519/cv25519 default is fine)
gpg --quick-generate-key "Lab5 Test <lab5@example.com>" default default 1y
gpg --list-keys

# 2. Encrypt / decrypt a file (asymmetric)
echo "confidential message" > msg.txt
gpg --encrypt --recipient lab5@example.com msg.txt     # -> msg.txt.gpg
rm msg.txt
gpg --decrypt msg.txt.gpg                              # prints message

# 3. Digital signature + verification
echo "release v1.0" > release.txt
gpg --armor --detach-sign release.txt                  # -> release.txt.asc
gpg --verify release.txt.asc release.txt               # Good signature

# 4. Tamper test: modify the file, verify again
echo "evil" >> release.txt
gpg --verify release.txt.asc release.txt               # BAD signature

# 5. Tamper with encrypted file
cp msg.txt.gpg broken.gpg
printf '\x00' | dd of=broken.gpg bs=1 seek=50 count=1 conv=notrunc
gpg --decrypt broken.gpg                               # fails (MDC / integrity error)

# 6. Symmetric mode (passphrase) for comparison with Case 2
gpg --symmetric --cipher-algo AES256 msg.txt           # -> msg.txt.gpg
```

**Take screenshots** of: key generation, successful decrypt, `Good signature`, `BAD signature`, failed decrypt of the broken file.

### Explain cryptographic usage in GnuPG
- **Asymmetric (Curve25519 / Ed25519):** encryption to a recipient's public key, signing with a private key.
- **Hybrid encryption:** a random session key encrypts data with a symmetric cipher (AES-256); the session key is encrypted with the recipient's public key.
- **Integrity:** MDC (SHA-1/SHA-256 modification detection code) / AEAD (OCB/EAX) detects modified ciphertext.
- **Signatures:** hash of the file signed with the private key → authenticity + non-repudiation.
- **Passphrase protection:** the private key is stored encrypted with a key derived from your passphrase (S2K).

### Comparison with my app
| | My app (Case 2) | GnuPG |
|---|---|---|
| Key model | passphrase → scrypt → AES key | public/private keys (hybrid) |
| Cipher | AES-256-GCM | AES-256 + MDC / AEAD |
| Integrity | GCM tag | MDC / signature |
| Use case | local file protection | sharing with other people, signing releases |

## Conclusion
Crypto is only secure when used correctly: slow salted KDFs for passwords, AEAD modes with unique nonces for encryption, standard audited libraries instead of homemade algorithms, and integrity checks together with confidentiality.

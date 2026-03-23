# Cryptographic Choices

## AES-256-GCM (chosen)

**Why:** Only authenticated encryption (AEAD) available natively in the Web Crypto API. Hardware-accelerated via AES-NI on modern CPUs. Each file gets a unique random key, eliminating nonce reuse risk entirely.

**Properties:**
- 256-bit key, 96-bit nonce, 128-bit authentication tag
- Nonce reuse is catastrophic (reveals XOR of plaintexts + enables forgery) — but with one key per file and a random nonce, collision probability is effectively zero
- Maximum plaintext: ~64GB (2^39 - 256 bits counter space). Sufficient for document exchange.
- Lacks key commitment: a ciphertext can decrypt validly under two different keys. Matters for multi-recipient; irrelevant for single-recipient file sharing.

**Source:** NIST SP 800-38D (T1), https://csrc.nist.gov/publications/detail/sp/800-38d/final

### Why not XChaCha20-Poly1305?

- Not available in Web Crypto API
- Using a JS library (libsodium.js, tweetnacl) loses the constant-time guarantees of native browser crypto
- 192-bit nonce is superior for long-lived keys, but vault uses ephemeral one-per-file keys — GCM's 96-bit nonce is fine

**Source:** Soatok, "Understanding XChaCha20-Poly1305" (T3); Web Crypto API spec (T1)

### Why not AES-CBC + HMAC?

- GCM provides authenticated encryption in one pass
- CBC without authentication is vulnerable to padding oracle attacks
- Encrypt-then-MAC (CBC + HMAC) works but is more complex and slower than GCM

## Key Generation

**Choice:** Generate 128-bit random key via `crypto.getRandomValues()`. Expand to encryption key via HKDF-SHA256.

**Why 128-bit, not 256-bit?** 128-bit provides 2^128 brute-force resistance, which exceeds the security margin of AES-256-GCM itself (birthday bound on GCM is ~2^64). The key appears in the URL, so shorter is better for usability. Bitwarden Send uses 128-bit.

**Source:** Bitwarden Send architecture docs (T3), NIST SP 800-57 (T1)

## Key Expansion (HKDF)

**Choice:** HKDF-SHA256 to derive a 256-bit encryption key from the 128-bit random key.

**Why HKDF, not direct use?** Key separation. HKDF produces cryptographically independent keys from one source, preventing key reuse across different operations. Even though vault currently only needs one derived key per file, this leaves room for future key derivation (e.g., filename encryption, metadata encryption) without reusing the same key material.

**Source:** RFC 5869 (T1), https://datatracker.ietf.org/doc/html/rfc5869

## PBKDF2 (optional password layer)

**Choice:** PBKDF2-SHA256 with >= 600,000 iterations. Used ONLY for authentication (gating the download endpoint), NOT for encryption.

**Why authentication-only?** The encryption key is the random 128-bit value in the URL. If the password were used for encryption, a weak password would compromise everything. Separating authentication (password) from encryption (random key) means a brute-forced password only bypasses the download gate — the attacker still needs the URL to decrypt.

**PBKDF2 weaknesses:**
- GPU-friendly. Modern GPUs can test billions of PBKDF2-SHA256 hashes/second.
- No memory cost parameter. ASICs can parallelise cheaply.
- Only option in Web Crypto API. Argon2id and scrypt are not available.

**OWASP recommended iterations (2024):**
- PBKDF2-HMAC-SHA256: 600,000
- PBKDF2-HMAC-SHA512: 210,000

**Source:** OWASP Password Storage Cheat Sheet (T2), https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

## The Mega Catastrophe (what NOT to do)

**Paper:** "MEGA: Malleable Encryption Goes Awry" — Backendal, Haller, Paterson (ETH Zurich), IEEE S&P 2023

**Five attacks, all from basic crypto mistakes:**
1. RSA key recovery via missing integrity protection on encrypted private keys (6 logins to recover)
2. Plaintext recovery via AES-ECB under a single master key with no key separation
3. AES-ECB structural weakness — no integrity checks, enabling manipulation
4. Framing attack — inserting forged files indistinguishable from legitimate uploads
5. Integrity attack — single known plaintext-ciphertext pair sufficient

**Root causes:** Key reuse across functions, unauthenticated encryption for key material, AES-ECB mode (no diffusion, no authentication), no key separation between encryption contexts, non-standard crypto implementations.

**How vault avoids every one:**
1. No long-lived keys. Each file has an ephemeral random key. No key recovery possible.
2. AES-256-GCM, not ECB. Authenticated encryption with unique key per file.
3. GCM provides authentication. Any tampering is detected.
4. No shared key context between files. Each upload is cryptographically independent.
5. No key reuse. No opportunity for known-plaintext correlation.

**Source:** https://eprint.iacr.org/2022/959 (T1), https://mega-awry.io/ (T1)

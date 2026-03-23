# vault

[![CI](https://github.com/Giuseppe552/vault/actions/workflows/ci.yml/badge.svg)](https://github.com/Giuseppe552/vault/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-23_passing-brightgreen)](https://github.com/Giuseppe552/vault)
[![Crypto deps](https://img.shields.io/badge/crypto_deps-0-blue)](https://github.com/Giuseppe552/vault)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

Encrypted document exchange. Files are encrypted in your browser with AES-256-GCM before they leave your device. The server stores only ciphertext. The decryption key exists only in the URL you share.

## How it works

1. Drop a file. It's encrypted in your browser.
2. The encrypted blob is uploaded to the server. The key is not.
3. You get a link: `https://vault.example.com/d/abc123#K7xP2mN9qR4sT6vW`
4. The part after `#` is the encryption key. It's never sent to the server.
5. The recipient opens the link. Their browser downloads the ciphertext and decrypts it locally.
6. The server deletes the blob after download (or after expiry).

## Cryptography

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Encryption | AES-256-GCM (Web Crypto API) | Only native AEAD in browsers. Hardware-accelerated. |
| Key | 128-bit random (`crypto.getRandomValues`) | In the URL fragment. Exceeds GCM birthday bound. |
| Key expansion | HKDF-SHA256 | Derives encryption key from URL key. Clean key separation. |
| Nonce | 96-bit random per file | One key per file = zero nonce reuse risk. |
| Password (optional) | Authentication only, not encryption | Server-side gate. Doesn't weaken encryption if absent. |

Reference: Bitwarden Send uses the same key delivery model.

## What the server sees

- The encrypted blob (ciphertext)
- File size
- Upload/download IP addresses and timestamps
- Whether a password was set (not the password itself)

## What the server never sees

- The file contents
- The file name (encrypted client-side)
- The encryption key (only in the URL fragment)
- The password (only a hash)

## Limitations

These apply to all browser-based encryption tools. Most don't state them.

1. **The server delivers the code.** A compromised server could serve modified JavaScript that captures keys. For high-assurance use, verify against the source code.

2. **The key is in the URL.** Browser history, cloud sync, and extensions with page access can read it.

3. **PBKDF2 is GPU-friendly.** If you add a password, it's authentication only. The encryption key is the random URL value.

4. **File size is visible.** Ciphertext reveals plaintext size (to within 28 bytes).

5. **IP addresses are visible.** The server sees uploader and downloader IPs.

6. **Deletion is best-effort.** Storage backups and browser caches may retain copies.

7. **JavaScript can't wipe memory.** Keys persist in heap until garbage collection.

8. **Extensions can read everything.** A browser extension with page access can read the key and decrypted content.

9. **Screenshots exist.** Once decrypted, content can be screen-captured.

10. **Abuse is possible.** Zero-knowledge means no content scanning. Rate limits and takedowns are the only mitigation.

Full research: [/research/](/research/)

## Stack

- **Frontend:** Vanilla TypeScript, Vite, Web Crypto API (zero external crypto deps)
- **Backend:** Cloudflare Workers (Hono), R2 (blob storage), D1 (metadata)

## Tests

```bash
cd apps/web && npm test
```

23 tests covering key generation, HKDF derivation, encrypt/decrypt round-trips (empty, 1 byte, 1MB), failure modes (wrong key, tampered data, truncated ciphertext), base64url encoding, and memory wiping.

## License

MIT

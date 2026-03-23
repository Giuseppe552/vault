# Honest Limitations

These are stated plainly in the tool, the README, and the project page. Each traces to a specific research finding.

## 1. The server delivers the code
A compromised server could serve modified JavaScript that captures encryption keys before encryption. This is a fundamental limitation of all browser-based encryption. For high-assurance use cases, verify the served code against the open-source repository.

**Source:** `03-code-delivery-problem.md` — Tony Arcieri analysis (T3), Mega-Awry paper (T1)

## 2. The key lives in the URL
The encryption key is in the URL fragment. It is stored in browser history, may sync to cloud accounts (Chrome Sync, Firefox Sync), and is readable by browser extensions with page access. Sharing the link via chat, email, or SMS transmits the key in cleartext through those channels.

**Source:** `02-key-delivery.md` — RFC 3986 (T1), Chrome Extensions docs (T2)

## 3. PBKDF2 is the only password KDF available
The Web Crypto API does not support Argon2 or scrypt. PBKDF2 is GPU-friendly. The optional password is authentication only — the encryption key is the random value in the URL, not derived from your password. A brute-forced password bypasses the download gate but cannot decrypt the file without the URL.

**Source:** `01-cryptographic-choices.md` — OWASP Password Storage Cheat Sheet (T2), Web Crypto API spec (T1)

## 4. File size is visible
The encrypted blob is the same size as the original file (plus 28 bytes for nonce + auth tag). The server and any network observer knows the file size.

**Source:** `06-metadata-leaks.md` — standard traffic analysis research (T1)

## 5. IP addresses are visible
The server sees both the uploader's and downloader's IP addresses, timestamps, and User-Agent strings. Use Tor or a VPN if you need sender/receiver anonymity.

**Source:** `06-metadata-leaks.md`

## 6. Deletion is best-effort
When a file expires or is downloaded (one-time mode), the server deletes the encrypted blob from storage. However:
- Cloud storage providers may retain data in backups
- CDN edge caches may hold copies
- The receiver's browser cache, download folder, and temp files retain the decrypted file

`Cache-Control: no-store` is set on all responses but browser compliance is not guaranteed.

**Source:** `06-metadata-leaks.md`

## 7. JavaScript cannot wipe memory
There is no `memzero()` in JavaScript. Key material stored in `Uint8Array` buffers may persist in the JavaScript heap after being overwritten, due to garbage collection, JIT compilation, and OS memory swapping. The W3C Web Crypto API spec explicitly disclaims responsibility for key material persistence.

`CryptoKey` objects with `extractable: false` are used where possible, keeping key material in the browser engine's native memory rather than the JavaScript heap. This is better but still not guaranteed.

**Source:** `07-browser-security-model.md` — W3C Web Crypto API spec §6.1 (T1)

## 8. Browser extensions can read everything
A browser extension with `<all_urls>` permission or host permission on vault's domain can:
- Read `window.location.hash` (the encryption key)
- Read the DOM (any decrypted content rendered to the page)
- Intercept network requests

There is no defence against a malicious browser extension.

**Source:** `07-browser-security-model.md` — Chrome Extensions Content Scripts docs (T2)

## 9. Screenshots and screen capture cannot be prevented
Once decrypted content is on screen, it can be captured by OS screenshot tools, screen recording, print-to-PDF, or a phone camera. No DRM-style prevention is attempted. CSS tricks like `user-select: none` are trivially bypassed and provide false security.

**Source:** `07-browser-security-model.md`

## 10. The tool can be used for abuse
Zero-knowledge encryption means content cannot be scanned. The tool can be used to share malware, stolen data, or illegal content — the same way Firefox Send was used before Mozilla shut it down. Rate limiting, file size caps, and link takedown are the only mitigations. Content scanning is not possible without breaking the encryption promise.

**Source:** `05-abuse-vectors.md` — Firefox Send shutdown (T2)

---

## Why state these?

Every encrypted file sharing tool has these limitations. Almost none state them clearly. The ones that do (Bitwarden) earn more trust than the ones that claim "zero knowledge" and bury the caveats (MEGA).

The limitations section is not a weakness of the project. It is the part that makes senior engineers take it seriously. Anyone can build AES-256-GCM encryption. Knowing — and stating — where it fails is what separates engineering from marketing.

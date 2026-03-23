# Design Decisions

Every decision traced to research. Read the referenced file for full context.

## Architecture

| Component | Choice | Source |
|-----------|--------|--------|
| Encryption | AES-256-GCM via Web Crypto API | `01-cryptographic-choices.md` — only native AEAD in browsers |
| Key generation | 128-bit random via `crypto.getRandomValues()` | `01-cryptographic-choices.md` — exceeds GCM birthday bound |
| Key expansion | HKDF-SHA256 → 256-bit encryption key | `01-cryptographic-choices.md` — clean key separation (RFC 5869) |
| Key delivery | URL fragment (`#key`) | `02-key-delivery.md` — fragment never sent to server (RFC 3986) |
| Optional password | Authentication only (server-side gate) | `01-cryptographic-choices.md` — separation of auth and encryption |
| Password KDF | PBKDF2-SHA256 ≥ 600,000 iterations | `01-cryptographic-choices.md` — only option in Web Crypto |
| Storage | Cloudflare R2 (encrypted blobs only) | `03-code-delivery-problem.md` — static hosting reduces trust surface |
| Backend | Cloudflare Workers (upload/download endpoints) | Stateless, edge-deployed, no persistent server |
| Frontend | Static HTML/JS on Cloudflare Pages | `03-code-delivery-problem.md` — minimise code delivery surface |
| Expiry | Server-side TTL (24h default, 7d max) + `Cache-Control: no-store` | `06-metadata-leaks.md` |

## Encryption flow

### Upload:
1. User drops file in browser
2. `crypto.getRandomValues(new Uint8Array(16))` → 128-bit random key
3. HKDF-SHA256(key, salt="vault-enc", info="aes-256-gcm") → 256-bit encryption key
4. `crypto.getRandomValues(new Uint8Array(12))` → 96-bit nonce
5. AES-256-GCM encrypt(plaintext, derived_key, nonce) → ciphertext + auth tag
6. Upload `{nonce || ciphertext || tag}` to server
7. Server returns blob ID
8. Construct URL: `https://vault.example.com/d/{blobId}#{base64url(key)}`
9. Display URL to user. Key never leaves the browser except in the URL.

### Download:
1. User opens URL
2. JavaScript reads `window.location.hash` → base64url decode → 128-bit key
3. `history.replaceState()` to strip fragment from history
4. Fetch encrypted blob from server
5. HKDF-SHA256(key, salt="vault-enc", info="aes-256-gcm") → 256-bit encryption key
6. Extract nonce from first 12 bytes of blob
7. AES-256-GCM decrypt(ciphertext, derived_key, nonce) → plaintext
8. Create Blob URL, trigger download
9. Zero out key buffer (best effort)
10. Server deletes blob (one-time download)

### With optional password:
- Upload: server stores bcrypt/PBKDF2 hash of password alongside blob
- Download step 2.5: server prompts for password, verifies against hash, returns blob only if correct
- Password never touches the encryption. It's a server-side access gate.

## Security headers

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store, no-cache, must-revalidate
```

**Why each header matters:**
- CSP `default-src 'none'`: no scripts, styles, images from external sources. Nothing loaded that isn't ours.
- `script-src 'self'`: only our own JavaScript executes. No CDN, no external scripts.
- `frame-ancestors 'none'`: can't be embedded in iframes (clickjacking prevention)
- `Referrer-Policy: no-referrer`: no URL information leaks to any external resource
- COOP/COEP/CORP: full cross-origin isolation
- `Cache-Control: no-store`: browser should not cache any response

## Rate limits

| Endpoint | Limit | Purpose |
|----------|-------|---------|
| Upload | 10/hour per IP | Prevent bulk abuse |
| Download | 60/hour per IP | Prevent brute-force of blob IDs |
| Password attempt | 5/minute per blob | Prevent password brute-force |

## What vault explicitly does NOT do

- No file type detection or content scanning
- No analytics, tracking, or third-party scripts
- No accounts or user registration
- No cookies (stateless)
- No DRM or copy protection on downloaded files
- No claim of protection against browser extensions, screenshots, or memory forensics
- No claim of sender/receiver anonymity (IPs are visible to server)

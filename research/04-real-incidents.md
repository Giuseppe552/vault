# Real Incidents — Encrypted File Sharing Failures

Ordered by research quality and relevance to vault's design.

## Tier 1 (Peer-reviewed / Official disclosures)

### MEGA.nz — "Malleable Encryption Goes Awry" (2022)

**Source:** https://eprint.iacr.org/2022/959 (IEEE S&P 2023)
**Attack site:** https://mega-awry.io/
**Researchers:** Backendal, Haller, Paterson (ETH Zurich)
**Quality:** T1 — peer-reviewed, published at top-tier venue

**What happened:** Five distinct attacks compromising confidentiality and integrity of MEGA's "zero knowledge" encryption:

1. **RSA key recovery** — Encrypted RSA private keys had no integrity protection. Server tampers with keys during login, client leaks key bits through the session ID exchange. Originally 512 logins to fully recover; later reduced to **6 logins** by UC San Diego researchers (Len, Koppel, Rescorla, Morrison).

2. **Plaintext recovery** — AES-ECB mode under a single master key. No key separation between different encryption contexts.

3. **Ciphertext manipulation** — No authentication on encrypted data. Attacker modifies ciphertext without detection.

4. **Framing attack** — Inserting forged files into a user's account, indistinguishable from legitimate uploads.

5. **Integrity attack** — Needs only a single known plaintext-ciphertext pair (obtainable from any public file share).

**Root causes:**
- Key reuse across encryption contexts (one master key for everything)
- AES-ECB mode (no diffusion, no authentication)
- No authenticated encryption for key material
- Non-standard cryptographic constructions
- No key separation via HKDF or similar

**Relevance to vault:** Every one of these failures is avoided by using AES-256-GCM with ephemeral per-file keys expanded via HKDF. The Mega paper is the single most important reference for why these specific choices matter.

---

### OnionShare — 9 CVEs (January 2022)

**Source:** Open Technology Fund security audit, conducted by Radically Open Security
**Quality:** T1 — funded audit with published report

**CVEs found:**
- OTF-001 (HIGH): Unsanitised URL path parameters passed to QT frontend — injection risk
- OTF-014 (HIGH): Denial of service via QT image parsing
- OTF-003 (MODERATE): Chat participant impersonation
- OTF-004 (MODERATE): Channel exit message spoofing
- OTF-012 (MODERATE): Upload rate limiting set to 100/sec — enables DoS
- OTF-005 (LOW): Username manipulation via trailing whitespace
- OTF-006 (LOW): CSP configuration issues
- OTF-009 (LOW): Unauthenticated messaging in public mode
- OTF-013 (LOW): Insufficient filesystem access restrictions

**Relevance to vault:** Input sanitisation, rate limiting, and CSP are all relevant. The high-severity findings were from trusting user-controlled URL parameters — vault must validate all inputs from the URL before any processing.

---

## Tier 2 (Authoritative reports / Official statements)

### Firefox Send — Abuse-driven shutdown (2020)

**Source:** Mozilla blog post, BleepingComputer, The Register reporting
**Quality:** T2 — official Mozilla statement + confirmed by security journalists

**What happened:**
- Mozilla launched Firefox Send in 2019 as an encrypted file-sharing service
- Malware operators discovered it was ideal for C2 payload delivery:
  - Trusted mozilla.org subdomain (bypasses corporate URL filters)
  - Files encrypted end-to-end (can't be scanned by security tools)
  - Automatic expiry (evidence self-destructs)
  - No account required
- Used for spear-phishing campaigns, malware distribution, and ransomware delivery
- Mozilla suspended the service in July 2020 and never reopened it
- Mozilla statement: "some abusive users were beginning to use Send to ship malware and conduct spear phishing attacks"

**Root cause:** Not a cryptographic failure. The design was sound. The problem was operational: zero-knowledge encryption + trusted domain + no-account uploads = perfect abuse infrastructure.

**Relevance to vault:** THE critical lesson. vault must either:
1. Accept the same abuse risk (and state it)
2. Require some form of identity (email, rate limit by IP)
3. Not host on a "trusted" domain (`.com` is less trusted than `mozilla.org`)

The Firefox Send failure is the reason vault should have rate limiting, size caps, and link takedown — even though none of these prevent abuse by a determined actor.

---

### FBI IC3 — Business Email Compromise statistics (2024)

**Source:** https://www.ic3.gov/PSA/2024/PSA240911
**Quality:** T2 — US federal law enforcement data

**Key data:**
- $55 billion in BEC losses globally between 2013–2023
- $2.7 billion in reported losses in 2024 alone
- 256,256 complaints with confirmed financial loss

**Relevance to vault:** Not directly about file sharing, but about the consequences of email spoofing. vault's existence is partly justified by the fact that email is not a secure document delivery channel. This stat belongs in the project page narrative.

---

## Tier 3 (Expert analysis)

### Tony Arcieri — "The Limits of Browser Crypto"

**Source:** Blog post / conference talks by Tony Arcieri (creator of the `age` encryption tool, former iMessage security engineer at Apple)
**Quality:** T3 — named expert, widely cited in cryptographic engineering community

**Key argument:** Browser-based "zero knowledge" encryption fundamentally conflicts with the browser security model. The browser is designed to download and execute code from the server on every page load. There is no mechanism for the browser to verify that the code being served is the code that was audited. SRI doesn't solve this because the HTML page containing the SRI attributes is itself served by the untrusted server.

**Relevance to vault:** This is why vault must state the code delivery limitation prominently, not bury it in a FAQ.

---

### Soatok — Cryptographic algorithm recommendations

**Source:** Soatok's blog (furry cryptographer, respected in applied crypto community)
**Quality:** T3 — named expert, well-sourced posts

**Key recommendations:**
- XChaCha20-Poly1305 for software implementations (constant-time without hardware support)
- AES-256-GCM when hardware acceleration is available (which it is in all modern browsers via Web Crypto)
- HKDF for key derivation from high-entropy sources (like random keys)
- PBKDF2 only when Argon2 is unavailable (which it is in Web Crypto)

**Relevance to vault:** Confirms AES-256-GCM + HKDF as the correct choice for browser-based encryption with ephemeral keys.

---

### W3C Web Crypto API — Security disclaimers

**Source:** https://www.w3.org/TR/WebCryptoAPI/#security
**Quality:** T1 — W3C specification

**Key disclaimers (direct quotes):**
- "does not guarantee that the underlying cryptographic key material will not be persisted to disk, possibly unencrypted"
- "No normative requirements on how implementations handle key material once all references to it go away"
- No constant-time guarantees mandated by the spec (though browser implementations use native C++ crypto libraries which are typically constant-time)

**Relevance to vault:** Memory management and key persistence are stated limitations. JavaScript has no `memzero()` equivalent.

---

## Tier 4 (Contextual)

### magic-wormhole — Low-entropy codes

**Source:** GitHub repository, protocol documentation
**Quality:** T4 — open source project documentation

**Issue:** Default nameplate codes have 16-bit entropy (1-in-65,536 chance of MITM). An attacker with network access to the mailbox server can attempt connections with guessed codes.

**Relevance to vault:** vault uses 128-bit random keys, not short human-readable codes. This attack doesn't apply, but it illustrates why high-entropy keys matter.

---

### Keybase — Acquisition and trust death (2020)

**Source:** Zoom acquisition announcement, community analysis
**Quality:** T4 — news reporting

**What happened:** Keybase was acquired by Zoom in May 2020. The team was absorbed, the product was deprioritized, and updates effectively stopped. Users who trusted Keybase for encrypted file storage found their trust model invalidated by a corporate acquisition.

**Relevance to vault:** vault is open source under MIT license, not a service. If Giuseppe stops maintaining it, anyone can fork it. The tool doesn't depend on a service provider's continued existence.

---

### Bitwarden Send — Reference architecture

**Source:** https://bitwarden.com/help/send-encryption/
**Quality:** T3 — vendor documentation for open-source product

**Architecture:**
- 128-bit random key generated client-side
- HKDF-SHA256 to derive 512-bit encryption key
- AES-256-CBC + HMAC-SHA256 for content encryption
- Optional password is authentication-only (server-side check)
- URL fragment contains the key, never sent to server

**Relevance to vault:** This is the reference implementation. vault follows the same model with one improvement: AES-256-GCM (single-pass AEAD) instead of CBC+HMAC (two-pass).

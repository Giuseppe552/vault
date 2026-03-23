# Key Delivery — URL Fragment Model

## How it works

The encryption key is placed in the URL fragment (after `#`). Example:
```
https://vault.example.com/d/abc123#K7xP2mN9qR4sT6vW
```

The fragment (`#K7xP2mN9qR4sT6vW`) is never sent to the server in any HTTP request, including:
- The initial page load
- Referer headers to third-party resources
- Redirects

**Source:** RFC 3986 §3.5 (T1) — "the fragment identifier is not used in the scheme-specific processing of a URI"

## Where the fragment DOES leak

### Browser history (HIGH RISK)
The full URL including fragment is stored in `window.history` and the browser's history database. Anyone with access to the browser — shared computer, forensic extraction, shoulder surfing — can recover the key.

**Mitigation:** Use `history.replaceState()` to strip the fragment after reading it. This removes it from the history entry but NOT from the address bar during the session.

**Source:** MDN History API documentation (T2)

### Browser sync (HIGH RISK)
Chrome, Firefox, and Edge sync browsing history to cloud accounts. A compromised Google/Firefox/Microsoft account = compromised keys for every vault link the user visited.

**Mitigation:** None within the tool's control. State this limitation. Recommend incognito/private browsing for sensitive transfers.

**Source:** Chrome sync documentation (T4), empirically verified behaviour

### Browser extensions (HIGH RISK)
Content scripts run in an isolated world but CAN read `window.location.hash`. Any extension with `<all_urls>` or host permission on your domain can extract the key.

**Mitigation:** None. State this limitation. "A malicious browser extension can read the encryption key from the URL."

**Source:** Chrome Extensions Content Scripts documentation (T2), https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts

### Copy-paste (MEDIUM RISK)
Users will paste the full URL into Slack, email, SMS, WhatsApp. The key travels with the link. This is by design — the alternative (separate key delivery) destroys usability.

**Mitigation:** UI can warn "This link contains the encryption key. Share it carefully." But users will paste it anyway.

### URL shorteners (MEDIUM RISK)
Most URL shorteners strip fragments. But some preserve them. If a user pastes the full URL into a shortener that logs the fragment, the key is exposed.

**Mitigation:** Document this risk. Consider detecting URL shortener referers and warning.

### window.opener (LOW RISK)
If the page opens external links with `target="_blank"` without `rel="noopener"`, the opened page can read `window.opener.location` including the fragment.

**Mitigation:** Always set `rel="noopener noreferrer"` on all external links. Use `Cross-Origin-Opener-Policy: same-origin` header.

**Source:** MDN Window.opener documentation (T2)

### Crash reports / telemetry (LOW RISK)
Browser crash reporters may include the current URL. Analytics tools injected by extensions can capture it.

**Mitigation:** None within the tool's control.

## The Bitwarden Send Model (reference implementation)

Bitwarden Send uses this exact architecture:
1. Generate 128-bit random key
2. Derive 512-bit encryption key from it using HKDF-SHA256
3. Encrypt content with the derived key
4. Put the 128-bit key in the URL fragment
5. Optional password is authentication-only (server-side gate), not encryption

This is the correct design. The key is the entropy. The password is access control. They are independent.

**Source:** Bitwarden Send architecture documentation (T3), https://bitwarden.com/help/send-encryption/

## Design decision

vault uses the Bitwarden Send model:
- 128-bit random key in URL fragment
- HKDF-SHA256 to derive AES-256-GCM encryption key
- Optional password for authentication only
- Fragment stripped from history via `replaceState` after reading
- All limitations stated honestly

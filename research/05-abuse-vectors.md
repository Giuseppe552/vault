# Abuse Vectors

## The fundamental tension

Zero-knowledge encryption means the server cannot see file contents. If the server cannot see contents, it cannot scan for:
- Malware (ransomware payloads, trojans, C2 droppers)
- CSAM
- Stolen data (credential dumps, PII databases)
- Copyrighted material

**You must choose:**
1. True zero-knowledge → no content scanning → abuse is possible
2. Content scanning → not zero-knowledge → the security promise is broken

There is no middle ground. Firefox Send chose option 1 and died from it. Google Drive chose option 2 and can read your files.

## The Firefox Send playbook (how attackers used it)

**Source:** BleepingComputer, Sophos analysis (T3/T4)

Attackers used Firefox Send because:
1. **Trusted domain** — `send.firefox.com` is a Mozilla domain. Corporate URL filters whitelist it. Email spam filters trust it.
2. **Encryption** — Files are encrypted. Security tools scanning network traffic see only an HTTPS request to a trusted domain.
3. **Auto-expiry** — Links expire after download count or time. Evidence self-destructs.
4. **No account required** — No identity trail. Upload anonymously.
5. **Free** — No payment trail either.

Attack pattern:
1. Attacker creates malware payload
2. Uploads to Firefox Send, gets encrypted link
3. Emails link to target in spear-phishing campaign
4. Target clicks trusted Mozilla link, downloads malware
5. Link expires, evidence gone

**This will happen to any zero-knowledge file sharing tool that gets popular enough.** The question is not whether, but when.

## Mitigations that preserve zero-knowledge

| Mitigation | Effectiveness | Notes |
|---|---|---|
| Rate limiting per IP | Low-medium | Slows automated abuse. Trivially bypassed with proxies. |
| File size cap (e.g., 100MB) | Low | Malware payloads are typically small (< 10MB). |
| Download count cap | Low | One download is enough for targeted attacks. |
| Expiry time cap (24h/7d) | Low | Attacks are executed within hours. |
| Email verification for upload | Medium | Creates identity trail. Deters casual abuse. Doesn't stop determined attackers with throwaway emails. |
| Abuse reporting URL | Medium | Recipients can flag links. Server deletes the blob. Reactive, not preventive. |
| Link takedown API | Medium | Cooperate with abuse reports. Delete blobs when notified. |
| CAPTCHA on upload | Low-medium | Stops automated abuse. Doesn't stop manual uploads. |
| IP logging | High (for law enforcement) | Doesn't prevent abuse but enables investigation. |
| Terms of service | Legal protection | Doesn't prevent anything but establishes legal basis for takedown. |

## Design decisions for vault

1. **Accept the tradeoff.** vault is zero-knowledge. Content scanning is impossible and will not be attempted.
2. **Rate limit uploads** — per IP, reasonable cap (e.g., 10 uploads/hour).
3. **File size cap** — 100MB. Covers documents. Doesn't cover video (most abuse is smaller files anyway).
4. **Expiry** — maximum 7 days, default 24 hours. Files auto-delete from storage.
5. **Download count** — default 1 (one-time download), maximum 10.
6. **Abuse reporting** — link on download page: "Report this file." Deletes the encrypted blob.
7. **IP logging** — server logs upload and download IPs. Retained for 30 days. Stated in privacy policy.
8. **No email verification** — for v1. Adds friction that hurts legitimate use more than it hurts attackers.
9. **State the limitation** — "This tool can be used to share malware. Content scanning is not possible without breaking the encryption. Rate limits and takedowns are the only mitigations."

## What vault is NOT

vault is not a platform. It's not a service with millions of users. It's a tool on a personal domain used by people who found it through the portfolio. The Firefox Send problem happened at Mozilla scale (~1M monthly users on a trusted domain). vault at its scale is not an attractive target for malware operators — the domain is unknown, there are no corporate whitelist benefits, and the rate limits make bulk use impractical.

If vault ever reaches a scale where abuse becomes a real operational concern, that's the moment to consider whether it needs email verification, a separate domain, or a business entity to handle legal obligations.

**Source:** Mozilla Firefox Send shutdown statement (T2), Sophos analysis of Send abuse (T3), BleepingComputer reporting (T4)

# Metadata Leaks

Zero-knowledge encryption protects file contents. It does NOT protect metadata. The server and any network observer can see:

## File size

**What leaks:** The ciphertext is the plaintext + 16 bytes (GCM auth tag) + 12 bytes (nonce). An observer knows the file size to within 28 bytes.

**Why it matters:** A 47KB file is probably a document. A 4.7MB file is probably a scanned image. An 800-byte file is probably a short text. File size is a fingerprint.

**Mitigation:** Padding. Add random bytes to a fixed bucket size (e.g., round up to nearest 64KB). Reduces precision but increases storage cost and adds complexity. Not implemented in v1.

**Implemented mitigation:** None. Stated as limitation.

**Source:** Traffic analysis research (T1 — numerous academic papers on traffic analysis via packet sizes)

## Timing correlation

**What leaks:** Upload timestamp + download timestamp + file size. If Alice uploads a 4.7MB file at 14:03 and Bob downloads a 4.7MB file at 14:05, an observer can correlate sender and receiver.

**Who can see this:** The server (always), the hosting provider (always), ISPs of both parties.

**Mitigation:** Tor for both upload and download hides IPs. Delay between upload and download reduces timing correlation. Neither is practical for document exchange between professionals.

**Implemented mitigation:** None. Stated as limitation. "The server sees both uploader and downloader IP addresses. Use Tor if you need sender/receiver anonymity."

**Source:** Standard traffic analysis research (T1)

## IP addresses

**What leaks:** Uploader IP, downloader IP, timestamps, User-Agent, request headers.

**Why it matters:** The server can correlate who sent what to whom. Even without decrypting content, the communication pattern is visible.

**Mitigation:** Tor, VPN. The tool cannot enforce this.

**Implemented mitigation:** Server retains IP logs for 30 days (for abuse response). Stated in privacy policy.

## Access patterns

**What leaks:** How many files a user uploads, how many times each link is accessed, geographic distribution of downloaders (from IPs), whether a link was ever accessed (the "read receipt" problem).

**Why it matters:** Pattern analysis. A user who uploads 50 files/day to 50 different recipients has a different profile than someone who uploads one file to one recipient.

**Mitigation:** Rate limiting normalises upload patterns. But download patterns are visible.

## Browser cache and download history

**What leaks:** After the receiver downloads and decrypts the file, a copy exists in:
- Browser download history
- The download folder on disk
- Browser cache (if `Cache-Control: no-store` is not respected)
- IndexedDB (if the app uses it for temp storage)
- OS temp files (during blob creation)

**Mitigation:** Set `Cache-Control: no-store, no-cache, must-revalidate` on all responses. Don't use IndexedDB. Advise users to delete downloaded files after use. Accept that the tool cannot control what happens after the file leaves the browser.

**Source:** W3C Cache-Control spec (T1), browser cache behaviour documentation (T2)

## Design decisions

1. **No padding in v1.** Adds complexity, marginal benefit for document exchange use case.
2. **Cache-Control: no-store** on all responses.
3. **State all metadata limitations** honestly.
4. **IP logging** for 30 days, stated in privacy policy.
5. **Do not claim anonymity.** vault protects content, not metadata.

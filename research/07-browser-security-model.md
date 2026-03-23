# Browser Security Model

## Extensions

### What extensions CAN do:
- Read `window.location.hash` (the encryption key) from content scripts
- Read the entire DOM (all rendered/decrypted content)
- Intercept network requests (webRequest API)
- Access clipboard contents
- Read cookies and localStorage

### What extensions CANNOT do:
- Read JavaScript variables in the page's execution context (isolated world)
- Access Web Crypto API `CryptoKey` objects (non-extractable keys stay in the browser engine)

### The reality:
Any extension with `<all_urls>` or host permission on your domain can extract the key from `window.location.hash` AND read any decrypted content rendered to the DOM. There is NO defence against this within the browser's security model.

**Mitigation:** None. State this limitation.

**Source:** Chrome Extensions Content Scripts documentation (T2), https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts

## DevTools

- Network tab shows all fetch requests (encrypted blobs in transit)
- Console shows JavaScript execution including crypto operations
- Memory inspector can dump heap including key material
- Application tab shows storage (localStorage, IndexedDB, cookies)

**This is expected behaviour.** A user with DevTools open can see everything. This is not a vulnerability — it's the browser working as designed.

## Memory persistence (the memzero problem)

### The problem:
JavaScript has no equivalent of `memzero()` or `sodium_memzero()`. When you store a key in a `Uint8Array`:
- Setting all bytes to 0 (`arr.fill(0)`) may work, but the original data may exist in:
  - Other heap locations (GC may have moved the buffer)
  - JIT compiler intermediate representations
  - V8's old-space or new-space if the buffer was promoted
- The garbage collector frees memory on its own schedule
- Freed memory may be swapped to disk by the OS

### W3C acknowledgement:
The Web Crypto API spec explicitly states:
> "does not guarantee that the underlying cryptographic key material will not be persisted to disk, possibly unencrypted"
> "No normative requirements on how implementations handle key material once all references to it go away"

### What CryptoKey provides:
When you import a key as `CryptoKey` with `extractable: false`, the key material lives in the browser engine's C++ memory, not in JavaScript heap. This is better than storing raw bytes in a `Uint8Array`:
- The key cannot be read back from JavaScript
- The browser engine may use OS-specific secure memory (though the spec doesn't require it)
- The key is still not guaranteed to be wiped after use

### Design decisions:
1. Use `CryptoKey` objects with `extractable: false` wherever possible
2. Minimise the time raw key bytes exist in JavaScript (convert to CryptoKey immediately)
3. Zero out `Uint8Array` buffers after use (`arr.fill(0)`) — best effort, not guaranteed
4. State the limitation: "Key material may persist in browser memory after use. JavaScript provides no mechanism to guarantee memory wiping."

**Source:** W3C Web Crypto API spec §6.1 (T1), https://www.w3.org/TR/WebCryptoAPI/#security

## Screenshots and screen capture

Once decrypted content is rendered in the browser:
- OS-level screenshot tools capture it
- `getDisplayMedia()` (screen sharing) captures it
- Print-to-PDF captures it
- A phone camera pointed at the screen captures it
- CSS `user-select: none` and `print { display: none }` are trivially bypassed

**No technical solution exists.** DRM-style protections (Widevine, FairPlay) are available for video streams but not for arbitrary HTML content, and they are also bypassed routinely.

**Design decision:** Do not attempt to prevent screenshots. Do not add `user-select: none` or other theatre. State the limitation honestly: "Once content is decrypted and displayed, it can be captured by any screen recording tool."

## Cross-origin security

- `Cross-Origin-Opener-Policy: same-origin` — prevents other tabs from accessing `window.opener.location`
- `Cross-Origin-Embedder-Policy: require-corp` — prevents the page from being embedded in other contexts
- `Cross-Origin-Resource-Policy: same-origin` — prevents other origins from fetching resources

**All three headers should be set.** They reduce the attack surface from other tabs and frames.

**Source:** MDN COOP/COEP/CORP documentation (T2)

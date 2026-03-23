# The Code Delivery Problem

This is the most fundamental limitation of browser-based encryption. Every design decision in vault must acknowledge it.

## The problem

The server delivers the JavaScript that performs the encryption. A compromised or malicious server can:

1. Serve modified JavaScript that sends the decryption key to the attacker before encrypting
2. Target specific users while serving clean code to everyone else (selective compromise)
3. Modify the code on any request — there is no persistent binary to verify against

**This is not a hypothetical.** It is how the MEGA attacks worked. The server is in the trust chain whether you want it to be or not.

## Why SRI doesn't solve it

Subresource Integrity (SRI) lets you pin script hashes:
```html
<script src="crypto.js" integrity="sha384-abc123...">
```

The browser verifies the script matches the hash before executing it. But:

**The HTML page that contains the SRI attribute is itself served by the server.** A compromised server changes both the script AND the SRI hash in the same response. The browser sees a valid SRI check for the malicious script.

SRI only protects against CDN compromise (a third-party serving modified scripts). It does NOT protect against the origin server itself.

**Source:** W3C Subresource Integrity spec (T1), Tony Arcieri's analysis of MEGA (T3)

## Tony Arcieri's analysis

Tony Arcieri (cryptographer, creator of the `age` encryption tool) on browser-based crypto:

> "Trust No One" services that attempt to prevent the service provider from accessing plaintext fundamentally conflict with the browser security model. The browser is "an engine for remote code execution" that downloads and runs code from servers on every page load.

The browser was designed to trust the server. Every page load is a fresh code delivery. There is no mechanism for a browser to verify that the code being served matches a known-good version without trusting an external party (extension developer, audit report, etc.).

**Source:** Tony Arcieri, "The Limits of Browser Crypto" (T3)

## Partial mitigations

| Mitigation | What it does | What it doesn't do |
|---|---|---|
| Open source | Lets anyone audit the code | Doesn't prove the served code matches the repo |
| Reproducible builds | Same source → same output → verifiable hash | Doesn't prevent the server from serving different code |
| Browser extension (code verifier) | Extension checks served code against known hash | Shifts trust to extension developer. Tiny user base. |
| Static hosting (Vercel, CF Pages) | Reduces server-side attack surface vs dynamic servers | Hosting platform can still modify files |
| Publish build hashes per release | Gives auditors a reference point | Only useful if someone actually checks |
| Native client (CLI/desktop app) | Downloaded once, runs locally, no server on each use | Loses the convenience that makes the tool useful |

## Design decision for vault

1. **State the limitation plainly** in the README, project page, and in-app. "The server delivers the code. A compromised server could capture your encryption key."
2. **Publish SRI hashes** for each release. Not a solution, but a reference point for auditors.
3. **Minimise the trust surface**: static hosting (Cloudflare Pages), no server-side rendering, no dynamic code generation. The served files are the build output.
4. **Recommend the CLI** for high-assurance use cases (if built later).
5. **Do not claim "zero knowledge"** without this caveat. Every other tool claims "zero knowledge" and buries this limitation in a FAQ. vault states it in the first screen.

## Comparison to other tools

| Tool | How they handle this | Honest? |
|---|---|---|
| MEGA | Claimed "zero knowledge". Got broken by researchers. | No |
| ProtonMail | Acknowledged the issue. Published audit. Offered bridge app. | Mostly |
| Bitwarden Send | Open source. Browser extension available. Web vault has this limitation. | Yes, in docs |
| Firefox Send | Did not address it publicly before shutdown. | No |
| vault | States it as limitation #1, above the fold, before any feature claim. | Yes |

**Source:** Mega-Awry paper (T1), ProtonMail security model docs (T3), Bitwarden architecture docs (T3)

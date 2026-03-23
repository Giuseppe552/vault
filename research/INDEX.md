# vault — Security Research Index

This directory contains pre-build security research for vault, an encrypted document exchange tool. Every design decision must trace back to a finding in these files.

## Files (read in order)

| File | What it covers | Read when |
|------|---------------|-----------|
| `01-cryptographic-choices.md` | AES-256-GCM, HKDF, PBKDF2, nonce safety, key commitment, Mega attack | Choosing any encryption parameter |
| `02-key-delivery.md` | URL fragment model, leakage vectors, Bitwarden Send analysis | Designing the link/share mechanism |
| `03-code-delivery-problem.md` | The fundamental browser trust issue, SRI limits, server compromise | Any architecture decision about where crypto runs |
| `04-real-incidents.md` | Mega 2022, Firefox Send 2020, OnionShare CVEs, magic-wormhole | Writing the project page, limitations, or comparing to alternatives |
| `05-abuse-vectors.md` | Firefox Send shutdown, C2 delivery, content scanning impossibility | Designing rate limits, takedown, abuse policy |
| `06-metadata-leaks.md` | File size, timing correlation, IP correlation, browser cache | Writing limitations, designing expiry |
| `07-browser-security-model.md` | Extensions, DevTools, memory persistence, W3C disclaimers | Any client-side security claim |
| `08-design-decisions.md` | Final architecture choices with rationale traced to research | Starting implementation |
| `09-limitations.md` | The 10 honest limitations, each with source | Writing the project page, README |

## Quality tiers

Research is tagged by source reliability:

- **T1 (Primary)**: Peer-reviewed papers, RFC specs, W3C specs, CVE database, official vendor disclosures
- **T2 (Authoritative)**: OWASP guidelines, security audit reports (funded by OTF/Mozilla/etc), FBI/ICO reports
- **T3 (Expert)**: Named security researcher blog posts (Arcieri, Ptacek, Bernstein), well-known security outlets
- **T4 (Contextual)**: News reporting, vendor blog posts, community analysis

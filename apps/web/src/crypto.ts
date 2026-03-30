/**
 * vault crypto primitives — v2.
 *
 * Upgrades from v1:
 *   1. Key commitment via HMAC-SHA256 (prevents MEGA-class multi-key attacks)
 *   2. PBKDF2-SHA256 password hashing (600k iterations, OWASP 2023 minimum)
 *   3. Authenticated associated data (binds blob metadata to ciphertext)
 *   4. Content hash for end-to-end integrity verification
 *   5. Per-file HKDF salt + version prefix for wire format evolution
 *
 * References:
 *   - Backendal, Haller, Paterson — "MEGA Isn't Enough" (IEEE S&P 2023, ePrint 2022/1242)
 *   - Bellare & Hoang — "Efficient Schemes for Committing Authenticated Encryption" (EUROCRYPT 2022)
 *   - RFC 5869 (HKDF), RFC 5116 (AEAD), OWASP Password Storage Cheat Sheet (2023)
 *   - Signal: attachment encryption uses Encrypt-then-MAC for the same key-commitment property
 *
 * All crypto uses the Web Crypto API — no external dependencies.
 */

// ── Constants ────────────────────────────────────────────────────────

/** Wire format version. Increment on breaking changes. */
export const WIRE_VERSION = 1;

const VERSION_BYTES = 2;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const COMMITMENT_BYTES = 32;
const TAG_BYTES = 16;
const KEY_BYTES = 16;

/** Overhead prepended to every ciphertext: version + salt + nonce + commitment */
export const HEADER_BYTES = VERSION_BYTES + SALT_BYTES + NONCE_BYTES + COMMITMENT_BYTES; // 62

/** PBKDF2 iteration count — OWASP 2023 minimum for SHA-256 */
const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_SALT_BYTES = 16;

// TS 5.9: generic Uint8Array doesn't satisfy BufferSource in crypto.subtle calls
const buf = (u: Uint8Array): BufferSource => u as unknown as BufferSource;

// ── Key generation ───────────────────────────────────────────────────

/** Generate a 128-bit random key. This IS the secret shared via URL fragment. */
export function generateKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(KEY_BYTES));
}

// ── Key derivation (HKDF split) ─────────────────────────────────────

/**
 * Derive two keys from a single IKM via HKDF-SHA256:
 *   enc_key — for AES-256-GCM encryption
 *   com_key — for HMAC-SHA256 key commitment
 *
 * Different `info` parameters guarantee independent keys even when
 * the salt is shared. Per RFC 5869 §3.2.
 */
async function deriveKeyPair(
  rawKey: Uint8Array,
  salt: Uint8Array,
): Promise<{ encKey: CryptoKey; comKey: CryptoKey }> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    rawKey.buffer.slice(rawKey.byteOffset, rawKey.byteOffset + rawKey.byteLength) as ArrayBuffer,
    "HKDF",
    false,
    ["deriveKey", "deriveBits"],
  );

  const encKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: buf(salt), info: buf(new TextEncoder().encode("vault-enc")) },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  // HMAC commitment key — derived from same IKM but different info
  const comKeyBits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: buf(salt), info: buf(new TextEncoder().encode("vault-commit")) },
    keyMaterial,
    256,
  );
  const comKey = await crypto.subtle.importKey(
    "raw",
    comKeyBits,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );

  return { encKey, comKey };
}

// Backwards-compatible export for tests that need to verify key derivation
export async function deriveEncryptionKey(rawKey: Uint8Array): Promise<CryptoKey> {
  const salt = new TextEncoder().encode("vault-enc"); // v1 fixed salt for compat
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    rawKey.buffer.slice(rawKey.byteOffset, rawKey.byteOffset + rawKey.byteLength) as ArrayBuffer,
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("aes-256-gcm") },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// ── Encrypt (v2 wire format) ────────────────────────────────────────

/**
 * Encrypt plaintext with AES-256-GCM + HMAC-SHA256 key commitment.
 *
 * Wire format:
 *   [0:2]   version   (uint16 big-endian)
 *   [2:18]  HKDF salt (16 random bytes)
 *   [18:30] GCM nonce (12 random bytes)
 *   [30:62] HMAC-SHA256 commitment over salt || nonce || ciphertext+tag
 *   [62:N]  AES-256-GCM ciphertext + 16-byte auth tag
 *
 * The commitment binds the ciphertext to the key material.
 * A different key produces a different HMAC, so the MEGA attack
 * (valid decryption under multiple keys) is detected before
 * the ciphertext is even touched.
 *
 * @param aad Optional additional authenticated data (blob metadata).
 *            Bound to the GCM auth tag but not encrypted.
 */
export async function encrypt(
  plaintext: ArrayBuffer,
  rawKey: Uint8Array,
  aad?: Uint8Array,
): Promise<ArrayBuffer> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const { encKey, comKey } = await deriveKeyPair(rawKey, salt);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- TS 5.9 Uint8Array generic vs BufferSource
  const gcmParams: any = { name: "AES-GCM", iv: nonce };
  if (aad) gcmParams.additionalData = aad;

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(gcmParams, encKey, plaintext),
  );

  // Key commitment: HMAC(com_key, salt || nonce || ciphertext+tag)
  const toCommit = new Uint8Array(SALT_BYTES + NONCE_BYTES + ciphertext.byteLength);
  toCommit.set(salt, 0);
  toCommit.set(nonce, SALT_BYTES);
  toCommit.set(ciphertext, SALT_BYTES + NONCE_BYTES);
  const commitment = new Uint8Array(
    await crypto.subtle.sign("HMAC", comKey, toCommit),
  );

  // Assemble wire format
  const result = new Uint8Array(HEADER_BYTES + ciphertext.byteLength);
  const view = new DataView(result.buffer);
  view.setUint16(0, WIRE_VERSION);
  result.set(salt, VERSION_BYTES);
  result.set(nonce, VERSION_BYTES + SALT_BYTES);
  result.set(commitment, VERSION_BYTES + SALT_BYTES + NONCE_BYTES);
  result.set(ciphertext, HEADER_BYTES);

  return result.buffer;
}

// ── Decrypt (v2 wire format) ────────────────────────────────────────

/**
 * Decrypt ciphertext with key commitment verification.
 *
 * Steps:
 *   1. Parse wire format header
 *   2. Re-derive key pair from raw key + salt
 *   3. Verify HMAC commitment BEFORE decrypting (reject multi-key attacks)
 *   4. Decrypt with AES-256-GCM (tag verification is automatic)
 *
 * Throws on: wrong key, tampered data, commitment mismatch, bad version.
 */
export async function decrypt(
  encrypted: ArrayBuffer,
  rawKey: Uint8Array,
  aad?: Uint8Array,
): Promise<ArrayBuffer> {
  const data = new Uint8Array(encrypted);

  if (data.byteLength < HEADER_BYTES + TAG_BYTES) {
    throw new Error("Encrypted data too short — missing header or auth tag.");
  }

  // Parse header
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const version = view.getUint16(0);
  if (version !== WIRE_VERSION) {
    throw new Error(`Unsupported wire format version: ${version}`);
  }

  const salt = data.slice(VERSION_BYTES, VERSION_BYTES + SALT_BYTES);
  const nonce = data.slice(VERSION_BYTES + SALT_BYTES, VERSION_BYTES + SALT_BYTES + NONCE_BYTES);
  const commitment = data.slice(
    VERSION_BYTES + SALT_BYTES + NONCE_BYTES,
    HEADER_BYTES,
  );
  const ciphertext = data.slice(HEADER_BYTES);

  const { encKey, comKey } = await deriveKeyPair(rawKey, salt);

  // Verify commitment BEFORE decrypting — this is the key-commitment check.
  // If a different key was used, the HMAC won't match.
  const toCommit = new Uint8Array(SALT_BYTES + NONCE_BYTES + ciphertext.byteLength);
  toCommit.set(salt, 0);
  toCommit.set(nonce, SALT_BYTES);
  toCommit.set(ciphertext, SALT_BYTES + NONCE_BYTES);
  const valid = await crypto.subtle.verify("HMAC", comKey, commitment, toCommit);
  if (!valid) {
    throw new Error("Key commitment failed — wrong key or tampered ciphertext.");
  }

  // Decrypt (GCM auth tag verification is automatic)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- TS 5.9 Uint8Array generic vs BufferSource
  const gcmParams: any = { name: "AES-GCM", iv: nonce };
  if (aad) gcmParams.additionalData = aad;

  return crypto.subtle.decrypt(gcmParams, encKey, ciphertext);
}

// ── Password hashing (PBKDF2-SHA256) ────────────────────────────────

/**
 * Hash a password with PBKDF2-SHA256 (600,000 iterations).
 *
 * OWASP 2023 minimum for SHA-256. A GPU doing 10B SHA-256/sec
 * is reduced to ~16,000 PBKDF2 guesses/sec. An 8-char password
 * goes from <1 second (SHA-256) to years.
 *
 * Returns { hash, salt } where salt is random per invocation.
 */
export async function hashPassword(
  password: string,
): Promise<{ hash: Uint8Array; salt: Uint8Array }> {
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTES));
  const hash = await hashPasswordWithSalt(password, salt);
  return { hash, salt };
}

/**
 * Verify a password against a stored hash + salt.
 */
export async function verifyPasswordHash(
  password: string,
  salt: Uint8Array,
  expectedHash: Uint8Array,
): Promise<boolean> {
  const hash = await hashPasswordWithSalt(password, salt);
  // Constant-time comparison
  if (hash.byteLength !== expectedHash.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < hash.byteLength; i++) {
    diff |= hash[i] ^ expectedHash[i];
  }
  return diff === 0;
}

async function hashPasswordWithSalt(
  password: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- TS 5.9 Uint8Array generic
      salt: salt as any,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );
  return new Uint8Array(bits);
}

// ── Content hash ────────────────────────────────────────────────────

/** SHA-256 hash of plaintext for end-to-end integrity verification. */
export async function contentHash(data: ArrayBuffer): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

// ── AAD encoding ────────────────────────────────────────────────────

/**
 * Encode blob metadata as AAD for GCM. Sorted keys, no whitespace.
 * Bound to the auth tag — changing any field invalidates decryption.
 */
export function encodeAAD(fields: Record<string, string | number>): Uint8Array {
  const sorted = Object.keys(fields).sort();
  const json = JSON.stringify(fields, sorted);
  return new TextEncoder().encode(json);
}

// ── Base64url encoding (RFC 4648 §5) ─────────────────────────────────

/** Encode bytes to base64url (no padding). */
export function base64urlEncode(bytes: Uint8Array): string {
  const binStr = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binStr)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Decode base64url to bytes. */
export function base64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ── Utility ──────────────────────────────────────────────────────────

/** Best-effort key wiping. JS has no memzero. See: research/07-browser-security-model.md */
export function wipe(arr: Uint8Array): void {
  arr.fill(0);
}

/** Cryptographically random blob ID (16 bytes, hex-encoded). */
export function generateBlobId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

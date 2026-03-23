/**
 * vault crypto primitives.
 *
 * All encryption uses the Web Crypto API — no external dependencies.
 * Each file gets a unique random key. The key is delivered via URL fragment.
 * The server never sees the key.
 *
 * Design decisions traced to: /research/01-cryptographic-choices.md
 * Key delivery model traced to: /research/02-key-delivery.md
 */

// ── Constants ────────────────────────────────────────────────────────

/** Key size for the random file key (16 bytes = 128 bits). */
const KEY_BYTES = 16;

/** Nonce size for AES-256-GCM (12 bytes = 96 bits). */
const NONCE_BYTES = 12;

/** Derived encryption key size (32 bytes = 256 bits). */
const DERIVED_KEY_BYTES = 32;

/** HKDF salt — fixed per application. Not secret. */
const HKDF_SALT = new TextEncoder().encode("vault-enc");

/** HKDF info — identifies the derived key's purpose. */
const HKDF_INFO = new TextEncoder().encode("aes-256-gcm");

// ── Key generation ───────────────────────────────────────────────────

/** Generate a 128-bit random key. This IS the secret. */
export function generateKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(KEY_BYTES));
}

// ── HKDF key expansion ──────────────────────────────────────────────

/**
 * Expand a 128-bit random key into a 256-bit AES-GCM encryption key
 * using HKDF-SHA256. This provides key separation — the raw key is
 * never used directly for encryption.
 *
 * RFC 5869. Web Crypto API native.
 */
export async function deriveEncryptionKey(
  rawKey: Uint8Array,
): Promise<CryptoKey> {
  // Import raw key as HKDF key material
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    rawKey.buffer.slice(rawKey.byteOffset, rawKey.byteOffset + rawKey.byteLength) as ArrayBuffer,
    "HKDF",
    false,
    ["deriveKey"],
  );

  // Derive AES-256-GCM key via HKDF-SHA256
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: HKDF_SALT,
      info: HKDF_INFO,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false, // non-extractable — key stays in browser engine memory
    ["encrypt", "decrypt"],
  );
}

// ── Encrypt ──────────────────────────────────────────────────────────

/**
 * Encrypt a file with AES-256-GCM.
 *
 * Returns: nonce (12 bytes) || ciphertext || auth tag (16 bytes)
 * The nonce is prepended so it travels with the ciphertext.
 * Each call generates a fresh random nonce.
 */
export async function encrypt(
  plaintext: ArrayBuffer,
  rawKey: Uint8Array,
): Promise<ArrayBuffer> {
  const key = await deriveEncryptionKey(rawKey);
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    plaintext,
  );

  // Prepend nonce to ciphertext
  const result = new Uint8Array(NONCE_BYTES + ciphertext.byteLength);
  result.set(nonce, 0);
  result.set(new Uint8Array(ciphertext), NONCE_BYTES);
  return result.buffer;
}

// ── Decrypt ──────────────────────────────────────────────────────────

/**
 * Decrypt a file with AES-256-GCM.
 *
 * Input: nonce (12 bytes) || ciphertext || auth tag (16 bytes)
 * The nonce is extracted from the first 12 bytes.
 *
 * Throws if: wrong key, corrupted data, tampered ciphertext.
 * GCM authentication tag verification is automatic.
 */
export async function decrypt(
  encrypted: ArrayBuffer,
  rawKey: Uint8Array,
): Promise<ArrayBuffer> {
  if (encrypted.byteLength < NONCE_BYTES + 16) {
    throw new Error("Encrypted data too short — missing nonce or auth tag.");
  }

  const key = await deriveEncryptionKey(rawKey);
  const data = new Uint8Array(encrypted);
  const nonce = data.slice(0, NONCE_BYTES);
  const ciphertext = data.slice(NONCE_BYTES);

  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    ciphertext,
  );
}

// ── Base64url encoding (RFC 4648 §5) ─────────────────────────────────

/** Encode bytes to base64url (no padding). Used for URL fragment keys. */
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

/**
 * Best-effort key wiping. JavaScript has no memzero().
 * The GC may have already copied the buffer elsewhere.
 * See: /research/07-browser-security-model.md
 */
export function wipe(arr: Uint8Array): void {
  arr.fill(0);
}

/** Generate a cryptographically random blob ID (16 bytes, hex-encoded). */
export function generateBlobId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

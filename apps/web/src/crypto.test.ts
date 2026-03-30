import { describe, it, expect } from "vitest";
import {
  generateKey,
  deriveEncryptionKey,
  encrypt,
  decrypt,
  hashPassword,
  verifyPasswordHash,
  contentHash,
  encodeAAD,
  base64urlEncode,
  base64urlDecode,
  wipe,
  generateBlobId,
  WIRE_VERSION,
  HEADER_BYTES,
} from "./crypto.js";

// ── Key generation ───────────────────────────────────────────────────

describe("generateKey", () => {
  it("returns 16 bytes (128 bits)", () => {
    const key = generateKey();
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.byteLength).toBe(16);
  });

  it("generates unique keys", () => {
    const a = generateKey();
    const b = generateKey();
    expect(a).not.toEqual(b);
  });

  it("is not all zeros", () => {
    const key = generateKey();
    expect(key.some((b) => b !== 0)).toBe(true);
  });
});

// ── HKDF key derivation (v1 compat) ─────────────────────────────────

describe("deriveEncryptionKey", () => {
  it("returns a non-extractable CryptoKey", async () => {
    const key = await deriveEncryptionKey(generateKey());
    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
  });

  it("same input produces same derived key (deterministic)", async () => {
    const raw = generateKey();
    const a = await deriveEncryptionKey(raw);
    const b = await deriveEncryptionKey(raw);
    const data = new Uint8Array([1, 2, 3, 4]);
    const nonce = new Uint8Array(12);
    const encA = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, a, data);
    const encB = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, b, data);
    expect(new Uint8Array(encA)).toEqual(new Uint8Array(encB));
  });

  it("different input produces different derived key", async () => {
    const a = await deriveEncryptionKey(generateKey());
    const b = await deriveEncryptionKey(generateKey());
    const data = new Uint8Array([1, 2, 3, 4]);
    const nonce = new Uint8Array(12);
    const encA = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, a, data);
    const encB = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, b, data);
    expect(new Uint8Array(encA)).not.toEqual(new Uint8Array(encB));
  });
});

// ── Encrypt / Decrypt (v2 wire format) ──────────────────────────────

describe("encrypt + decrypt (v2)", () => {
  it("round-trips small data", async () => {
    const key = generateKey();
    const original = new TextEncoder().encode("hello vault");
    const encrypted = await encrypt(original.buffer, key);
    const decrypted = await decrypt(encrypted, key);
    expect(new Uint8Array(decrypted)).toEqual(original);
  });

  it("round-trips empty data", async () => {
    const key = generateKey();
    const original = new Uint8Array(0);
    const encrypted = await encrypt(original.buffer, key);
    const decrypted = await decrypt(encrypted, key);
    expect(new Uint8Array(decrypted)).toEqual(original);
  });

  it("round-trips 1 byte", async () => {
    const key = generateKey();
    const original = new Uint8Array([0xff]);
    const encrypted = await encrypt(original.buffer, key);
    const decrypted = await decrypt(encrypted, key);
    expect(new Uint8Array(decrypted)).toEqual(original);
  });

  it("round-trips 1MB data", async () => {
    const key = generateKey();
    const original = new Uint8Array(1024 * 1024);
    for (let i = 0; i < original.byteLength; i += 65536) {
      const chunk = Math.min(65536, original.byteLength - i);
      crypto.getRandomValues(original.subarray(i, i + chunk));
    }
    const encrypted = await encrypt(original.buffer, key);
    const decrypted = await decrypt(encrypted, key);
    expect(new Uint8Array(decrypted)).toEqual(original);
  });

  it("ciphertext includes header overhead", async () => {
    const key = generateKey();
    const original = new Uint8Array(100);
    const encrypted = await encrypt(original.buffer, key);
    // header (62) + plaintext (100) + GCM tag (16) = 178
    expect(encrypted.byteLength).toBe(HEADER_BYTES + 100 + 16);
  });

  it("two encryptions produce different ciphertext (random salt + nonce)", async () => {
    const key = generateKey();
    const data = new TextEncoder().encode("same data");
    const a = await encrypt(data.buffer, key);
    const b = await encrypt(data.buffer, key);
    expect(new Uint8Array(a)).not.toEqual(new Uint8Array(b));
  });

  it("wire format starts with correct version", async () => {
    const key = generateKey();
    const encrypted = new Uint8Array(await encrypt(new Uint8Array(1).buffer, key));
    const version = new DataView(encrypted.buffer).getUint16(0);
    expect(version).toBe(WIRE_VERSION);
  });

  // ── Key commitment tests ────────────────────────────────────────

  it("fails with wrong key (commitment check)", async () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const encrypted = await encrypt(new TextEncoder().encode("secret").buffer, key1);
    await expect(decrypt(encrypted, key2)).rejects.toThrow("Key commitment failed");
  });

  it("fails with tampered ciphertext", async () => {
    const key = generateKey();
    const encrypted = await encrypt(new TextEncoder().encode("data").buffer, key);
    const tampered = new Uint8Array(encrypted);
    // Flip a byte in the ciphertext body (after the header)
    tampered[HEADER_BYTES + 2] ^= 0xff;
    await expect(decrypt(tampered.buffer, key)).rejects.toThrow();
  });

  it("fails with tampered commitment", async () => {
    const key = generateKey();
    const encrypted = await encrypt(new TextEncoder().encode("data").buffer, key);
    const tampered = new Uint8Array(encrypted);
    // Flip a byte in the HMAC commitment (bytes 30-62)
    tampered[35] ^= 0xff;
    await expect(decrypt(tampered.buffer, key)).rejects.toThrow("Key commitment failed");
  });

  it("fails with tampered salt", async () => {
    const key = generateKey();
    const encrypted = await encrypt(new TextEncoder().encode("data").buffer, key);
    const tampered = new Uint8Array(encrypted);
    // Flip a byte in the salt (bytes 2-18)
    tampered[5] ^= 0xff;
    await expect(decrypt(tampered.buffer, key)).rejects.toThrow();
  });

  it("fails with truncated data", async () => {
    const key = generateKey();
    const short = new Uint8Array(20);
    await expect(decrypt(short.buffer, key)).rejects.toThrow("too short");
  });

  it("fails with wrong version", async () => {
    const key = generateKey();
    const encrypted = new Uint8Array(await encrypt(new Uint8Array(1).buffer, key));
    // Set version to 99
    new DataView(encrypted.buffer).setUint16(0, 99);
    await expect(decrypt(encrypted.buffer, key)).rejects.toThrow("Unsupported wire format");
  });

  // ── AAD tests ───────────────────────────────────────────────────

  it("round-trips with AAD", async () => {
    const key = generateKey();
    const aad = encodeAAD({ blob_id: "abc123", expires_at: 1711843200 });
    const original = new TextEncoder().encode("with metadata binding");
    const encrypted = await encrypt(original.buffer, key, aad);
    const decrypted = await decrypt(encrypted, key, aad);
    expect(new Uint8Array(decrypted)).toEqual(original);
  });

  it("fails when AAD changes between encrypt and decrypt", async () => {
    const key = generateKey();
    const aadEnc = encodeAAD({ blob_id: "abc123", expires_at: 1711843200 });
    const aadDec = encodeAAD({ blob_id: "abc123", expires_at: 9999999999 }); // changed expiry
    const encrypted = await encrypt(new TextEncoder().encode("data").buffer, key, aadEnc);
    // Commitment check passes (HMAC doesn't include AAD), but GCM tag fails
    await expect(decrypt(encrypted, key, aadDec)).rejects.toThrow();
  });

  it("fails when AAD provided on decrypt but not on encrypt", async () => {
    const key = generateKey();
    const encrypted = await encrypt(new TextEncoder().encode("data").buffer, key);
    const aad = encodeAAD({ blob_id: "abc123" });
    await expect(decrypt(encrypted, key, aad)).rejects.toThrow();
  });
});

// ── Password hashing (PBKDF2) ───────────────────────────────────────

describe("hashPassword", () => {
  it("returns 32-byte hash and 16-byte salt", async () => {
    const { hash, salt } = await hashPassword("test-password");
    expect(hash.byteLength).toBe(32);
    expect(salt.byteLength).toBe(16);
  });

  it("same password with same salt produces same hash", async () => {
    const { hash: h1, salt } = await hashPassword("same-password");
    const valid = await verifyPasswordHash("same-password", salt, h1);
    expect(valid).toBe(true);
  });

  it("wrong password fails verification", async () => {
    const { hash, salt } = await hashPassword("correct-password");
    const valid = await verifyPasswordHash("wrong-password", salt, hash);
    expect(valid).toBe(false);
  });

  it("different salt produces different hash (even for same password)", async () => {
    const a = await hashPassword("same-password");
    const b = await hashPassword("same-password");
    // Random salts differ
    expect(a.salt).not.toEqual(b.salt);
    expect(a.hash).not.toEqual(b.hash);
  });

  it("empty password is hashable", async () => {
    const { hash, salt } = await hashPassword("");
    expect(hash.byteLength).toBe(32);
    const valid = await verifyPasswordHash("", salt, hash);
    expect(valid).toBe(true);
  });

  it("unicode password works", async () => {
    const { hash, salt } = await hashPassword("パスワード🔐");
    const valid = await verifyPasswordHash("パスワード🔐", salt, hash);
    expect(valid).toBe(true);
  });
});

// ── Content hash ────────────────────────────────────────────────────

describe("contentHash", () => {
  it("returns 32-byte SHA-256 hash", async () => {
    const hash = await contentHash(new TextEncoder().encode("hello").buffer);
    expect(hash.byteLength).toBe(32);
  });

  it("same input produces same hash (deterministic)", async () => {
    const data = new TextEncoder().encode("deterministic");
    const a = await contentHash(data.buffer);
    const b = await contentHash(data.buffer);
    expect(a).toEqual(b);
  });

  it("different input produces different hash", async () => {
    const a = await contentHash(new TextEncoder().encode("a").buffer);
    const b = await contentHash(new TextEncoder().encode("b").buffer);
    expect(a).not.toEqual(b);
  });

  it("empty input has a valid hash", async () => {
    const hash = await contentHash(new ArrayBuffer(0));
    expect(hash.byteLength).toBe(32);
  });
});

// ── AAD encoding ────────────────────────────────────────────────────

describe("encodeAAD", () => {
  it("produces deterministic output for same fields", () => {
    const a = encodeAAD({ blob_id: "abc", expires_at: 123 });
    const b = encodeAAD({ blob_id: "abc", expires_at: 123 });
    expect(a).toEqual(b);
  });

  it("sorts keys (order-independent input)", () => {
    const a = encodeAAD({ z: 1, a: 2 });
    const b = encodeAAD({ a: 2, z: 1 });
    expect(a).toEqual(b);
  });

  it("different values produce different output", () => {
    const a = encodeAAD({ blob_id: "abc" });
    const b = encodeAAD({ blob_id: "xyz" });
    expect(a).not.toEqual(b);
  });
});

// ── Base64url ────────────────────────────────────────────────────────

describe("base64url", () => {
  it("round-trips a key", () => {
    const key = generateKey();
    const encoded = base64urlEncode(key);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(key);
  });

  it("produces URL-safe characters only", () => {
    for (let i = 0; i < 50; i++) {
      const encoded = base64urlEncode(generateKey());
      expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    }
  });

  it("has no padding", () => {
    const encoded = base64urlEncode(generateKey());
    expect(encoded).not.toContain("=");
  });

  it("round-trips empty array", () => {
    const encoded = base64urlEncode(new Uint8Array(0));
    expect(encoded).toBe("");
    expect(base64urlDecode("")).toEqual(new Uint8Array(0));
  });

  it("handles known value", () => {
    const bytes = new Uint8Array([0xff, 0xfe]);
    const encoded = base64urlEncode(bytes);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(bytes);
  });
});

// ── Wipe ─────────────────────────────────────────────────────────────

describe("wipe", () => {
  it("zeros out a buffer", () => {
    const arr = new Uint8Array([1, 2, 3, 4, 5]);
    wipe(arr);
    expect(arr.every((b) => b === 0)).toBe(true);
  });
});

// ── Blob ID ──────────────────────────────────────────────────────────

describe("generateBlobId", () => {
  it("returns 32-char hex string", () => {
    const id = generateBlobId();
    expect(id).toMatch(/^[0-9a-f]{32}$/);
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateBlobId()));
    expect(ids.size).toBe(100);
  });
});

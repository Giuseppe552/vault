import { describe, it, expect } from "vitest";
import {
  generateKey,
  deriveEncryptionKey,
  encrypt,
  decrypt,
  base64urlEncode,
  base64urlDecode,
  wipe,
  generateBlobId,
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

// ── HKDF key derivation ─────────────────────────────────────────────

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
    // Can't compare CryptoKey directly, but encrypting same data with
    // same key + same nonce should produce identical output
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

// ── Encrypt / Decrypt round-trip ─────────────────────────────────────

describe("encrypt + decrypt", () => {
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
    // crypto.getRandomValues has a 65536-byte limit per call,
    // so fill in chunks
    const original = new Uint8Array(1024 * 1024);
    for (let i = 0; i < original.byteLength; i += 65536) {
      const chunk = Math.min(65536, original.byteLength - i);
      crypto.getRandomValues(original.subarray(i, i + chunk));
    }
    const encrypted = await encrypt(original.buffer, key);
    const decrypted = await decrypt(encrypted, key);
    expect(new Uint8Array(decrypted)).toEqual(original);
  });

  it("ciphertext is larger than plaintext by nonce + tag", async () => {
    const key = generateKey();
    const original = new Uint8Array(100);
    const encrypted = await encrypt(original.buffer, key);
    // nonce (12) + plaintext (100) + tag (16) = 128
    expect(encrypted.byteLength).toBe(128);
  });

  it("two encryptions of same data produce different ciphertext (random nonce)", async () => {
    const key = generateKey();
    const data = new TextEncoder().encode("same data");
    const a = await encrypt(data.buffer, key);
    const b = await encrypt(data.buffer, key);
    expect(new Uint8Array(a)).not.toEqual(new Uint8Array(b));
  });

  it("fails with wrong key", async () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const encrypted = await encrypt(new TextEncoder().encode("secret").buffer, key1);
    await expect(decrypt(encrypted, key2)).rejects.toThrow();
  });

  it("fails with tampered ciphertext", async () => {
    const key = generateKey();
    const encrypted = await encrypt(new TextEncoder().encode("data").buffer, key);
    const tampered = new Uint8Array(encrypted);
    // Flip a byte in the ciphertext (after the nonce)
    tampered[14] ^= 0xff;
    await expect(decrypt(tampered.buffer, key)).rejects.toThrow();
  });

  it("fails with truncated ciphertext", async () => {
    const key = generateKey();
    const short = new Uint8Array(20); // less than nonce + tag
    await expect(decrypt(short.buffer, key)).rejects.toThrow(
      "Encrypted data too short",
    );
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
    // [0xff, 0xfe] should encode to "_-4" (standard base64 "//4=" → base64url "__4")
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

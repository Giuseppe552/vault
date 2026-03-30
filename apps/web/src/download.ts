import { decrypt, contentHash, encodeAAD, hashPasswordWithSalt, base64urlDecode, base64urlEncode, wipe } from "./crypto.js";

const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export type BlobMeta = {
  filename_enc: string;
  size_bytes: number;
  has_password: boolean;
  password_salt?: string;
  downloads_remaining: number;
  expires_at: number;
  expiry_hours?: number;
  max_downloads?: number;
  content_hash?: string;
};

export type DownloadCallbacks = {
  onProgress: (label: string, pct: number) => void;
  onNeedPassword: () => void;
  onComplete: () => void;
  onError: (msg: string) => void;
};

/**
 * Parse the blob ID and key from the current URL.
 * URL format: /d/{blobId}#{base64url(key)}
 */
export function parseDownloadUrl(): { blobId: string; key: Uint8Array } | null {
  const path = window.location.pathname;
  const match = path.match(/^\/d\/([a-f0-9]{32})$/);
  if (!match) return null;

  const fragment = window.location.hash.slice(1);
  if (!fragment) return null;

  try {
    const key = base64urlDecode(fragment);
    if (key.byteLength !== 16) return null;
    return { blobId: match[1], key };
  } catch {
    return null;
  }
}

/** Strip the key from browser history. Best effort — see research/02-key-delivery.md */
export function stripKeyFromHistory(): void {
  try {
    const url = window.location.pathname + window.location.search;
    history.replaceState(null, "", url);
  } catch {
    // Some browsers may block this
  }
}

/** Fetch blob metadata to check if it exists and needs a password. */
export async function fetchMeta(blobId: string): Promise<BlobMeta | null> {
  const res = await fetch(`${API_BASE}/api/blob/${blobId}/meta`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<BlobMeta>;
}

/** Verify a password against the server using PBKDF2 hash. */
export async function verifyPassword(
  blobId: string,
  password: string,
  saltB64: string,
): Promise<boolean> {
  // Re-derive the PBKDF2 hash client-side with the stored salt
  const salt = base64urlDecode(saltB64);
  const hash = await hashPasswordWithSalt(password, salt);
  const passwordHash = base64urlEncode(hash);

  const res = await fetch(`${API_BASE}/api/blob/${blobId}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password_hash: passwordHash }),
  });

  if (res.status === 429) throw new Error("Too many attempts. Wait and try again.");
  if (!res.ok && res.status !== 401) throw new Error(`HTTP ${res.status}`);

  const data = (await res.json()) as { valid: boolean };
  return data.valid;
}

/** Download and decrypt the blob. Triggers a file download in the browser. */
export async function downloadAndDecrypt(
  blobId: string,
  key: Uint8Array,
  meta: BlobMeta,
  onProgress: (label: string, pct: number) => void,
): Promise<void> {
  onProgress("Downloading encrypted file...", 10);

  const res = await fetch(`${API_BASE}/api/blob/${blobId}`);
  if (res.status === 404) throw new Error("File expired or already downloaded.");
  if (res.status === 429) throw new Error("Rate limited. Try again later.");
  if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`);

  const encrypted = await res.arrayBuffer();
  onProgress("Decrypting...", 50);

  // Reconstruct AAD from metadata (must match what was used during encryption)
  // AAD is only present in v2 uploads — v1 files have no AAD
  const hasAAD = meta.expiry_hours !== undefined && meta.max_downloads !== undefined;
  const aad = hasAAD
    ? encodeAAD({ expiry_hours: meta.expiry_hours!, max_downloads: meta.max_downloads! })
    : undefined;

  // Decrypt the blob
  const plaintext = await decrypt(encrypted, key, aad);
  onProgress("Verifying integrity...", 75);

  // Verify content hash if available
  if (meta.content_hash) {
    const hash = base64urlEncode(await contentHash(plaintext));
    if (hash !== meta.content_hash) {
      throw new Error("Content hash mismatch — file may be corrupted.");
    }
  }

  onProgress("Decryption complete.", 80);

  // Decrypt the filename
  let filename = "download";
  try {
    const filenameEnc = base64urlDecode(meta.filename_enc);
    const buf = filenameEnc.buffer.slice(
      filenameEnc.byteOffset,
      filenameEnc.byteOffset + filenameEnc.byteLength,
    ) as ArrayBuffer;
    const filenameBytes = await decrypt(buf, key);
    filename = new TextDecoder().decode(filenameBytes);
  } catch {
    // Filename decryption failed — use default
  }

  // Trigger browser download
  onProgress("Saving file...", 90);
  const blob = new Blob([plaintext]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);

  // Wipe key
  wipe(key);

  onProgress("Done.", 100);
}

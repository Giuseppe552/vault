import { decrypt, base64urlDecode, base64urlEncode, wipe } from "./crypto.js";

const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export type BlobMeta = {
  filename_enc: string;
  size_bytes: number;
  has_password: boolean;
  downloads_remaining: number;
  expires_at: number;
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

/** Verify a password against the server. */
export async function verifyPassword(
  blobId: string,
  password: string,
): Promise<boolean> {
  const pwBytes = new TextEncoder().encode(password);
  const hashBuf = await crypto.subtle.digest("SHA-256", pwBytes);
  const passwordHash = base64urlEncode(new Uint8Array(hashBuf));

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

  // Decrypt the blob
  const plaintext = await decrypt(encrypted, key);
  onProgress("Decryption complete.", 80);

  // Decrypt the filename
  let filename = "download";
  try {
    const filenameEnc = base64urlDecode(meta.filename_enc);
    const filenameBytes = await decrypt(filenameEnc.buffer.slice(filenameEnc.byteOffset, filenameEnc.byteOffset + filenameEnc.byteLength) as ArrayBuffer, key);
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

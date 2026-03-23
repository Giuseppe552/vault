import { generateKey, encrypt, base64urlEncode, wipe } from "./crypto.js";

const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export type UploadOptions = {
  file: File;
  expiryHours: number;
  maxDownloads: number;
  password?: string;
  onProgress: (label: string, pct: number) => void;
};

export type UploadResult = {
  url: string;
  id: string;
};

/**
 * Encrypt a file client-side and upload the ciphertext.
 * Returns the shareable URL with the key in the fragment.
 */
export async function uploadFile(opts: UploadOptions): Promise<UploadResult> {
  const { file, expiryHours, maxDownloads, password, onProgress } = opts;

  // Step 1: Generate key
  onProgress("Generating encryption key...", 5);
  const rawKey = generateKey();

  // Step 2: Encrypt file
  onProgress("Encrypting in your browser...", 10);
  const plaintext = await file.arrayBuffer();
  const encrypted = await encrypt(plaintext, rawKey);
  onProgress("File encrypted.", 50);

  // Step 3: Encrypt filename (so server doesn't see it)
  const filenameBytes = new TextEncoder().encode(file.name);
  const filenameEnc = base64urlEncode(new Uint8Array(await encrypt(filenameBytes.buffer, rawKey)));

  // Step 4: Hash password if provided (client-side, for server comparison)
  let passwordHash: string | undefined;
  if (password && password.length > 0) {
    const pwBytes = new TextEncoder().encode(password);
    const hashBuf = await crypto.subtle.digest("SHA-256", pwBytes);
    passwordHash = base64urlEncode(new Uint8Array(hashBuf));
  }

  // Step 5: Upload
  onProgress("Uploading encrypted file...", 60);
  const formData = new FormData();
  formData.append("blob", new Blob([encrypted], { type: "application/octet-stream" }));
  formData.append(
    "meta",
    JSON.stringify({
      filename_enc: filenameEnc,
      password_hash: passwordHash,
      expiry_hours: expiryHours,
      max_downloads: maxDownloads,
    }),
  );

  const res = await fetch(`${API_BASE}/api/upload`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Upload failed" }));
    throw new Error((err as { error: string }).error ?? `HTTP ${res.status}`);
  }

  onProgress("Upload complete.", 95);
  const { id } = (await res.json()) as { id: string };

  // Step 6: Construct shareable URL
  const keyStr = base64urlEncode(rawKey);
  const origin = window.location.origin;
  const url = `${origin}/d/${id}#${keyStr}`;

  // Step 7: Wipe key from memory (best effort)
  wipe(rawKey);

  onProgress("Done.", 100);
  return { url, id };
}

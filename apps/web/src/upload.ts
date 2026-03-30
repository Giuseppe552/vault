import { generateKey, encrypt, hashPassword, contentHash, encodeAAD, base64urlEncode, wipe } from "./crypto.js";

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

  // Step 2: Read plaintext and compute content hash for integrity verification
  onProgress("Reading file...", 8);
  const plaintext = await file.arrayBuffer();
  const fileHash = base64urlEncode(await contentHash(plaintext));

  // Step 3: Encrypt file with AAD binding (metadata bound to auth tag)
  onProgress("Encrypting in your browser...", 10);
  const aad = encodeAAD({
    expiry_hours: expiryHours,
    max_downloads: maxDownloads,
  });
  const encrypted = await encrypt(plaintext, rawKey, aad);
  onProgress("File encrypted.", 50);

  // Step 4: Encrypt filename (so server doesn't see it)
  const filenameBytes = new TextEncoder().encode(file.name);
  const filenameEnc = base64urlEncode(new Uint8Array(await encrypt(filenameBytes.buffer, rawKey)));

  // Step 5: Hash password with PBKDF2 if provided (600k iterations)
  let passwordHashB64: string | undefined;
  let passwordSaltB64: string | undefined;
  if (password && password.length > 0) {
    onProgress("Hashing password...", 55);
    const { hash, salt } = await hashPassword(password);
    passwordHashB64 = base64urlEncode(hash);
    passwordSaltB64 = base64urlEncode(salt);
  }

  // Step 6: Upload
  onProgress("Uploading encrypted file...", 60);
  const formData = new FormData();
  formData.append("blob", new Blob([encrypted], { type: "application/octet-stream" }));
  formData.append(
    "meta",
    JSON.stringify({
      filename_enc: filenameEnc,
      password_hash: passwordHashB64,
      password_salt: passwordSaltB64,
      expiry_hours: expiryHours,
      max_downloads: maxDownloads,
      content_hash: fileHash,
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

  // Step 7: Construct shareable URL
  const keyStr = base64urlEncode(rawKey);
  const origin = window.location.origin;
  const url = `${origin}/d/${id}#${keyStr}`;

  // Step 8: Wipe key from memory (best effort)
  wipe(rawKey);

  onProgress("Done.", 100);
  return { url, id };
}

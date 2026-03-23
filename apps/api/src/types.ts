/** Cloudflare Workers bindings. */
export type Env = {
  BLOBS: R2Bucket;
  DB: D1Database;
  APP_ORIGIN: string;
  MAX_FILE_SIZE: string;
};

/** Metadata stored in D1 alongside the encrypted blob in R2. */
export type BlobMeta = {
  id: string;
  /** Original filename, encrypted client-side (base64url). Not readable by server. */
  filename_enc: string;
  /** Size of the encrypted blob in bytes. */
  size_bytes: number;
  /** PBKDF2 hash of optional password. Null if no password. */
  password_hash: string | null;
  /** Unix timestamp (ms) when the blob expires. */
  expires_at: number;
  /** Maximum allowed downloads. */
  max_downloads: number;
  /** Current download count. */
  download_count: number;
  /** Upload timestamp (ms). */
  created_at: number;
  /** Uploader IP (for abuse response). */
  uploader_ip: string;
};

/** Upload request body. */
export type UploadRequest = {
  /** Encrypted filename (base64url, encrypted by client). */
  filename_enc: string;
  /** Optional PBKDF2 password hash. */
  password_hash?: string;
  /** Expiry in hours (1, 24, 168). */
  expiry_hours: number;
  /** Max downloads (1–10). */
  max_downloads: number;
};

/** Upload response. */
export type UploadResponse = {
  id: string;
};

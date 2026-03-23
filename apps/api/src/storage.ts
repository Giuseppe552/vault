import type { Env, BlobMeta } from "./types.js";

/** D1 schema — run once to create the table. */
export const SCHEMA = `
CREATE TABLE IF NOT EXISTS blobs (
  id TEXT PRIMARY KEY,
  filename_enc TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  password_hash TEXT,
  expires_at INTEGER NOT NULL,
  max_downloads INTEGER NOT NULL DEFAULT 1,
  download_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  uploader_ip TEXT NOT NULL
);
`;

/** Store encrypted blob in R2 and metadata in D1. */
export async function putBlob(
  env: Env,
  id: string,
  data: ArrayBuffer,
  meta: Omit<BlobMeta, "download_count">,
): Promise<void> {
  // Store encrypted blob in R2
  await env.BLOBS.put(id, data);

  // Store metadata in D1
  await env.DB.prepare(
    `INSERT INTO blobs (id, filename_enc, size_bytes, password_hash, expires_at, max_downloads, download_count, created_at, uploader_ip)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`,
  )
    .bind(
      meta.id,
      meta.filename_enc,
      meta.size_bytes,
      meta.password_hash,
      meta.expires_at,
      meta.max_downloads,
      meta.created_at,
      meta.uploader_ip,
    )
    .run();
}

/** Get blob metadata from D1. Returns null if not found or expired. */
export async function getMeta(
  env: Env,
  id: string,
): Promise<BlobMeta | null> {
  const row = await env.DB.prepare(
    "SELECT * FROM blobs WHERE id = ?",
  )
    .bind(id)
    .first<BlobMeta>();

  if (!row) return null;

  // Check expiry
  if (row.expires_at < Date.now()) {
    // Clean up expired blob
    await deleteBlob(env, id);
    return null;
  }

  // Check download limit
  if (row.download_count >= row.max_downloads) {
    await deleteBlob(env, id);
    return null;
  }

  return row;
}

/** Get the encrypted blob from R2. */
export async function getBlob(
  env: Env,
  id: string,
): Promise<ArrayBuffer | null> {
  const obj = await env.BLOBS.get(id);
  if (!obj) return null;
  return obj.arrayBuffer();
}

/** Increment download count. Returns the new count. */
export async function incrementDownloads(
  env: Env,
  id: string,
): Promise<number> {
  const result = await env.DB.prepare(
    "UPDATE blobs SET download_count = download_count + 1 WHERE id = ? RETURNING download_count",
  )
    .bind(id)
    .first<{ download_count: number }>();

  return result?.download_count ?? 0;
}

/** Delete blob from both R2 and D1. */
export async function deleteBlob(env: Env, id: string): Promise<void> {
  await Promise.all([
    env.BLOBS.delete(id),
    env.DB.prepare("DELETE FROM blobs WHERE id = ?").bind(id).run(),
  ]);
}

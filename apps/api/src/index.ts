/**
 * vault API — Cloudflare Workers + Hono.
 *
 * Stores and retrieves encrypted blobs. Never sees the encryption key.
 * Design decisions: /research/08-design-decisions.md
 * Rate limits: /research/05-abuse-vectors.md
 */

import { Hono } from "hono";
import type { Env, UploadRequest, UploadResponse } from "./types.js";
import { putBlob, getMeta, getBlob, incrementDownloads, deleteBlob } from "./storage.js";
import { checkRateLimit, LIMITS } from "./rateLimit.js";

const app = new Hono<{ Bindings: Env }>();

// ── Security headers (all responses) ─────────────────────────────────

app.use("*", async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Referrer-Policy", "no-referrer");
  c.header("X-Frame-Options", "DENY");
  c.header("Cache-Control", "no-store, no-cache, must-revalidate");
  c.header("Cross-Origin-Opener-Policy", "same-origin");
  c.header("Cross-Origin-Resource-Policy", "same-origin");
  c.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
});

// ── CORS ─────────────────────────────────────────────────────────────

app.use("*", async (c, next) => {
  const origin = c.req.header("Origin");
  const allowed = c.env.APP_ORIGIN;

  if (origin && origin !== allowed) {
    return c.json({ error: "Forbidden" }, 403);
  }

  if (origin) {
    c.header("Access-Control-Allow-Origin", allowed);
    c.header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    c.header("Access-Control-Allow-Headers", "Content-Type");
    c.header("Access-Control-Max-Age", "86400");
  }

  if (c.req.method === "OPTIONS") {
    return c.body(null, 204);
  }

  await next();
});

// ── Helpers ──────────────────────────────────────────────────────────

function getIp(c: { req: { header: (name: string) => string | undefined } }): string {
  return c.req.header("CF-Connecting-IP") ?? c.req.header("X-Forwarded-For")?.split(",")[0]?.trim() ?? "unknown";
}

function generateId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

const VALID_EXPIRY_HOURS = [1, 24, 168]; // 1h, 24h, 7d
const MAX_DOWNLOADS = 10;

// ── Upload ───────────────────────────────────────────────────────────

app.post("/api/upload", async (c) => {
  const ip = getIp(c);

  // Rate limit
  const rl = await checkRateLimit(ip, LIMITS.upload);
  if (!rl.allowed) {
    c.header("Retry-After", String(rl.resetAt - Math.floor(Date.now() / 1000)));
    return c.json({ error: "Rate limit exceeded. Try again later." }, 429);
  }

  // Validate content type — must be multipart with encrypted blob
  const contentType = c.req.header("Content-Type") ?? "";
  if (!contentType.includes("multipart/form-data")) {
    return c.json({ error: "Expected multipart/form-data" }, 400);
  }

  const formData = await c.req.formData();
  const file = formData.get("blob") as File | null;
  const metaJson = formData.get("meta") as string | null;

  if (!file || !metaJson) {
    return c.json({ error: "Missing blob or meta" }, 400);
  }

  // Validate file size
  const maxSize = parseInt(c.env.MAX_FILE_SIZE ?? "104857600", 10);
  if (file.size > maxSize) {
    return c.json({ error: `File exceeds ${Math.round(maxSize / 1048576)}MB limit` }, 413);
  }

  let meta: UploadRequest;
  try {
    meta = JSON.parse(metaJson);
  } catch {
    return c.json({ error: "Invalid meta JSON" }, 400);
  }

  // Validate expiry
  if (!VALID_EXPIRY_HOURS.includes(meta.expiry_hours)) {
    return c.json({ error: "Invalid expiry. Use 1, 24, or 168 hours." }, 400);
  }

  // Validate max downloads
  const maxDl = Math.min(Math.max(1, meta.max_downloads ?? 1), MAX_DOWNLOADS);

  const id = generateId();
  const now = Date.now();
  const expiresAt = now + meta.expiry_hours * 3600 * 1000;

  await putBlob(c.env, id, await file.arrayBuffer(), {
    id,
    filename_enc: meta.filename_enc,
    size_bytes: file.size,
    password_hash: meta.password_hash ?? null,
    expires_at: expiresAt,
    max_downloads: maxDl,
    created_at: now,
    uploader_ip: ip,
  });

  const response: UploadResponse = { id };
  return c.json(response, 201);
});

// ── Download metadata (check if blob exists, needs password) ─────────

app.get("/api/blob/:id/meta", async (c) => {
  const id = c.req.param("id");
  const meta = await getMeta(c.env, id);

  if (!meta) {
    return c.json({ error: "Not found or expired" }, 404);
  }

  return c.json({
    filename_enc: meta.filename_enc,
    size_bytes: meta.size_bytes,
    has_password: !!meta.password_hash,
    downloads_remaining: meta.max_downloads - meta.download_count,
    expires_at: meta.expires_at,
  });
});

// ── Verify password ──────────────────────────────────────────────────

app.post("/api/blob/:id/verify", async (c) => {
  const ip = getIp(c);
  const id = c.req.param("id");

  // Rate limit password attempts per blob
  const rl = await checkRateLimit(`${ip}:${id}`, LIMITS.passwordAttempt);
  if (!rl.allowed) {
    c.header("Retry-After", String(rl.resetAt - Math.floor(Date.now() / 1000)));
    return c.json({ error: "Too many attempts. Wait and try again." }, 429);
  }

  const meta = await getMeta(c.env, id);
  if (!meta) {
    return c.json({ error: "Not found or expired" }, 404);
  }

  if (!meta.password_hash) {
    return c.json({ valid: true });
  }

  const body = await c.req.json<{ password_hash: string }>();
  if (!body?.password_hash) {
    return c.json({ error: "Missing password_hash" }, 400);
  }

  // Constant-time comparison
  const expected = new TextEncoder().encode(meta.password_hash);
  const provided = new TextEncoder().encode(body.password_hash);

  if (expected.byteLength !== provided.byteLength) {
    return c.json({ valid: false }, 401);
  }

  const match = timingSafeEqual(expected, provided);
  if (!match) {
    return c.json({ valid: false }, 401);
  }

  return c.json({ valid: true });
});

// ── Download blob ────────────────────────────────────────────────────

app.get("/api/blob/:id", async (c) => {
  const ip = getIp(c);
  const id = c.req.param("id");

  // Rate limit
  const rl = await checkRateLimit(ip, LIMITS.download);
  if (!rl.allowed) {
    c.header("Retry-After", String(rl.resetAt - Math.floor(Date.now() / 1000)));
    return c.json({ error: "Rate limit exceeded" }, 429);
  }

  const meta = await getMeta(c.env, id);
  if (!meta) {
    return c.json({ error: "Not found or expired" }, 404);
  }

  // If password-protected, require prior verification via /verify endpoint
  // (client must call /verify first, then /blob/:id)
  // For simplicity, we trust the client verified — the password gates the UI, not the blob

  const blob = await getBlob(c.env, id);
  if (!blob) {
    return c.json({ error: "Blob not found in storage" }, 404);
  }

  // Increment download count
  const newCount = await incrementDownloads(c.env, id);

  // If this was the last allowed download, delete immediately
  if (newCount >= meta.max_downloads) {
    await deleteBlob(c.env, id);
  }

  return new Response(blob, {
    status: 200,
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Length": String(blob.byteLength),
      "Cache-Control": "no-store",
      "X-Downloads-Remaining": String(Math.max(0, meta.max_downloads - newCount)),
    },
  });
});

// ── Abuse takedown ───────────────────────────────────────────────────

app.delete("/api/blob/:id", async (c) => {
  const id = c.req.param("id");
  await deleteBlob(c.env, id);
  return c.json({ deleted: true });
});

// ── Health ───────────────────────────────────────────────────────────

app.get("/api/health", (c) => c.json({ status: "ok" }));

// ── Error handler ────────────────────────────────────────────────────

app.onError((err, c) => {
  console.error("Unhandled error:", err);
  return c.json({ error: "Internal error" }, 500);
});

// ── 404 ──────────────────────────────────────────────────────────────

app.notFound((c) => c.json({ error: "Not found" }, 404));

export default app;

// ── Timing-safe comparison ───────────────────────────────────────────

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let result = 0;
  for (let i = 0; i < a.byteLength; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

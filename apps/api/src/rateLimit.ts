/**
 * IP-based rate limiting using Cloudflare Cache API.
 * No external dependencies. Cache entries auto-expire.
 */

type RateLimitOpts = {
  /** Max requests in the window. */
  max: number;
  /** Window size in seconds. */
  windowSec: number;
  /** Prefix for cache keys. */
  prefix: string;
};

/**
 * Check and increment rate limit for an IP.
 * Returns true if the request should be allowed, false if rate-limited.
 */
export async function checkRateLimit(
  ip: string,
  opts: RateLimitOpts,
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const cache = await caches.open("vault-ratelimit");
  const key = `https://vault-ratelimit/${opts.prefix}/${ip}`;
  const now = Math.floor(Date.now() / 1000);

  const existing = await cache.match(key);
  let count = 0;
  let windowStart = now;

  if (existing) {
    const data = await existing.json<{ count: number; start: number }>();
    // Check if we're still in the same window
    if (now - data.start < opts.windowSec) {
      count = data.count;
      windowStart = data.start;
    }
    // Otherwise window has expired, start fresh
  }

  count++;
  const allowed = count <= opts.max;
  const resetAt = windowStart + opts.windowSec;
  const ttl = resetAt - now;

  // Store updated count
  const response = new Response(
    JSON.stringify({ count, start: windowStart }),
    {
      headers: {
        "Cache-Control": `max-age=${Math.max(1, ttl)}`,
        "Content-Type": "application/json",
      },
    },
  );
  await cache.put(key, response);

  return { allowed, remaining: Math.max(0, opts.max - count), resetAt };
}

/** Rate limit presets matching research/08-design-decisions.md */
export const LIMITS = {
  upload: { max: 10, windowSec: 3600, prefix: "upload" } as const,
  download: { max: 60, windowSec: 3600, prefix: "download" } as const,
  passwordAttempt: { max: 5, windowSec: 60, prefix: "pwd" } as const,
} satisfies Record<string, RateLimitOpts>;

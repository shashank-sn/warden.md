import type { D1Database, RateLimiter } from "./types.js";

interface Bucket {
  startedAt: number;
  count: number;
}

/** Suitable for tests and one Worker isolate. Supply a durable limiter in production. */
export class FixedWindowRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  public async take(
    key: string,
    limit: number,
    windowSeconds: number,
    now: number,
  ): Promise<boolean> {
    if (limit < 1) {
      return false;
    }
    const windowMilliseconds = windowSeconds * 1000;
    const existing = this.buckets.get(key);
    if (!existing || now - existing.startedAt >= windowMilliseconds) {
      this.buckets.set(key, { startedAt: now, count: 1 });
      return true;
    }
    if (existing.count >= limit) {
      return false;
    }
    existing.count += 1;
    return true;
  }
}

interface D1RateLimitRow {
  count: number;
}

/** Atomic fixed windows for a D1-backed Worker deployment. */
export class D1FixedWindowRateLimiter implements RateLimiter {
  public constructor(private readonly database: D1Database) {}

  public async take(
    key: string,
    limit: number,
    windowSeconds: number,
    now: number,
  ): Promise<boolean> {
    if (limit < 1) {
      return false;
    }
    const windowMilliseconds = windowSeconds * 1000;
    const windowStartedAt = Math.floor(now / windowMilliseconds) * windowMilliseconds;
    const row = await this.database
      .prepare(
        `INSERT INTO rate_limit_buckets (bucket_key, window_started_at, count)
         VALUES (?, ?, 1)
         ON CONFLICT(bucket_key) DO UPDATE SET
           window_started_at = CASE
             WHEN rate_limit_buckets.window_started_at = excluded.window_started_at
             THEN rate_limit_buckets.window_started_at
             ELSE excluded.window_started_at
           END,
           count = CASE
             WHEN rate_limit_buckets.window_started_at = excluded.window_started_at
             THEN rate_limit_buckets.count + 1
             ELSE 1
           END
         RETURNING count`,
      )
      .bind(key, windowStartedAt)
      .first<D1RateLimitRow>();
    return (row?.count ?? limit + 1) <= limit;
  }
}

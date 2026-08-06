/**
 * One counted hit against a rate-limit key.
 */
export interface RateLimitHit {
  /** Hits recorded in the current window, including this one */
  count: number
  /** When the current window ends and the count resets */
  resetAt: Date
}

/**
 * Storage adapter for rate-limit counters.
 *
 * Applications implement this to share counters across instances, or use the
 * shipped InMemoryRateLimitStore (the default) for single-instance
 * deployments.
 */
export interface RateLimitStore {
  /**
   * Atomically count one hit against `key` inside a fixed window of
   * `windowSeconds` and return the post-increment count (SQL: `UPDATE ...
   * RETURNING`; Redis: `INCR` + `EXPIRE`). The first hit for a key starts a
   * new window.
   */
  hit(key: string, windowSeconds: number): Promise<RateLimitHit>
}

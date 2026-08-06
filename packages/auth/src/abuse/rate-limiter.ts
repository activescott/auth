import type { RateLimitStore } from "./rate-limit-store.js"

const MS_PER_SECOND = 1000

/**
 * One fixed-window limit: at most `max` hits per `windowSeconds`.
 * Combine a short window with a long one to allow a burst while capping the
 * sustained rate (e.g. 3/minute plus 10/hour).
 */
export interface RateLimitRule {
  windowSeconds: number
  max: number
}

/**
 * Outcome of evaluating a rule list. `rule` and `retryAfterSeconds` are set
 * only when a rule was exceeded.
 */
export interface RateLimitVerdict {
  allowed: boolean
  rule?: RateLimitRule
  retryAfterSeconds?: number
}

/**
 * Evaluates fixed-window rules against a RateLimitStore.
 *
 * Rules are checked in order and evaluation stops at the first one exceeded,
 * so an already-blocked caller does not inflate the counters of the remaining
 * rules.
 */
export class RateLimiter {
  public constructor(private readonly store: RateLimitStore) {}

  /**
   * Count this request against every rule for `keyPrefix` (e.g.
   * `ip:email:203.0.113.7`) and return the first rule it exceeds.
   */
  public async check(
    keyPrefix: string,
    rules: RateLimitRule[],
  ): Promise<RateLimitVerdict> {
    for (const rule of rules) {
      const hit = await this.store.hit(
        `${keyPrefix}:${rule.windowSeconds}`,
        rule.windowSeconds,
      )
      if (hit.count > rule.max) {
        const remainingMs = hit.resetAt.getTime() - Date.now()
        return {
          allowed: false,
          rule,
          retryAfterSeconds: Math.max(
            1,
            Math.ceil(remainingMs / MS_PER_SECOND),
          ),
        }
      }
    }
    return { allowed: true }
  }
}

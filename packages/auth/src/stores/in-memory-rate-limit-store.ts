import type { RateLimitHit, RateLimitStore } from "../abuse/rate-limit-store.js"

const MS_PER_SECOND = 1000
const SECONDS_PER_MINUTE = 60
/** Interval between sweeps of ended windows in minutes */
const SWEEP_INTERVAL_MINUTES = 5

interface Window {
  count: number
  resetAtMs: number
}

/**
 * In-memory RateLimitStore for single-instance deployments and development.
 * This is the default store when an application configures no other one.
 *
 * Counters are lost on restart and not shared across instances, so a
 * multi-instance deployment effectively multiplies every limit by the
 * instance count. Implement RateLimitStore against Redis or a shared database
 * there instead.
 */
export class InMemoryRateLimitStore implements RateLimitStore {
  private windows = new Map<string, Window>()
  private sweepInterval: ReturnType<typeof setInterval> | null = null

  public constructor(
    sweepIntervalMs: number = SWEEP_INTERVAL_MINUTES *
      SECONDS_PER_MINUTE *
      MS_PER_SECOND,
  ) {
    this.sweepInterval = setInterval(() => this.sweep(), sweepIntervalMs)
  }

  /**
   * Clean up resources (call when shutting down)
   */
  public destroy(): void {
    if (this.sweepInterval) {
      clearInterval(this.sweepInterval)
      this.sweepInterval = null
    }
  }

  public hit(key: string, windowSeconds: number): Promise<RateLimitHit> {
    const now = Date.now()
    const existing = this.windows.get(key)

    if (!existing || existing.resetAtMs <= now) {
      const window = {
        count: 1,
        resetAtMs: now + windowSeconds * MS_PER_SECOND,
      }
      this.windows.set(key, window)
      return Promise.resolve({
        count: window.count,
        resetAt: new Date(window.resetAtMs),
      })
    }

    existing.count += 1
    return Promise.resolve({
      count: existing.count,
      resetAt: new Date(existing.resetAtMs),
    })
  }

  private sweep(): void {
    const now = Date.now()
    for (const [key, window] of this.windows.entries()) {
      if (window.resetAtMs <= now) {
        this.windows.delete(key)
      }
    }
  }
}

import type { RateLimitHit, RateLimitStore } from "../abuse/rate-limit-store.js"

const MS_PER_SECOND = 1000
const SECONDS_PER_MINUTE = 60
/** Interval between sweeps of ended windows in minutes */
const SWEEP_INTERVAL_MINUTES = 5

/** Default cap on stored windows, ended ones included until swept */
const DEFAULT_MAX_KEYS = 100_000

interface Window {
  count: number
  resetAtMs: number
}

/** Options for InMemoryRateLimitStore */
export interface InMemoryRateLimitStoreOptions {
  /** How often ended windows are swept, in milliseconds (default 5 minutes) */
  sweepIntervalMs?: number
  /**
   * Most keys held at once (default 100,000). Starting a window for a new key
   * past that evicts the oldest window, so a caller who rotates spoofed IPs
   * cannot grow memory without limit. An evicted key starts counting from
   * zero again, so under that kind of flood some limits reset early: size
   * this well above the distinct IPs you expect within an hour.
   */
  maxKeys?: number
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
  private readonly maxKeys: number

  /**
   * @param options Store options, or (for backwards compatibility) the sweep
   * interval in milliseconds on its own
   */
  public constructor(options: InMemoryRateLimitStoreOptions | number = {}) {
    const resolved =
      typeof options === "number" ? { sweepIntervalMs: options } : options
    this.maxKeys = resolved.maxKeys ?? DEFAULT_MAX_KEYS
    this.sweepInterval = setInterval(
      () => this.sweep(),
      resolved.sweepIntervalMs ??
        SWEEP_INTERVAL_MINUTES * SECONDS_PER_MINUTE * MS_PER_SECOND,
    )
  }

  /** Number of windows currently held, ended ones included until swept */
  public get size(): number {
    return this.windows.size
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
      // Re-insert so Map order stays oldest-window-first for eviction
      this.windows.delete(key)
      if (this.windows.size >= this.maxKeys) this.evictOldest()
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

  /**
   * Drop the oldest windows until there is room for one more (Map iteration
   * is insertion order)
   */
  private evictOldest(): void {
    for (const key of this.windows.keys()) {
      if (this.windows.size < this.maxKeys) break
      this.windows.delete(key)
    }
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

import type { AuthUser, Identity } from "../types.js"

const MS_PER_SECOND = 1000
const SECONDS_PER_MINUTE = 60

/** How long a verified session is reused when `session.cacheTtlMs` is unset */
export const DEFAULT_CACHE_TTL_MS = 2 * SECONDS_PER_MINUTE * MS_PER_SECOND

/**
 * How many sessions the cache holds. The sweep only runs every few minutes,
 * so between sweeps this is what keeps a long-lived process from holding one
 * entry per session token it has ever seen. Sessions are small and the number
 * of people using an app at once is much smaller than this, so hitting the
 * bound means something is wrong (or the deployment is big enough to want the
 * cache off).
 */
export const DEFAULT_CACHE_MAX_ENTRIES = 10_000

/** A session that was verified against the stores, and when that happened */
export interface SessionCacheEntry {
  user: AuthUser | null
  identity: Identity | null
  timestamp: number
}

/**
 * In-memory cache of verified sessions, keyed by the raw session token, so a
 * page that calls `verifySession` in several loaders costs one pair of store
 * reads instead of one per loader. Per process: nothing is shared between
 * instances, which is fine because an entry is only ever a repeat of what the
 * stores just said.
 *
 * A TTL of 0 (or less) turns it off entirely. `get` always misses and `set`
 * stores nothing.
 */
export class SessionCache {
  private cache = new Map<string, SessionCacheEntry>()
  private readonly ttl: number
  private readonly maxEntries: number

  public constructor(
    ttlMs: number = DEFAULT_CACHE_TTL_MS,
    maxEntries: number = DEFAULT_CACHE_MAX_ENTRIES,
  ) {
    this.ttl = ttlMs
    this.maxEntries = maxEntries
  }

  /** False when the cache is off, so callers can skip the cleanup timer */
  public get enabled(): boolean {
    return this.ttl > 0
  }

  /** Entries currently held, for tests and diagnostics */
  public get size(): number {
    return this.cache.size
  }

  public get(token: string): SessionCacheEntry | undefined {
    if (!this.enabled) return undefined

    const entry = this.cache.get(token)
    if (!entry) return undefined

    // Check if expired
    if (Date.now() - entry.timestamp > this.ttl) {
      this.cache.delete(token)
      return undefined
    }

    return entry
  }

  public set(
    token: string,
    user: AuthUser | null,
    identity: Identity | null,
  ): void {
    if (!this.enabled) return

    if (!this.cache.has(token) && this.cache.size >= this.maxEntries) {
      this.evict()
    }

    this.cache.set(token, {
      user,
      identity,
      timestamp: Date.now(),
    })
  }

  public cleanup(): void {
    const now = Date.now()
    for (const [token, entry] of this.cache.entries()) {
      if (now - entry.timestamp > this.ttl) {
        this.cache.delete(token)
      }
    }
  }

  /**
   * Make room for one more entry: drop what has expired, and if that was not
   * enough, drop the front of the map. That is approximately oldest-first:
   * re-setting an existing key keeps its original position, so a rewritten
   * entry can be evicted before older ones. The only cost is an extra store
   * read.
   */
  private evict(): void {
    this.cleanup()
    while (this.cache.size >= this.maxEntries) {
      const oldest = this.cache.keys().next()
      if (oldest.done) return
      this.cache.delete(oldest.value)
    }
  }
}

import type { Challenge, ChallengeStore } from "../types.js"

const MS_PER_SECOND = 1000
const SECONDS_PER_MINUTE = 60
/** Interval between sweeps of expired challenges in minutes */
const SWEEP_INTERVAL_MINUTES = 5
/** Default cap on stored challenges, live and expired together */
const DEFAULT_MAX_CHALLENGES = 10_000

/** Options for InMemoryChallengeStore */
export interface InMemoryChallengeStoreOptions {
  /** How often expired challenges are swept, in milliseconds (default 5 minutes) */
  sweepIntervalMs?: number
  /**
   * Most challenges held at once (default 10,000). When a create would
   * exceed it, expired challenges are dropped first, then the oldest live
   * ones, so a loop of unauthenticated requests cannot grow memory without
   * limit. Evicting a live challenge fails that sign-in attempt, and the
   * store is shared by every provider, so a flood through one endpoint fails
   * other users' in-flight email, SMS, OIDC, and passkey sign-ins until it
   * stops. The first live eviction in each sweep interval is logged with
   * `console.warn`. Size this above the number of ceremonies you expect in
   * flight within one challenge lifetime.
   */
  maxChallenges?: number
}

/**
 * In-memory ChallengeStore for single-instance deployments and development.
 *
 * Challenges are lost on restart and not shared across instances. For
 * multi-instance deployments, implement ChallengeStore against a shared
 * database or cache instead.
 */
export class InMemoryChallengeStore implements ChallengeStore {
  private challenges = new Map<string, Challenge>()
  private sweepInterval: ReturnType<typeof setInterval> | null = null
  private readonly maxChallenges: number
  /** Whether a live eviction has been logged since the last scheduled sweep */
  private warnedSinceSweep = false

  /**
   * @param options Store options, or (for backwards compatibility) the sweep
   * interval in milliseconds on its own
   */
  public constructor(options: InMemoryChallengeStoreOptions | number = {}) {
    const resolved =
      typeof options === "number" ? { sweepIntervalMs: options } : options
    this.maxChallenges = resolved.maxChallenges ?? DEFAULT_MAX_CHALLENGES
    this.sweepInterval = setInterval(
      () => {
        this.sweep()
        this.warnedSinceSweep = false
      },
      resolved.sweepIntervalMs ??
        SWEEP_INTERVAL_MINUTES * SECONDS_PER_MINUTE * MS_PER_SECOND,
    )
  }

  /** Number of challenges currently held, expired ones included until swept */
  public get size(): number {
    return this.challenges.size
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

  public create(
    data: Omit<Challenge, "attempts" | "createdAt">,
  ): Promise<Challenge> {
    const challenge: Challenge = {
      ...data,
      attempts: 0,
      createdAt: new Date(),
    }
    this.challenges.delete(challenge.id)
    if (this.challenges.size >= this.maxChallenges) this.makeRoom()
    this.challenges.set(challenge.id, challenge)
    return Promise.resolve(challenge)
  }

  public findById(id: string): Promise<Challenge | null> {
    return Promise.resolve(this.challenges.get(id) ?? null)
  }

  public incrementAttempts(id: string): Promise<number> {
    const challenge = this.challenges.get(id)
    if (!challenge) {
      return Promise.reject(new Error(`Challenge not found: ${id}`))
    }
    challenge.attempts += 1
    return Promise.resolve(challenge.attempts)
  }

  public delete(id: string): Promise<void> {
    this.challenges.delete(id)
    return Promise.resolve()
  }

  /**
   * Free at least one slot: sweep expired challenges, then evict the oldest
   * live ones (Map iteration is insertion order). A live eviction fails a
   * sign-in in progress, so the first one in each sweep window is logged.
   */
  private makeRoom(): void {
    this.sweep()
    if (this.challenges.size < this.maxChallenges) return
    if (!this.warnedSinceSweep) {
      this.warnedSinceSweep = true
      // eslint-disable-next-line no-console
      console.warn(
        `[auth] InMemoryChallengeStore is full (maxChallenges=${this.maxChallenges}): ` +
          "evicting live challenges, which fails those sign-ins. A flood of " +
          "sign-in requests is the usual cause; check the per-IP limits and " +
          "abuse.clientIp.",
      )
    }
    for (const id of this.challenges.keys()) {
      if (this.challenges.size < this.maxChallenges) break
      this.challenges.delete(id)
    }
  }

  private sweep(): void {
    const now = Date.now()
    for (const [id, challenge] of this.challenges.entries()) {
      if (challenge.expiresAt.getTime() < now) {
        this.challenges.delete(id)
      }
    }
  }
}

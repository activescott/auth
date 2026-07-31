import type { Challenge, ChallengeStore } from "../types.js"

const MS_PER_SECOND = 1000
const SECONDS_PER_MINUTE = 60
/** Interval between sweeps of expired challenges in minutes */
const SWEEP_INTERVAL_MINUTES = 5

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

  public create(
    data: Omit<Challenge, "attempts" | "createdAt">,
  ): Promise<Challenge> {
    const challenge: Challenge = {
      ...data,
      attempts: 0,
      createdAt: new Date(),
    }
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

  private sweep(): void {
    const now = Date.now()
    for (const [id, challenge] of this.challenges.entries()) {
      if (challenge.expiresAt.getTime() < now) {
        this.challenges.delete(id)
      }
    }
  }
}

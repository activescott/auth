import { describe, it, expect, afterEach } from "vitest"
import { InMemoryChallengeStore } from "../stores/in-memory-challenge-store.js"
import type { Challenge } from "../types.js"

const FUTURE_MS = 10 * 60 * 1000
const SHORT_SWEEP_MS = 10

function challengeData(
  overrides: Partial<Omit<Challenge, "attempts" | "createdAt">> = {},
): Omit<Challenge, "attempts" | "createdAt"> {
  return {
    id: "challenge-1",
    type: "email-otp",
    identifier: "user@example.com",
    hashedCode: "abc123",
    maxAttempts: 5,
    expiresAt: new Date(Date.now() + FUTURE_MS),
    ...overrides,
  }
}

describe("InMemoryChallengeStore", () => {
  let store: InMemoryChallengeStore

  afterEach(() => {
    store?.destroy()
  })

  it("should create a challenge with zero attempts and a created date", async () => {
    store = new InMemoryChallengeStore()
    const challenge = await store.create(challengeData())

    expect(challenge.attempts).toBe(0)
    expect(challenge.createdAt).toBeInstanceOf(Date)
    expect(challenge.id).toBe("challenge-1")
  })

  it("should find a created challenge by ID", async () => {
    store = new InMemoryChallengeStore()
    await store.create(challengeData())

    const found = await store.findById("challenge-1")
    expect(found?.identifier).toBe("user@example.com")
  })

  it("should return null for an unknown ID", async () => {
    store = new InMemoryChallengeStore()
    expect(await store.findById("nope")).toBeNull()
  })

  it("should return expired challenges from findById so callers can distinguish expired from unknown", async () => {
    store = new InMemoryChallengeStore()
    await store.create(
      challengeData({ expiresAt: new Date(Date.now() - 1000) }),
    )

    const found = await store.findById("challenge-1")
    expect(found).not.toBeNull()
  })

  it("should increment attempts and return the new count", async () => {
    store = new InMemoryChallengeStore()
    await store.create(challengeData())

    expect(await store.incrementAttempts("challenge-1")).toBe(1)
    expect(await store.incrementAttempts("challenge-1")).toBe(2)

    const found = await store.findById("challenge-1")
    expect(found?.attempts).toBe(2)
  })

  it("should reject incrementAttempts for an unknown challenge", async () => {
    store = new InMemoryChallengeStore()
    await expect(store.incrementAttempts("nope")).rejects.toThrow(
      "Challenge not found",
    )
  })

  it("should delete a challenge", async () => {
    store = new InMemoryChallengeStore()
    await store.create(challengeData())
    await store.delete("challenge-1")

    expect(await store.findById("challenge-1")).toBeNull()
  })

  it("should sweep expired challenges but keep live ones", async () => {
    store = new InMemoryChallengeStore(SHORT_SWEEP_MS)
    await store.create(
      challengeData({ id: "expired", expiresAt: new Date(Date.now() - 1000) }),
    )
    await store.create(challengeData({ id: "live" }))

    await new Promise((resolve) => setTimeout(resolve, SHORT_SWEEP_MS * 5))

    expect(await store.findById("expired")).toBeNull()
    expect(await store.findById("live")).not.toBeNull()
  })

  describe("size bound", () => {
    it("caps the store at maxChallenges under a loop of creates, evicting the oldest", async () => {
      store = new InMemoryChallengeStore({ maxChallenges: 100 })

      for (let index = 0; index < 1000; index++) {
        await store.create(challengeData({ id: `challenge-${index}` }))
        expect(store.size).toBeLessThanOrEqual(100)
      }

      expect(store.size).toBe(100)
      expect(await store.findById("challenge-999")).not.toBeNull()
      expect(await store.findById("challenge-900")).not.toBeNull()
      expect(await store.findById("challenge-899")).toBeNull()
    })

    it("drops expired challenges before evicting live ones", async () => {
      store = new InMemoryChallengeStore({ maxChallenges: 3 })
      await store.create(challengeData({ id: "live-1" }))
      await store.create(
        challengeData({
          id: "expired",
          expiresAt: new Date(Date.now() - 1000),
        }),
      )
      await store.create(challengeData({ id: "live-2" }))

      await store.create(challengeData({ id: "live-3" }))

      expect(store.size).toBe(3)
      expect(await store.findById("expired")).toBeNull()
      expect(await store.findById("live-1")).not.toBeNull()
    })

    it("is bounded by default, with no options", async () => {
      store = new InMemoryChallengeStore()

      for (let index = 0; index < 10_500; index++) {
        await store.create(challengeData({ id: `challenge-${index}` }))
      }

      expect(store.size).toBe(10_000)
    })

    it("still accepts a sweep interval as its only argument", async () => {
      store = new InMemoryChallengeStore(SHORT_SWEEP_MS)
      await store.create(
        challengeData({ expiresAt: new Date(Date.now() - 1000) }),
      )

      await new Promise((resolve) => setTimeout(resolve, SHORT_SWEEP_MS * 5))

      expect(store.size).toBe(0)
    })
  })
})

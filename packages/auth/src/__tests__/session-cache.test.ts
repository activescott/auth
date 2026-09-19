import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import { SessionCache } from "../session/session-cache.js"
import type { AuthUser, Identity } from "../types.js"

const user: AuthUser = { id: "user-1" }
const identity: Identity = {
  id: "identity-1",
  userId: "user-1",
  provider: "email",
  identifier: "user@example.com",
  providerState: {},
  createdAt: new Date(),
}

const ONE_MINUTE_MS = 60_000

describe("SessionCache", () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it("returns what was stored", () => {
    const cache = new SessionCache(ONE_MINUTE_MS)
    cache.set("token", user, identity)

    expect(cache.get("token")).toMatchObject({ user, identity })
  })

  it("caches a session that resolved to no user", () => {
    const cache = new SessionCache(ONE_MINUTE_MS)
    cache.set("token", null, null)

    // Present but empty: the store was asked and said no, which is the answer
    // worth not asking again.
    expect(cache.get("token")).toMatchObject({ user: null, identity: null })
  })

  it("misses once the entry is older than the TTL", () => {
    const cache = new SessionCache(ONE_MINUTE_MS)
    cache.set("token", user, identity)

    vi.advanceTimersByTime(ONE_MINUTE_MS + 1)

    expect(cache.get("token")).toBeUndefined()
    expect(cache.size).toBe(0)
  })

  it("drops expired entries on cleanup and keeps the rest", () => {
    const cache = new SessionCache(ONE_MINUTE_MS)
    cache.set("old", user, identity)
    vi.advanceTimersByTime(ONE_MINUTE_MS - 1)
    cache.set("new", user, identity)

    vi.advanceTimersByTime(2)
    cache.cleanup()

    expect(cache.size).toBe(1)
    expect(cache.get("new")).toBeDefined()
  })

  describe("ttl of 0", () => {
    it("stores nothing and always misses", () => {
      const cache = new SessionCache(0)
      cache.set("token", user, identity)

      expect(cache.get("token")).toBeUndefined()
      expect(cache.size).toBe(0)
    })

    it("reports itself disabled", () => {
      expect(new SessionCache(0).enabled).toBe(false)
      expect(new SessionCache(ONE_MINUTE_MS).enabled).toBe(true)
    })
  })

  describe("size bound", () => {
    it("evicts the oldest entry to stay at the bound", () => {
      const cache = new SessionCache(ONE_MINUTE_MS, 3)
      for (const token of ["a", "b", "c"]) {
        cache.set(token, user, identity)
        vi.advanceTimersByTime(1)
      }

      cache.set("d", user, identity)

      expect(cache.size).toBe(3)
      expect(cache.get("a")).toBeUndefined()
      expect(cache.get("b")).toBeDefined()
      expect(cache.get("d")).toBeDefined()
    })

    it("overwrites an existing token without evicting anything", () => {
      const cache = new SessionCache(ONE_MINUTE_MS, 2)
      cache.set("a", user, identity)
      cache.set("b", user, identity)

      cache.set("b", null, null)

      expect(cache.size).toBe(2)
      expect(cache.get("a")).toBeDefined()
      expect(cache.get("b")).toMatchObject({ user: null })
    })

    it("stays bounded across many writes", () => {
      const cache = new SessionCache(ONE_MINUTE_MS, 10)
      for (let index = 0; index < 100; index++) {
        cache.set(`token-${index}`, user, identity)
      }

      expect(cache.size).toBe(10)
      expect(cache.get("token-99")).toBeDefined()
    })
  })
})

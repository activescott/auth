import { describe, it, expect } from "vitest"
import { RateLimiter } from "../abuse/rate-limiter.js"
import { InMemoryRateLimitStore } from "../stores/in-memory-rate-limit-store.js"

const BURST = { windowSeconds: 60, max: 2 }
const SUSTAINED = { windowSeconds: 3600, max: 5 }

describe("RateLimiter", () => {
  it("allows hits up to the rule maximum", async () => {
    const store = new InMemoryRateLimitStore()
    const limiter = new RateLimiter(store)

    expect((await limiter.check("ip:email:1.1.1.1", [BURST])).allowed).toBe(
      true,
    )
    expect((await limiter.check("ip:email:1.1.1.1", [BURST])).allowed).toBe(
      true,
    )

    store.destroy()
  })

  it("blocks on the burst rule before the sustained rule", async () => {
    const store = new InMemoryRateLimitStore()
    const limiter = new RateLimiter(store)
    const rules = [BURST, SUSTAINED]

    await limiter.check("ip:email:1.1.1.1", rules)
    await limiter.check("ip:email:1.1.1.1", rules)
    const verdict = await limiter.check("ip:email:1.1.1.1", rules)

    expect(verdict.allowed).toBe(false)
    expect(verdict.rule).toEqual(BURST)
    expect(verdict.retryAfterSeconds).toBeGreaterThan(0)

    store.destroy()
  })

  it("does not count blocked requests against later rules", async () => {
    const hits: string[] = []
    const limiter = new RateLimiter({
      hit: (key) => {
        hits.push(key)
        return Promise.resolve({
          count: hits.filter((entry) => entry === key).length,
          resetAt: new Date(Date.now() + 60_000),
        })
      },
    })
    const rules = [{ windowSeconds: 60, max: 1 }, SUSTAINED]

    await limiter.check("k", rules)
    await limiter.check("k", rules)

    // Second call stops at the exceeded burst rule, so the sustained rule was
    // only counted once
    expect(hits.filter((key) => key === "k:3600")).toHaveLength(1)
  })

  it("keys separately per prefix", async () => {
    const store = new InMemoryRateLimitStore()
    const limiter = new RateLimiter(store)
    const rules = [{ windowSeconds: 60, max: 1 }]

    await limiter.check("ip:email:1.1.1.1", rules)
    const other = await limiter.check("ip:email:2.2.2.2", rules)

    expect(other.allowed).toBe(true)

    store.destroy()
  })
})

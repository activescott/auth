import { describe, it, expect, vi, afterEach } from "vitest"
import { InMemoryRateLimitStore } from "../stores/in-memory-rate-limit-store.js"

const MS_PER_SECOND = 1000

describe("InMemoryRateLimitStore", () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it("counts hits within a window", async () => {
    const store = new InMemoryRateLimitStore()

    expect((await store.hit("a", 60)).count).toBe(1)
    expect((await store.hit("a", 60)).count).toBe(2)
    expect((await store.hit("a", 60)).count).toBe(3)

    store.destroy()
  })

  it("counts keys independently", async () => {
    const store = new InMemoryRateLimitStore()

    await store.hit("a", 60)
    await store.hit("a", 60)

    expect((await store.hit("b", 60)).count).toBe(1)

    store.destroy()
  })

  it("resets the count when the window ends", async () => {
    vi.useFakeTimers()
    const store = new InMemoryRateLimitStore()

    const first = await store.hit("a", 60)
    expect(first.count).toBe(1)
    expect(first.resetAt.getTime()).toBe(Date.now() + 60 * MS_PER_SECOND)

    vi.advanceTimersByTime(61 * MS_PER_SECOND)

    expect((await store.hit("a", 60)).count).toBe(1)

    store.destroy()
  })

  it("sweeps ended windows without changing observable counts", async () => {
    vi.useFakeTimers()
    const sweepMs = 1000
    const store = new InMemoryRateLimitStore(sweepMs)

    await store.hit("a", 1)
    vi.advanceTimersByTime(2 * MS_PER_SECOND)

    expect((await store.hit("a", 1)).count).toBe(1)

    store.destroy()
  })
})

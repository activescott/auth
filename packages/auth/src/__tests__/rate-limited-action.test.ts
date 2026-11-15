import { describe, it, expect, vi, afterEach } from "vitest"
import { Auth } from "../auth.js"
import type { AbuseConfig, AbuseEvent } from "../abuse/abuse-guard.js"
import { InMemoryChallengeStore } from "../stores/in-memory-challenge-store.js"
import type { AuthProvider } from "../types.js"

// Drives Auth.handleRequest with a provider whose action routes opt into
// `rateLimitByIp`, the way the passkey options endpoints do, to pin down how
// the per-IP action limit resolves the client IP.

const BASE_URL = "https://example.com"
const HTTP_OK = 200
const HTTP_TOO_MANY_REQUESTS = 429
const LIMIT = 3
const ATTEMPTS = 10
const PROXY_IP = "203.0.113.7"

function createProvider(): AuthProvider {
  return {
    id: "fake",
    name: "Fake",
    initiate: vi.fn(),
    verify: vi.fn(),
    handleAction: vi.fn(async () => Response.json({ ok: true })),
    describe: () => ({ settings: {} }),
    getRoutes: () => [
      {
        method: "POST",
        path: "/fake/authenticate-options",
        handler: "action",
        rateLimitByIp: true,
      },
      {
        method: "POST",
        path: "/fake/register-options",
        handler: "action",
        rateLimitByIp: true,
      },
    ],
  }
}

describe("rate-limited action routes", () => {
  const cleanup: Array<() => void> = []

  afterEach(() => {
    for (const fn of cleanup.splice(0)) fn()
    vi.restoreAllMocks()
  })

  function setup(abuse: AbuseConfig = {}): {
    auth: Auth
    onBlocked: ReturnType<typeof vi.fn<(event: AbuseEvent) => void>>
  } {
    vi.spyOn(console, "warn").mockImplementation(() => {})
    const onBlocked = vi.fn<(event: AbuseEvent) => void>()
    const challengeStore = new InMemoryChallengeStore()
    const auth = new Auth({
      session: {
        secret: "test-session-secret",
        maxAge: "1d",
        cookieName: "session",
        cookie: { secure: true, sameSite: "lax" },
      },
      identityStore: {
        findByProviderAndIdentifier: vi.fn(),
        findByUserId: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        reassignByUserId: vi.fn(),
      },
      userStore: { findById: vi.fn(), create: vi.fn(), onMerge: vi.fn() },
      challengeStore,
      abuse: {
        perIpAction: [{ windowSeconds: 60, max: LIMIT }],
        onBlocked,
        ...abuse,
      },
      providers: [createProvider()],
    })
    cleanup.push(() => {
      auth.destroy()
      challengeStore.destroy()
    })
    return { auth, onBlocked }
  }

  async function statuses(
    auth: Auth,
    headers: (index: number) => Record<string, string>,
    action = "authenticate-options",
  ): Promise<number[]> {
    const result: number[] = []
    for (let index = 0; index < ATTEMPTS; index++) {
      const response = await auth.handleRequest(
        new Request(`${BASE_URL}/auth/fake/${action}`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...headers(index) },
          body: "{}",
        }),
      )
      result.push(response.status)
    }
    return result
  }

  function expectLimited(result: number[]): void {
    expect(result).toEqual([
      ...Array<number>(LIMIT).fill(HTTP_OK),
      ...Array<number>(ATTEMPTS - LIMIT).fill(HTTP_TOO_MANY_REQUESTS),
    ])
  }

  it("counts requests with no client IP against one shared bucket", async () => {
    const { auth, onBlocked } = setup()

    expectLimited(await statuses(auth, () => ({})))
    expect(onBlocked).toHaveBeenCalledWith(
      expect.objectContaining({ reason: "ip_rate_limited", ip: null }),
    )
  })

  it("names abuse.clientIp in the block log when no client IP is known", async () => {
    const { auth } = setup()

    await statuses(auth, () => ({}))

    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining("ip=unknown (set abuse.clientIp)"),
    )
  })

  it("counts no-IP requests in the shared bucket when getClientIp returns null", async () => {
    const { auth } = setup({ clientIp: { getClientIp: () => null } })

    expectLimited(await statuses(auth, () => ({ "X-Forwarded-For": PROXY_IP })))
  })

  it("ignores a rotating cf-connecting-ip by default", async () => {
    const { auth } = setup()

    // A non-Cloudflare proxy passes cf-connecting-ip through untouched and
    // only rewrites X-Forwarded-For, so the spoofed header must not count
    expectLimited(
      await statuses(auth, (index) => ({
        "X-Forwarded-For": PROXY_IP,
        "cf-connecting-ip": `198.51.100.${index}`,
      })),
    )
  })

  it("counts each action route separately", async () => {
    const { auth, onBlocked } = setup()
    const sameIp = (): Record<string, string> => ({
      "X-Forwarded-For": PROXY_IP,
    })

    // A burst of registrations must not lock the same IP out of sign-in
    expectLimited(await statuses(auth, sameIp, "register-options"))
    const signIn = await statuses(auth, sameIp, "authenticate-options")

    expectLimited(signIn)
    expect(onBlocked).toHaveBeenLastCalledWith(
      expect.objectContaining({ action: "authenticate-options" }),
    )
  })

  it("keys by cf-connecting-ip when the app trusts Cloudflare", async () => {
    const { auth } = setup({ clientIp: { trustCloudflare: true } })

    const result = await statuses(auth, (index) => ({
      "X-Forwarded-For": PROXY_IP,
      "cf-connecting-ip": `198.51.100.${index}`,
    }))

    expect(result).toEqual(Array<number>(ATTEMPTS).fill(HTTP_OK))
  })

  it("counts IPv6 addresses in one /64 against one bucket", async () => {
    const { auth } = setup()

    expectLimited(
      await statuses(auth, (index) => ({
        "X-Forwarded-For": `2001:db8:0:0::${index + 1}`,
      })),
    )
  })

  it("counts one IPv4 client on rotating source ports against one bucket", async () => {
    const { auth } = setup()

    expectLimited(
      await statuses(auth, (index) => ({
        "X-Forwarded-For": `${PROXY_IP}:${50000 + index}`,
      })),
    )
  })
})

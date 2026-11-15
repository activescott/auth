import { describe, it, expect, vi, afterEach } from "vitest"
import type {
  AbuseConfig,
  AbuseEvent,
  Identity,
  IdentityStore,
  UserStore,
} from "@activescott/auth"
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import { PasskeyProvider } from "../passkey-provider.js"
import type { WebAuthnServer } from "../types.js"

// Runs the passkey provider behind a real Auth, because the per-IP limit on
// the options endpoints is applied by Auth.handleRequest, not the provider.

const BASE_URL = "https://example.com"
const SESSION_SECRET = "test-session-secret-at-least-32-chars"
const CLIENT_IP = "203.0.113.7"
const OTHER_IP = "198.51.100.9"
/** Mirrors the documented default: 20 options calls per IP per minute */
const DEFAULT_PER_MINUTE = 20
const HTTP_OK = 200
const HTTP_UNAUTHORIZED = 401
const HTTP_TOO_MANY_REQUESTS = 429

const EMAIL_IDENTITY: Identity = {
  id: "identity-email",
  userId: "user-1",
  provider: "email",
  identifier: "user@example.com",
  providerState: {},
  createdAt: new Date(),
}

function createFakeWebAuthn(): WebAuthnServer {
  return {
    generateRegistrationOptions: vi.fn(async () => ({
      challenge: "reg-challenge",
      rp: { name: "Test App", id: "example.com" },
      user: { id: "dXNlci0x", name: "u", displayName: "u" },
      pubKeyCredParams: [],
    })),
    verifyRegistrationResponse: vi.fn(),
    generateAuthenticationOptions: vi.fn(async () => ({
      challenge: "auth-challenge",
      rpId: "example.com",
      allowCredentials: [],
    })),
    verifyAuthenticationResponse: vi.fn(),
  } as unknown as WebAuthnServer
}

function createAuth(abuse?: AbuseConfig): {
  auth: Auth
  challengeStore: InMemoryChallengeStore
} {
  const identityStore: IdentityStore = {
    findByProviderAndIdentifier: vi.fn(async () => null),
    findByUserId: vi.fn(async () => [EMAIL_IDENTITY]),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    reassignByUserId: vi.fn(),
  }
  const userStore: UserStore = {
    findById: vi.fn(async () => ({ id: "user-1" })),
    create: vi.fn(),
    onMerge: vi.fn(),
  }
  const challengeStore = new InMemoryChallengeStore()
  const auth = new Auth({
    session: {
      secret: SESSION_SECRET,
      maxAge: "7d",
      cookieName: "auth_session",
      cookie: { secure: false, sameSite: "lax" },
    },
    identityStore,
    userStore,
    challengeStore,
    abuse,
    providers: [
      new PasskeyProvider(
        { rpName: "Test App", challengeSecret: "test-challenge-secret" },
        createFakeWebAuthn(),
      ),
    ],
  })
  return { auth, challengeStore }
}

function optionsRequest(
  action: "authenticate-options" | "register-options",
  ip: string,
  cookie?: string,
): Request {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Forwarded-For": ip,
  }
  if (cookie) headers.Cookie = cookie
  return new Request(`${BASE_URL}/auth/passkey/${action}`, {
    method: "POST",
    headers,
    body: "{}",
  })
}

async function statuses(
  auth: Auth,
  count: number,
  request: () => Request,
): Promise<number[]> {
  const result: number[] = []
  for (let index = 0; index < count; index++) {
    const response = await auth.handleRequest(request())
    result.push(response.status)
  }
  return result
}

describe("passkey options endpoints behind the abuse guard", () => {
  const cleanup: Array<() => void> = []

  afterEach(() => {
    for (const fn of cleanup.splice(0)) fn()
    vi.restoreAllMocks()
  })

  function setup(abuse?: AbuseConfig): {
    auth: Auth
    challengeStore: InMemoryChallengeStore
  } {
    vi.spyOn(console, "warn").mockImplementation(() => {})
    const created = createAuth(abuse)
    cleanup.push(() => {
      created.auth.destroy()
      created.challengeStore.destroy()
    })
    return created
  }

  it("refuses authenticate-options past the default per-IP limit and keeps the store bounded", async () => {
    const onBlocked = vi.fn<(event: AbuseEvent) => void>()
    const { auth, challengeStore } = setup({ onBlocked })

    const result = await statuses(auth, DEFAULT_PER_MINUTE + 30, () =>
      optionsRequest("authenticate-options", CLIENT_IP),
    )

    expect(result.slice(0, DEFAULT_PER_MINUTE)).toEqual(
      Array(DEFAULT_PER_MINUTE).fill(HTTP_OK),
    )
    expect(result.slice(DEFAULT_PER_MINUTE)).toEqual(
      Array(30).fill(HTTP_TOO_MANY_REQUESTS),
    )
    // Refused calls write nothing, so the store holds one row per allowed call
    expect(challengeStore.size).toBe(DEFAULT_PER_MINUTE)
    expect(onBlocked).toHaveBeenCalledTimes(30)
    expect(onBlocked.mock.calls[0]?.[0]).toMatchObject({
      reason: "ip_rate_limited",
      providerId: "passkey",
      ip: CLIENT_IP,
      rule: { windowSeconds: 60, max: DEFAULT_PER_MINUTE },
    })
  })

  it("answers a refused call with RATE_LIMITED JSON and a Retry-After header", async () => {
    const { auth } = setup({ perIpAction: [{ windowSeconds: 60, max: 1 }] })

    await auth.handleRequest(optionsRequest("authenticate-options", CLIENT_IP))
    const refused = await auth.handleRequest(
      optionsRequest("authenticate-options", CLIENT_IP),
    )

    expect(refused.status).toBe(HTTP_TOO_MANY_REQUESTS)
    expect(Number(refused.headers.get("Retry-After"))).toBeGreaterThan(0)
    expect(refused.headers.get("Set-Cookie")).toBeNull()
    const body = (await refused.json()) as {
      success: boolean
      error: { code: string }
    }
    expect(body.success).toBe(false)
    expect(body.error.code).toBe("RATE_LIMITED")
  })

  it("uses the app's perIpAction rules and clientIp resolver", async () => {
    const onBlocked = vi.fn<(event: AbuseEvent) => void>()
    const { auth } = setup({
      perIpAction: [{ windowSeconds: 60, max: 2 }],
      clientIp: { getClientIp: () => "192.0.2.1" },
      onBlocked,
    })

    // The custom resolver ignores X-Forwarded-For, so both IPs share a bucket
    const result = [
      ...(await statuses(auth, 2, () =>
        optionsRequest("authenticate-options", CLIENT_IP),
      )),
      ...(await statuses(auth, 1, () =>
        optionsRequest("authenticate-options", OTHER_IP),
      )),
    ]

    expect(result).toEqual([HTTP_OK, HTTP_OK, HTTP_TOO_MANY_REQUESTS])
    expect(onBlocked).toHaveBeenCalledWith(
      expect.objectContaining({ ip: "192.0.2.1", reason: "ip_rate_limited" }),
    )
  })

  it("counts each client IP separately", async () => {
    const { auth } = setup({ perIpAction: [{ windowSeconds: 60, max: 1 }] })

    const first = await statuses(auth, 2, () =>
      optionsRequest("authenticate-options", CLIENT_IP),
    )
    const second = await statuses(auth, 1, () =>
      optionsRequest("authenticate-options", OTHER_IP),
    )

    expect(first).toEqual([HTTP_OK, HTTP_TOO_MANY_REQUESTS])
    expect(second).toEqual([HTTP_OK])
  })

  it("does not throttle when abuse protection is disabled", async () => {
    const { auth } = setup({
      enabled: false,
      perIpAction: [{ windowSeconds: 60, max: 1 }],
    })

    const result = await statuses(auth, 3, () =>
      optionsRequest("authenticate-options", CLIENT_IP),
    )

    expect(result).toEqual([HTTP_OK, HTTP_OK, HTTP_OK])
  })

  it("does not count verify calls against the options limit", async () => {
    const { auth } = setup({ perIpAction: [{ windowSeconds: 60, max: 1 }] })

    // No challenge cookie, so each verify fails, but none is rate limited
    const verifies = await statuses(
      auth,
      3,
      () =>
        new Request(`${BASE_URL}/auth/passkey/authenticate-verify`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Forwarded-For": CLIENT_IP,
          },
          body: "{}",
        }),
    )
    const options = await statuses(auth, 1, () =>
      optionsRequest("authenticate-options", CLIENT_IP),
    )

    expect(verifies).toEqual([
      HTTP_UNAUTHORIZED,
      HTTP_UNAUTHORIZED,
      HTTP_UNAUTHORIZED,
    ])
    expect(options).toEqual([HTTP_OK])
  })

  describe("register-options", () => {
    it("writes no challenge without a session, however often it is called", async () => {
      const { auth, challengeStore } = setup()

      const result = await statuses(auth, 50, () =>
        optionsRequest("register-options", CLIENT_IP),
      )

      expect(result.every((status) => status !== HTTP_OK)).toBe(true)
      expect(challengeStore.size).toBe(0)
    })

    it("refuses a signed-in caller past the per-IP limit", async () => {
      const onBlocked = vi.fn<(event: AbuseEvent) => void>()
      const { auth, challengeStore } = setup({
        perIpAction: [{ windowSeconds: 60, max: 3 }],
        onBlocked,
      })
      const session = await auth.createSessionCookie(
        { id: "user-1" },
        EMAIL_IDENTITY,
      )
      const cookie = session.split(";")[0]

      const result = await statuses(auth, 5, () =>
        optionsRequest("register-options", CLIENT_IP, cookie),
      )

      expect(result).toEqual([
        HTTP_OK,
        HTTP_OK,
        HTTP_OK,
        HTTP_TOO_MANY_REQUESTS,
        HTTP_TOO_MANY_REQUESTS,
      ])
      expect(challengeStore.size).toBe(3)
      expect(onBlocked).toHaveBeenCalledTimes(2)
      expect(onBlocked.mock.calls[0]?.[0]).toMatchObject({
        reason: "ip_rate_limited",
        providerId: "passkey",
        ip: CLIENT_IP,
      })
    })
  })
})

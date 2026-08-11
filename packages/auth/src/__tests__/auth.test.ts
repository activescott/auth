import { describe, it, expect, vi, afterEach } from "vitest"
import { SignJWT } from "jose"
import { Auth } from "../auth.js"
import { createFormToken } from "../abuse/bot-check.js"
import { SessionManager } from "../session/session-manager.js"
import { InMemoryChallengeStore } from "../stores/in-memory-challenge-store.js"
import type {
  AuthConfig,
  AuthProvider,
  ChallengeStore,
  IdentityStore,
  UserStore,
  Identity,
} from "../types.js"

const TEST_SECRET = "test-session-secret"
const TEST_BASE_URL = "https://example.com"

/** Sign a session-shaped JWT with an arbitrary secret (for negative tests) */
function signTestToken(
  payload: Record<string, string>,
  secret: string,
): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("1h")
    .setIssuer("auth")
    .setAudience("users")
    .sign(new TextEncoder().encode(secret))
}

function createMockIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: "identity-1",
    userId: "user-1",
    provider: "email",
    identifier: "user@example.com",
    providerState: {},
    createdAt: new Date(),
    ...overrides,
  }
}

function createMockProvider(
  overrides: Partial<AuthProvider> = {},
): AuthProvider {
  const id = overrides.id ?? "email"
  return {
    id,
    name: "Email",
    initiate: vi.fn().mockResolvedValue({ success: true, message: "Sent" }),
    verify: vi.fn().mockResolvedValue({
      success: true,
      user: { id: "user-1" },
      identity: createMockIdentity(),
    }),
    getRoutes: vi.fn().mockReturnValue([
      { method: "POST", path: `/${id}/initiate`, handler: "initiate" },
      { method: "GET", path: `/${id}/verify`, handler: "verify" },
      { method: "POST", path: `/${id}/verify`, handler: "verify" },
      { method: "POST", path: `/${id}/register-options`, handler: "action" },
    ]),
    describe: vi.fn().mockReturnValue({ settings: {} }),
    ...overrides,
  }
}

function createMockStores(): {
  identityStore: IdentityStore
  userStore: UserStore
} {
  return {
    identityStore: {
      findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
      findByUserId: vi.fn().mockResolvedValue([createMockIdentity()]),
      create: vi.fn().mockResolvedValue(createMockIdentity()),
      update: vi.fn().mockResolvedValue(createMockIdentity()),
      delete: vi.fn(),
      reassignByUserId: vi.fn(),
    },
    userStore: {
      findById: vi.fn().mockResolvedValue({ id: "user-1" }),
      create: vi.fn().mockResolvedValue({ id: "user-1" }),
      onMerge: vi.fn(),
    },
  }
}

function createMockChallengeStore(): ChallengeStore {
  return {
    create: vi.fn(),
    findById: vi.fn().mockResolvedValue(null),
    incrementAttempts: vi.fn().mockResolvedValue(1),
    delete: vi.fn(),
  }
}

function createAuthConfig(overrides: Partial<AuthConfig> = {}): AuthConfig {
  const stores = createMockStores()
  return {
    session: {
      secret: TEST_SECRET,
      maxAge: "7d",
      cookieName: "auth_session",
      cookie: { secure: false, sameSite: "lax" },
    },
    identityStore: stores.identityStore,
    userStore: stores.userStore,
    challengeStore: createMockChallengeStore(),
    providers: [createMockProvider()],
    ...overrides,
  }
}

describe("Auth", () => {
  let auth: Auth

  afterEach(() => {
    auth?.destroy()
  })

  describe("handleRequest", () => {
    it("should route initiate action to provider", async () => {
      const provider = createMockProvider()
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      const request = new Request(`${TEST_BASE_URL}/auth/email/initiate`, {
        method: "POST",
      })
      const response = await auth.handleRequest(request)

      expect(provider.initiate).toHaveBeenCalledTimes(1)
      expect(response.status).toBe(200)
    })

    it("should route verify action to provider", async () => {
      const provider = createMockProvider()
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      const request = new Request(`${TEST_BASE_URL}/auth/email/verify`)
      const response = await auth.handleRequest(request)

      expect(provider.verify).toHaveBeenCalledTimes(1)
      expect(response.status).toBe(200)
    })

    it("should not serve action names outside the declared route table", async () => {
      const provider = createMockProvider()
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      // "send" and "callback" were pre-v5 aliases; no longer declared routes
      const send = await auth.handleRequest(
        new Request(`${TEST_BASE_URL}/auth/email/send`, { method: "POST" }),
      )
      const callback = await auth.handleRequest(
        new Request(`${TEST_BASE_URL}/auth/email/callback`),
      )

      expect(send.status).toBe(404)
      expect(callback.status).toBe(404)
      expect(provider.initiate).not.toHaveBeenCalled()
      expect(provider.verify).not.toHaveBeenCalled()
    })

    it("should answer 405 when only the method differs from the declared route", async () => {
      const provider = createMockProvider()
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      const response = await auth.handleRequest(
        new Request(`${TEST_BASE_URL}/auth/email/initiate`),
      )

      expect(response.status).toBe(405)
      expect(provider.initiate).not.toHaveBeenCalled()
    })

    it("should return 404 for unknown provider", async () => {
      auth = new Auth(createAuthConfig())

      const request = new Request(`${TEST_BASE_URL}/auth/unknown/initiate`)
      const response = await auth.handleRequest(request)

      expect(response.status).toBe(404)
    })

    it("should return 404 for non-auth paths", async () => {
      auth = new Auth(createAuthConfig())

      const request = new Request(`${TEST_BASE_URL}/other/path`)
      const response = await auth.handleRequest(request)

      expect(response.status).toBe(404)
    })

    it("should return 404 for unknown action when provider has no handleAction", async () => {
      auth = new Auth(createAuthConfig())

      const request = new Request(`${TEST_BASE_URL}/auth/email/unknown`)
      const response = await auth.handleRequest(request)

      expect(response.status).toBe(404)
    })

    it("should dispatch declared action routes to provider handleAction", async () => {
      const actionResponse = new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json" },
      })
      const handleAction = vi.fn().mockResolvedValue(actionResponse)
      const provider = createMockProvider({ id: "passkey", handleAction })
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      const request = new Request(
        `${TEST_BASE_URL}/auth/passkey/register-options`,
        { method: "POST" },
      )
      const response = await auth.handleRequest(request)

      expect(handleAction).toHaveBeenCalledWith(
        "register-options",
        request,
        expect.objectContaining({ challengeStore: expect.anything() }),
      )
      expect(response).toBe(actionResponse)
    })

    it("should prefer built-in actions over handleAction", async () => {
      const handleAction = vi.fn()
      const provider = createMockProvider({ handleAction })
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      await auth.handleRequest(
        new Request(`${TEST_BASE_URL}/auth/email/verify`),
      )
      await auth.handleRequest(
        new Request(`${TEST_BASE_URL}/auth/email/initiate`, { method: "POST" }),
      )

      expect(provider.verify).toHaveBeenCalledTimes(1)
      expect(provider.initiate).toHaveBeenCalledTimes(1)
      expect(handleAction).not.toHaveBeenCalled()
    })

    it("should return 500 when handleAction throws", async () => {
      const provider = createMockProvider({
        handleAction: vi.fn().mockRejectedValue(new Error("boom")),
      })
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      const request = new Request(
        `${TEST_BASE_URL}/auth/email/register-options`,
        {
          method: "POST",
        },
      )
      const response = await auth.handleRequest(request)

      expect(response.status).toBe(500)
    })

    it("should return 500 when provider throws", async () => {
      const provider = createMockProvider({
        initiate: vi.fn().mockRejectedValue(new Error("Provider crashed")),
      })
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      const request = new Request(`${TEST_BASE_URL}/auth/email/initiate`, {
        method: "POST",
      })
      const response = await auth.handleRequest(request)

      expect(response.status).toBe(500)
    })

    it("should append setCookies from initiate result to the response", async () => {
      const provider = createMockProvider({
        initiate: vi.fn().mockResolvedValue({
          success: true,
          message: "Sent",
          setCookies: ["auth_challenge=abc; HttpOnly", "other=1; Path=/"],
        }),
      })
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      const request = new Request(`${TEST_BASE_URL}/auth/email/initiate`, {
        method: "POST",
      })
      const response = await auth.handleRequest(request)

      expect(response.headers.getSetCookie()).toEqual([
        "auth_challenge=abc; HttpOnly",
        "other=1; Path=/",
      ])
    })

    it("should append setCookies from verify result to the response", async () => {
      const provider = createMockProvider({
        verify: vi.fn().mockResolvedValue({
          success: true,
          user: { id: "user-1" },
          identity: createMockIdentity(),
          setCookies: ["auth_challenge=; Max-Age=0"],
        }),
      })
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      const request = new Request(`${TEST_BASE_URL}/auth/email/verify`)
      const response = await auth.handleRequest(request)

      expect(response.headers.getSetCookie()).toEqual([
        "auth_challenge=; Max-Age=0",
      ])
    })

    it("should set no cookies when results omit setCookies", async () => {
      auth = new Auth(createAuthConfig())

      const request = new Request(`${TEST_BASE_URL}/auth/email/initiate`, {
        method: "POST",
      })
      const response = await auth.handleRequest(request)

      expect(response.headers.getSetCookie()).toEqual([])
    })
  })

  describe("createContext", () => {
    it("should pass challengeStore through to the context", () => {
      const challengeStore = createMockChallengeStore()
      auth = new Auth(createAuthConfig({ challengeStore }))

      const context = auth.createContext(new Request(TEST_BASE_URL))
      expect(context.challengeStore).toBe(challengeStore)
    })

    it("should bind getSession to verifySession", async () => {
      auth = new Auth(createAuthConfig())

      const user = { id: "user-1" }
      const identity = createMockIdentity()
      const cookie = await auth.createSessionCookie(user, identity)
      const cookieValue = cookie.split(";")[0]

      const request = new Request(TEST_BASE_URL, {
        headers: { Cookie: cookieValue },
      })
      const context = auth.createContext(request)

      const result = await context.getSession?.(request)
      expect(result?.user.id).toBe("user-1")
      expect(result?.identity.identifier).toBe("user@example.com")
    })

    it("should return null from getSession without a session cookie", async () => {
      auth = new Auth(createAuthConfig())

      const request = new Request(TEST_BASE_URL)
      const context = auth.createContext(request)

      expect(await context.getSession?.(request)).toBeNull()
    })
  })

  describe("verify returning a Response", () => {
    it("should pass a provider Response through unchanged", async () => {
      const confirmPage = new Response("<html>Confirm</html>", {
        headers: { "Content-Type": "text/html" },
      })
      const provider = createMockProvider({
        verify: vi.fn().mockResolvedValue(confirmPage),
      })
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      const request = new Request(`${TEST_BASE_URL}/auth/email/verify?x=1`)
      const response = await auth.handleRequest(request)

      expect(response).toBe(confirmPage)
    })
  })

  describe("verifySession", () => {
    it("should return user and identity for valid session", async () => {
      const config = createAuthConfig()
      auth = new Auth(config)

      const user = { id: "user-1" }
      const identity = createMockIdentity()

      const sessionManager = auth.getSessionManager()
      const cookie = await sessionManager.createSessionCookie(user, identity)
      const cookieValue = cookie.split(";")[0]

      const request = new Request(TEST_BASE_URL, {
        headers: { Cookie: cookieValue },
      })

      const result = await auth.verifySession(request)

      expect(result).not.toBeNull()
      expect(result?.user.id).toBe("user-1")
    })

    it("should return null when no cookie present", async () => {
      auth = new Auth(createAuthConfig())

      const request = new Request(TEST_BASE_URL)
      const result = await auth.verifySession(request)

      expect(result).toBeNull()
    })

    it("should return null when user not found in store", async () => {
      const stores = createMockStores()
      vi.mocked(stores.userStore.findById).mockResolvedValue(null)
      const config = createAuthConfig({
        userStore: stores.userStore,
        identityStore: stores.identityStore,
      })
      auth = new Auth(config)

      const user = { id: "user-1" }
      const identity = createMockIdentity()
      const sessionManager = auth.getSessionManager()
      const cookie = await sessionManager.createSessionCookie(user, identity)
      const cookieValue = cookie.split(";")[0]

      const request = new Request(TEST_BASE_URL, {
        headers: { Cookie: cookieValue },
      })

      const result = await auth.verifySession(request)

      expect(result).toBeNull()
    })

    it("should return null when identity not found", async () => {
      const stores = createMockStores()
      vi.mocked(stores.identityStore.findByUserId).mockResolvedValue([])
      const config = createAuthConfig({
        userStore: stores.userStore,
        identityStore: stores.identityStore,
      })
      auth = new Auth(config)

      const user = { id: "user-1" }
      const identity = createMockIdentity()
      const sessionManager = auth.getSessionManager()
      const cookie = await sessionManager.createSessionCookie(user, identity)
      const cookieValue = cookie.split(";")[0]

      const request = new Request(TEST_BASE_URL, {
        headers: { Cookie: cookieValue },
      })

      const result = await auth.verifySession(request)

      expect(result).toBeNull()
    })
  })

  describe("provider management", () => {
    it("should get provider by id", () => {
      auth = new Auth(createAuthConfig())
      expect(auth.getProvider("email")).toBeDefined()
      expect(auth.getProvider("nonexistent")).toBeUndefined()
    })

    it("should get all providers", () => {
      auth = new Auth(createAuthConfig())
      expect(auth.getProviders()).toHaveLength(1)
    })
  })

  describe("session cookies", () => {
    it("should create and destroy session cookies", async () => {
      auth = new Auth(createAuthConfig())

      const user = { id: "user-1" }
      const identity = createMockIdentity()

      const cookie = await auth.createSessionCookie(user, identity)
      expect(cookie).toContain("auth_session=")
      expect(cookie).toContain("HttpOnly")

      const destroyCookie = auth.destroySessionCookie()
      expect(destroyCookie).toContain("Max-Age=0")
    })
  })

  describe("mergeUsers", () => {
    function createMergeStores(): {
      identityStore: IdentityStore
      userStore: UserStore
    } {
      return {
        identityStore: {
          findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
          findByUserId: vi
            .fn()
            .mockResolvedValue([
              createMockIdentity({ id: "identity-b", userId: "user-b" }),
            ]),
          create: vi.fn(),
          update: vi.fn(),
          reassignByUserId: vi.fn().mockResolvedValue(undefined),
        },
        userStore: {
          findById: vi
            .fn()
            .mockImplementation(async (id: string) =>
              id === "user-a" || id === "user-b" ? { id } : null,
            ),
          create: vi.fn(),
          onMerge: vi.fn().mockResolvedValue(undefined),
        },
      }
    }

    it("should reassign identities, call onMerge, and report what moved", async () => {
      const stores = createMergeStores()
      auth = new Auth(createAuthConfig(stores))

      const result = await auth.mergeUsers("user-b", "user-a")

      expect(stores.identityStore.reassignByUserId).toHaveBeenCalledWith(
        "user-b",
        "user-a",
      )
      expect(stores.userStore.onMerge).toHaveBeenCalledWith(
        { id: "user-b" },
        { id: "user-a" },
      )
      expect(result.fromUserId).toBe("user-b")
      expect(result.intoUserId).toBe("user-a")
      expect(result.movedIdentities).toHaveLength(1)
      expect(result.movedIdentities[0]?.id).toBe("identity-b")
    })

    it("should reject merging a user into itself", async () => {
      auth = new Auth(createAuthConfig(createMergeStores()))

      await expect(auth.mergeUsers("user-a", "user-a")).rejects.toMatchObject({
        code: "IDENTITY_CONFLICT",
      })
    })

    it("should reject when either user is missing", async () => {
      auth = new Auth(createAuthConfig(createMergeStores()))

      await expect(
        auth.mergeUsers("user-missing", "user-a"),
      ).rejects.toMatchObject({ code: "USER_NOT_FOUND" })
    })
  })

  describe("link-merge action", () => {
    const TICKET_ID = "ticket-1"

    /**
     * An Auth whose stores hold user-a (signed in, email identity) and
     * user-b (owner of the conflicting identifier), with a redeemable merge
     * ticket in a real challenge store.
     */
    async function createMergeScenario(overrides?: {
      ticketProvider?: string
    }): Promise<{
      auth: Auth
      identityStore: IdentityStore
      userStore: UserStore
      sessionCookieValue: string
    }> {
      const sessionIdentity = createMockIdentity({ userId: "user-a" })
      // The identifier the ticket was minted for still belongs to user-b —
      // redemption re-checks this before merging
      const conflictingIdentity = createMockIdentity({
        id: "identity-b",
        userId: "user-b",
        identifier: "+14155550100",
      })
      const identityStore: IdentityStore = {
        findByProviderAndIdentifier: vi
          .fn()
          .mockResolvedValue(conflictingIdentity),
        findByUserId: vi.fn().mockResolvedValue([sessionIdentity]),
        create: vi.fn(),
        update: vi.fn(),
        reassignByUserId: vi.fn().mockResolvedValue(undefined),
      }
      const userStore: UserStore = {
        findById: vi
          .fn()
          .mockImplementation(async (id: string) =>
            id === "user-a" || id === "user-b" ? { id } : null,
          ),
        create: vi.fn(),
        onMerge: vi.fn().mockResolvedValue(undefined),
      }
      const challengeStore = new InMemoryChallengeStore()
      await challengeStore.create({
        id: TICKET_ID,
        type: "account-merge",
        identifier: "+14155550100",
        data: {
          fromUserId: "user-b",
          intoUserId: "user-a",
          provider: overrides?.ticketProvider ?? "email",
        },
        maxAttempts: 1,
        expiresAt: new Date(Date.now() + 60_000),
      })

      const mergeAuth = new Auth(
        createAuthConfig({ identityStore, userStore, challengeStore }),
      )
      const cookie = await mergeAuth.createSessionCookie(
        { id: "user-a" },
        sessionIdentity,
      )
      const sessionCookieValue = cookie.split(";")[0] ?? ""

      return { auth: mergeAuth, identityStore, userStore, sessionCookieValue }
    }

    function mergeRequest(cookies: string[]): Request {
      return new Request(`${TEST_BASE_URL}/auth/email/link-merge`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: cookies.join("; "),
        },
        body: "{}",
      })
    }

    it("should merge and answer JSON for fetch callers", async () => {
      const scenario = await createMergeScenario()
      auth = scenario.auth

      const response = await auth.handleRequest(
        mergeRequest([
          `auth_merge_ticket=${TICKET_ID}`,
          scenario.sessionCookieValue,
        ]),
      )

      expect(response.status).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      expect(body.merged).toEqual({
        fromUserId: "user-b",
        intoUserId: "user-a",
        movedIdentityCount: 1,
      })
      expect(scenario.identityStore.reassignByUserId).toHaveBeenCalledWith(
        "user-b",
        "user-a",
      )
      const cleared = response.headers
        .getSetCookie()
        .find((value) => value.startsWith("auth_merge_ticket="))
      expect(cleared).toContain("Max-Age=0")
    })

    it("should redirect browser form posts back with ?merged=1", async () => {
      const scenario = await createMergeScenario()
      auth = scenario.auth

      const request = new Request(`${TEST_BASE_URL}/auth/email/link-merge`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "text/html",
          Referer: `${TEST_BASE_URL}/dashboard`,
          Cookie: [
            `auth_merge_ticket=${TICKET_ID}`,
            scenario.sessionCookieValue,
          ].join("; "),
        },
        body: "",
      })
      const response = await auth.handleRequest(request)

      expect(response.status).toBe(302)
      const location = new URL(response.headers.get("Location") ?? "")
      expect(location.pathname).toBe("/dashboard")
      expect(location.searchParams.get("merged")).toBe("1")
    })

    it("should reject without a ticket cookie", async () => {
      const scenario = await createMergeScenario()
      auth = scenario.auth

      const response = await auth.handleRequest(
        mergeRequest([scenario.sessionCookieValue]),
      )

      expect(response.status).toBe(401)
      expect(scenario.identityStore.reassignByUserId).not.toHaveBeenCalled()
    })

    it("should reject without a session for the surviving user", async () => {
      const scenario = await createMergeScenario()
      auth = scenario.auth

      const response = await auth.handleRequest(
        mergeRequest([`auth_merge_ticket=${TICKET_ID}`]),
      )

      expect(response.status).toBe(401)
      const body = await response.json()
      expect(body.error.code).toBe("SESSION_INVALID")
      expect(scenario.identityStore.reassignByUserId).not.toHaveBeenCalled()
    })

    it("should be single-use", async () => {
      const scenario = await createMergeScenario()
      auth = scenario.auth
      const cookies = [
        `auth_merge_ticket=${TICKET_ID}`,
        scenario.sessionCookieValue,
      ]

      const first = await auth.handleRequest(mergeRequest(cookies))
      expect(first.status).toBe(200)

      const second = await auth.handleRequest(mergeRequest(cookies))
      expect(second.status).toBe(401)
      expect(scenario.identityStore.reassignByUserId).toHaveBeenCalledTimes(1)
    })

    it("should reject a ticket minted by a different provider", async () => {
      const scenario = await createMergeScenario({ ticketProvider: "sms" })
      auth = scenario.auth

      const response = await auth.handleRequest(
        mergeRequest([
          `auth_merge_ticket=${TICKET_ID}`,
          scenario.sessionCookieValue,
        ]),
      )

      expect(response.status).toBe(401)
      expect(scenario.identityStore.reassignByUserId).not.toHaveBeenCalled()
    })

    it("should reject when the identifier no longer belongs to the absorbed user", async () => {
      const scenario = await createMergeScenario()
      auth = scenario.auth
      // Ownership changed within the ticket's window (another merge, an
      // unlink); redeeming the stale ticket must not merge anyone
      vi.mocked(
        scenario.identityStore.findByProviderAndIdentifier,
      ).mockResolvedValue(
        createMockIdentity({ userId: "user-c", identifier: "+14155550100" }),
      )

      const response = await auth.handleRequest(
        mergeRequest([
          `auth_merge_ticket=${TICKET_ID}`,
          scenario.sessionCookieValue,
        ]),
      )

      expect(response.status).toBe(401)
      expect(scenario.identityStore.reassignByUserId).not.toHaveBeenCalled()
    })
  })
})

describe("SessionManager", () => {
  const sessionConfig = {
    secret: TEST_SECRET,
    maxAge: "7d",
    cookieName: "auth_session",
    cookie: { secure: true, sameSite: "lax" as const },
  }

  it("should create and verify a session token", async () => {
    const manager = new SessionManager(sessionConfig)
    const user = { id: "user-1" }
    const identity = createMockIdentity()

    const token = await manager.createSession(user, identity)
    const session = await manager.verifyToken(token)

    expect(session).not.toBeNull()
    expect(session?.userId).toBe("user-1")
    expect(session?.provider).toBe("email")
    expect(session?.identifier).toBe("user@example.com")
  })

  it("should reject token signed with wrong secret", async () => {
    const manager = new SessionManager(sessionConfig)
    const badToken = await signTestToken({ userId: "user-1" }, "wrong-secret")

    expect(await manager.verifyToken(badToken)).toBeNull()
  })

  it("should accept token signed with additional secret", async () => {
    const manager = new SessionManager({
      ...sessionConfig,
      additionalSecrets: ["e2e-secret"],
    })

    const token = await signTestToken(
      { userId: "user-1", identifier: "user@example.com", provider: "email" },
      "e2e-secret",
    )

    const session = await manager.verifyToken(token)
    expect(session).not.toBeNull()
    expect(session?.userId).toBe("user-1")
  })

  it("should create session cookie with correct attributes", async () => {
    const manager = new SessionManager(sessionConfig)
    const user = { id: "user-1" }
    const identity = createMockIdentity()

    const cookie = await manager.createSessionCookie(user, identity)

    expect(cookie).toContain("auth_session=")
    expect(cookie).toContain("HttpOnly")
    expect(cookie).toContain("Secure")
    expect(cookie).toContain("SameSite=Lax")
    expect(cookie).toContain("Path=/")
  })

  it("should create destroy cookie with Max-Age=0", () => {
    const manager = new SessionManager(sessionConfig)
    const cookie = manager.destroySessionCookie()

    expect(cookie).toContain("Max-Age=0")
    expect(cookie).toContain("auth_session=")
  })

  it("should get session from request cookie", async () => {
    const manager = new SessionManager(sessionConfig)
    const user = { id: "user-1" }
    const identity = createMockIdentity()

    const cookie = await manager.createSessionCookie(user, identity)
    const cookieValue = cookie.split(";")[0]

    const request = new Request(TEST_BASE_URL, {
      headers: { Cookie: cookieValue },
    })

    const session = await manager.getSession(request)
    expect(session).not.toBeNull()
    expect(session?.userId).toBe("user-1")
  })

  it("should return null when no cookie in request", async () => {
    const manager = new SessionManager(sessionConfig)
    const request = new Request(TEST_BASE_URL)

    const session = await manager.getSession(request)
    expect(session).toBeNull()
  })

  it("should return cookie name", () => {
    const manager = new SessionManager(sessionConfig)
    expect(manager.getCookieName()).toBe("auth_session")
  })
})

describe("Auth abuse protection", () => {
  let auth: Auth

  afterEach(() => {
    auth?.destroy()
    vi.restoreAllMocks()
  })

  /** A form post from one IP, the shape a login form submits */
  function initiateRequest(
    body: Record<string, string>,
    ip = "203.0.113.7",
  ): Request {
    return new Request(`${TEST_BASE_URL}/auth/email/initiate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "x-forwarded-for": ip,
      },
      body: new URLSearchParams(body).toString(),
    })
  }

  it("blocks per-IP bursts and answers exactly like a successful send", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {})
    const provider = createMockProvider({
      initiateSentMessage: "Magic link sent. Please check your email.",
      initiate: vi.fn().mockResolvedValue({
        success: true,
        message: "Magic link sent. Please check your email.",
      }),
    })
    auth = new Auth(
      createAuthConfig({
        providers: [provider],
        abuse: { perIp: [{ windowSeconds: 60, max: 1 }] },
      }),
    )

    const allowed = await auth.handleRequest(
      initiateRequest({ email: "user@example.com" }),
    )
    const blocked = await auth.handleRequest(
      initiateRequest({ email: "user@example.com" }),
    )

    expect(provider.initiate).toHaveBeenCalledTimes(1)
    expect(blocked.status).toBe(allowed.status)
    expect(await blocked.text()).toBe(await allowed.text())
    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining("reason=ip_rate_limited"),
    )
  })

  it("logs the blocked ip and calls onBlocked", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {})
    const onBlocked = vi.fn()
    auth = new Auth(
      createAuthConfig({
        abuse: { perIp: [{ windowSeconds: 60, max: 1 }], onBlocked },
      }),
    )

    await auth.handleRequest(initiateRequest({ email: "user@example.com" }))
    await auth.handleRequest(initiateRequest({ email: "user@example.com" }))

    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining("ip=203.0.113.7"),
    )
    expect(onBlocked).toHaveBeenCalledWith(
      expect.objectContaining({
        reason: "ip_rate_limited",
        providerId: "email",
      }),
    )
  })

  it("counts each IP separately", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {})
    const provider = createMockProvider()
    auth = new Auth(
      createAuthConfig({
        providers: [provider],
        abuse: { perIp: [{ windowSeconds: 60, max: 1 }] },
      }),
    )

    await auth.handleRequest(initiateRequest({ email: "a@example.com" }))
    await auth.handleRequest(
      initiateRequest({ email: "b@example.com" }, "198.51.100.4"),
    )

    expect(provider.initiate).toHaveBeenCalledTimes(2)
  })

  it("blocks a submission faster than a human could fill the form", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {})
    const provider = createMockProvider()
    auth = new Auth(createAuthConfig({ providers: [provider] }))
    const formToken = await createFormToken(TEST_SECRET)

    const response = await auth.handleRequest(
      initiateRequest({
        email: "user@example.com",
        authFormToken: formToken,
      }),
    )

    expect(provider.initiate).not.toHaveBeenCalled()
    expect(response.status).toBe(200)
    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining("detail=form-token:too_fast"),
    )
  })

  it("returns 429 with Retry-After when respondWith is rateLimited", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {})
    auth = new Auth(
      createAuthConfig({
        abuse: {
          perIp: [{ windowSeconds: 60, max: 1 }],
          respondWith: "rateLimited",
        },
      }),
    )

    await auth.handleRequest(initiateRequest({ email: "user@example.com" }))
    const blocked = await auth.handleRequest(
      initiateRequest({ email: "user@example.com" }),
    )

    expect(blocked.status).toBe(429)
    expect(blocked.headers.get("Retry-After")).toBeTruthy()
  })

  it("does nothing when disabled", async () => {
    const provider = createMockProvider()
    auth = new Auth(
      createAuthConfig({
        providers: [provider],
        abuse: { enabled: false, perIp: [{ windowSeconds: 60, max: 1 }] },
      }),
    )

    await auth.handleRequest(initiateRequest({ email: "user@example.com" }))
    await auth.handleRequest(initiateRequest({ email: "user@example.com" }))

    expect(provider.initiate).toHaveBeenCalledTimes(2)
  })

  it("leaves the request body readable by the provider", async () => {
    let seen: string | null = null
    const provider = createMockProvider({
      initiate: vi.fn(async (request: Request) => {
        seen = await request.text()
        return { success: true, message: "Sent" }
      }),
    })
    auth = new Auth(createAuthConfig({ providers: [provider] }))

    await auth.handleRequest(initiateRequest({ email: "user@example.com" }))

    expect(seen).toBe("email=user%40example.com")
  })

  it("exposes per-identifier checks to providers", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {})
    auth = new Auth(
      createAuthConfig({
        abuse: { perIdentifier: [{ windowSeconds: 3600, max: 1 }] },
      }),
    )
    const context = auth.createContext(
      initiateRequest({ email: "user@example.com" }),
    )

    const first = await context.abuse?.checkIdentifier(
      "email",
      "User@Example.com",
    )
    const second = await context.abuse?.checkIdentifier(
      "email",
      "user@example.com",
    )

    expect(first?.allowed).toBe(true)
    expect(second?.allowed).toBe(false)
    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining("identifier=user@example.com"),
    )
  })
})

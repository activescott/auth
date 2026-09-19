import { describe, it, expect, vi, afterEach } from "vitest"
import { createAuthHandlers, type AuthHandlers } from "../handlers.js"
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import type {
  AuthLogger,
  AuthProvider,
  AuthUser,
  Identity,
} from "@activescott/auth"

const TEST_BASE_URL = "https://example.com"

function createMockIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: "identity-1",
    userId: "user-1",
    provider: "email",
    identifier: "user@example.com",
    createdAt: new Date(),
    ...overrides,
  }
}

function createMockAuth(overrides: Partial<Auth> = {}): Auth {
  return {
    handleRequest: vi.fn().mockResolvedValue(new Response("OK")),
    verifySession: vi.fn().mockResolvedValue(null),
    createSessionCookie: vi
      .fn()
      .mockResolvedValue("auth_session=token; Path=/; HttpOnly"),
    destroySessionCookie: vi
      .fn()
      .mockReturnValue("auth_session=; Max-Age=0; Path=/; HttpOnly"),
    getProvider: vi.fn().mockReturnValue(null),
    getProviders: vi.fn().mockReturnValue([]),
    findProvider: vi.fn().mockReturnValue(null),
    createContext: vi.fn().mockReturnValue({
      identityStore: {},
      userStore: {},
      baseUrl: TEST_BASE_URL,
      createSession: vi.fn(),
    }),
    getSessionManager: vi.fn(),
    getSessionConfig: vi.fn(),
    destroy: vi.fn(),
    ...overrides,
  } as unknown as Auth
}

describe("createAuthHandlers", () => {
  describe("requireAuth", () => {
    it("should return user when session exists", async () => {
      const mockAuth = createMockAuth({
        verifySession: vi.fn().mockResolvedValue({
          user: { id: "user-1" },
          identity: createMockIdentity(),
        }),
      })
      const handlers = createAuthHandlers(mockAuth)

      const request = new Request(`${TEST_BASE_URL}/dashboard`)
      const user = await handlers.requireAuth(request)

      expect(user.id).toBe("user-1")
    })

    it("should throw redirect when not authenticated", async () => {
      const mockAuth = createMockAuth()
      const handlers = createAuthHandlers(mockAuth)

      const request = new Request(`${TEST_BASE_URL}/dashboard`)

      try {
        await handlers.requireAuth(request)
        expect.fail("Should have thrown")
      } catch (error) {
        const response = error as Response
        expect(response.status).toBe(302)
        const location = response.headers.get("Location")
        expect(location).toContain("/login")
        expect(location).toContain("redirectTo=")
      }
    })

    it("should use custom redirectTo when provided", async () => {
      const mockAuth = createMockAuth()
      const handlers = createAuthHandlers(mockAuth)

      const request = new Request(`${TEST_BASE_URL}/dashboard`)

      try {
        await handlers.requireAuth(request, "/custom-login")
        expect.fail("Should have thrown")
      } catch (error) {
        const response = error as Response
        expect(response.headers.get("Location")).toContain("/custom-login")
      }
    })
  })

  describe("optionalAuth", () => {
    it("should return user when session exists", async () => {
      const mockAuth = createMockAuth({
        verifySession: vi.fn().mockResolvedValue({
          user: { id: "user-1" },
          identity: createMockIdentity(),
        }),
      })
      const handlers = createAuthHandlers(mockAuth)

      const request = new Request(TEST_BASE_URL)
      const user = await handlers.optionalAuth(request)

      expect(user).not.toBeNull()
      expect(user?.id).toBe("user-1")
    })

    it("should return null when not authenticated", async () => {
      const mockAuth = createMockAuth()
      const handlers = createAuthHandlers(mockAuth)

      const request = new Request(TEST_BASE_URL)
      const user = await handlers.optionalAuth(request)

      expect(user).toBeNull()
    })
  })

  describe("getSession", () => {
    it("should return session with user and identity", async () => {
      const identity = createMockIdentity()
      const mockAuth = createMockAuth({
        verifySession: vi.fn().mockResolvedValue({
          user: { id: "user-1" },
          identity,
        }),
      })
      const handlers = createAuthHandlers(mockAuth)

      const request = new Request(TEST_BASE_URL)
      const session = await handlers.getSession(request)

      expect(session).not.toBeNull()
      expect(session?.user.id).toBe("user-1")
      expect(session?.identity.identifier).toBe("user@example.com")
    })

    it("should return null when no session", async () => {
      const mockAuth = createMockAuth()
      const handlers = createAuthHandlers(mockAuth)

      const request = new Request(TEST_BASE_URL)
      const session = await handlers.getSession(request)

      expect(session).toBeNull()
    })

    it("should apply mapUser when configured", async () => {
      const mockAuth = createMockAuth({
        verifySession: vi.fn().mockResolvedValue({
          user: { id: "user-1" },
          identity: createMockIdentity(),
        }),
      })

      interface AppUser {
        id: string
        email: string
      }

      const handlers = createAuthHandlers<AppUser>(mockAuth, {
        mapUser: (user: AuthUser, identity: Identity) => ({
          id: user.id,
          email: identity.identifier,
        }),
      })

      const request = new Request(TEST_BASE_URL)
      const session = await handlers.getSession(request)

      expect(session?.user.email).toBe("user@example.com")
    })
  })

  describe("onSessionVerified", () => {
    /** Auth with a live session, and the three ways an app reads one */
    function signedInAuth(): Auth {
      return createMockAuth({
        verifySession: vi.fn().mockResolvedValue({
          user: { id: "user-1" },
          identity: createMockIdentity(),
        }),
      })
    }

    const entryPoints = [
      [
        "requireAuth",
        (handlers: AuthHandlers, request: Request) =>
          handlers.requireAuth(request),
      ],
      [
        "optionalAuth",
        (handlers: AuthHandlers, request: Request) =>
          handlers.optionalAuth(request),
      ],
      [
        "getSession",
        (handlers: AuthHandlers, request: Request) =>
          handlers.getSession(request),
      ],
    ] as const

    it.each(entryPoints)("should run in %s", async (_name, call) => {
      const onSessionVerified = vi.fn()
      const handlers = createAuthHandlers(signedInAuth(), {
        onSessionVerified,
      })
      const request = new Request(`${TEST_BASE_URL}/dashboard`)

      await call(handlers, request)

      expect(onSessionVerified).toHaveBeenCalledTimes(1)
      expect(onSessionVerified).toHaveBeenCalledWith(
        { user: { id: "user-1" }, identity: expect.anything() },
        request,
      )
    })

    it.each(entryPoints)(
      "should bounce %s with a Response the hook throws",
      async (_name, call) => {
        const handlers = createAuthHandlers(signedInAuth(), {
          onSessionVerified: () => {
            throw new Response(null, {
              status: 302,
              headers: { Location: "/waitlist" },
            })
          },
        })

        try {
          await call(handlers, new Request(`${TEST_BASE_URL}/dashboard`))
          expect.fail("Should have thrown")
        } catch (error) {
          const response = error as Response
          expect(response.status).toBe(302)
          expect(response.headers.get("Location")).toBe("/waitlist")
        }
      },
    )

    it.each(entryPoints)(
      "should bounce %s with a Response the hook returns",
      async (_name, call) => {
        const handlers = createAuthHandlers(signedInAuth(), {
          onSessionVerified: () => new Response("Blocked", { status: 403 }),
        })

        try {
          await call(handlers, new Request(`${TEST_BASE_URL}/dashboard`))
          expect.fail("Should have thrown")
        } catch (error) {
          expect((error as Response).status).toBe(403)
        }
      },
    )

    it("should not run when there is no session", async () => {
      const onSessionVerified = vi.fn()
      const handlers = createAuthHandlers(createMockAuth(), {
        onSessionVerified,
      })

      expect(await handlers.optionalAuth(new Request(TEST_BASE_URL))).toBeNull()
      expect(onSessionVerified).not.toHaveBeenCalled()
    })

    it("should see the user mapUser produced", async () => {
      const onSessionVerified =
        vi.fn<(session: { user: { email: string } }) => void>()
      const handlers = createAuthHandlers<{ id: string; email: string }>(
        signedInAuth(),
        {
          mapUser: (user, identity) => ({
            id: user.id,
            email: identity.identifier,
          }),
          onSessionVerified,
        },
      )

      await handlers.requireAuth(new Request(`${TEST_BASE_URL}/dashboard`))

      expect(onSessionVerified.mock.calls[0]?.[0].user.email).toBe(
        "user@example.com",
      )
    })

    it("should let the session through when the hook returns nothing", async () => {
      const handlers = createAuthHandlers(signedInAuth(), {
        onSessionVerified: async () => {
          await Promise.resolve()
        },
      })

      const user = await handlers.requireAuth(
        new Request(`${TEST_BASE_URL}/dashboard`),
      )

      expect(user.id).toBe("user-1")
    })
  })

  describe("clearSessionCookie", () => {
    it("should return the header that expires the session cookie", () => {
      const mockAuth = createMockAuth()
      const handlers = createAuthHandlers(mockAuth)

      expect(handlers.clearSessionCookie()).toBe(
        "auth_session=; Max-Age=0; Path=/; HttpOnly",
      )
      expect(mockAuth.destroySessionCookie).toHaveBeenCalledTimes(1)
    })
  })

  describe("handleAuth", () => {
    const trackedAuths: Auth[] = []

    afterEach(() => {
      for (const tracked of trackedAuths.splice(0)) tracked.destroy()
    })

    /**
     * handleAuth is a thin wrapper over Auth.handleRequest responders, so
     * these tests run a REAL Auth over a mock provider rather than mocking
     * the dispatch they exist to verify.
     */
    function createTestProvider(
      overrides: Partial<AuthProvider> = {},
    ): AuthProvider {
      return {
        id: "email",
        name: "Email",
        initiate: vi.fn().mockResolvedValue({ success: true, message: "Sent" }),
        verify: vi.fn().mockResolvedValue({
          success: true,
          user: { id: "user-1" },
          identity: createMockIdentity(),
        }),
        getRoutes: () => [
          { method: "POST", path: "/email/initiate", handler: "initiate" },
          { method: "GET", path: "/email/verify", handler: "verify" },
          { method: "POST", path: "/email/verify", handler: "verify" },
          { method: "POST", path: "/email/register-verify", handler: "action" },
        ],
        describe: () => ({ settings: {} }),
        ...overrides,
      }
    }

    function createRealAuth(provider: AuthProvider, logger?: AuthLogger): Auth {
      const realAuth = new Auth({
        logger,
        session: {
          secret: "test-secret",
          maxAge: "7d",
          cookieName: "auth_session",
          cookie: { secure: false, sameSite: "lax" },
        },
        identityStore: {
          findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
          findByUserId: vi.fn().mockResolvedValue([]),
          create: vi.fn(),
          update: vi.fn(),
          delete: vi.fn(),
          reassignByUserId: vi.fn(),
        },
        userStore: {
          findById: vi.fn().mockResolvedValue(null),
          create: vi.fn(),
          onMerge: vi.fn(),
        },
        challengeStore: new InMemoryChallengeStore(),
        providers: [provider],
      })
      trackedAuths.push(realAuth)
      return realAuth
    }

    it("should route initiate requests to the provider untouched", async () => {
      const provider = createTestProvider()
      const handlers = createAuthHandlers(createRealAuth(provider))

      const request = new Request(`${TEST_BASE_URL}/auth/email/initiate`, {
        method: "POST",
      })
      const response = await handlers.handleAuth({ request })

      expect(provider.initiate).toHaveBeenCalledTimes(1)
      expect(response.status).toBe(200)
    })

    it("should route action routes to handleAction, not verify", async () => {
      const actionResponse = new Response("{}", {
        headers: { "Content-Type": "application/json" },
      })
      const handleAction = vi.fn().mockResolvedValue(actionResponse)
      const provider = createTestProvider({ handleAction })
      const handlers = createAuthHandlers(createRealAuth(provider))

      // register-verify contains "verify" but is declared handler: "action"
      const request = new Request(
        `${TEST_BASE_URL}/auth/email/register-verify`,
        { method: "POST" },
      )
      const response = await handlers.handleAuth({ request })

      expect(handleAction).toHaveBeenCalledTimes(1)
      expect(provider.verify).not.toHaveBeenCalled()
      expect(response).toBe(actionResponse)
    })

    it("should handle verify requests with session cookie and redirect", async () => {
      const provider = createTestProvider()
      const handlers = createAuthHandlers(createRealAuth(provider), {
        successRedirect: "/dashboard",
      })

      const request = new Request(
        `${TEST_BASE_URL}/auth/email/verify?token=abc`,
      )
      const response = await handlers.handleAuth({ request })

      expect(provider.verify).toHaveBeenCalledTimes(1)
      expect(response.status).toBe(302)
      expect(response.headers.get("Location")).toBe("/dashboard")
      expect(response.headers.get("Set-Cookie")).toContain("auth_session=")
    })

    it("should redirect to error page on verify failure", async () => {
      const provider = createTestProvider({
        verify: vi.fn().mockResolvedValue({
          success: false,
          error: { code: "INVALID_TOKEN", message: "Bad token" },
        }),
      })
      const handlers = createAuthHandlers(createRealAuth(provider))

      const request = new Request(
        `${TEST_BASE_URL}/auth/email/verify?token=bad`,
      )
      const response = await handlers.handleAuth({ request })

      expect(response.status).toBe(302)
      expect(response.headers.get("Location")).toContain("/login?error=")
    })

    it("should carry failure setCookies on the error redirect", async () => {
      const provider = createTestProvider({
        verify: vi.fn().mockResolvedValue({
          success: false,
          error: { code: "IDENTITY_CONFLICT", message: "Conflict" },
          setCookies: ["auth_merge_ticket=ticket-1; Path=/auth; HttpOnly"],
        }),
      })
      const handlers = createAuthHandlers(createRealAuth(provider))

      const request = new Request(`${TEST_BASE_URL}/auth/email/verify`, {
        method: "POST",
      })
      const response = await handlers.handleAuth({ request })

      expect(response.status).toBe(302)
      expect(response.headers.get("Location")).toContain(
        "error=IDENTITY_CONFLICT",
      )
      expect(response.headers.getSetCookie()).toEqual([
        "auth_merge_ticket=ticket-1; Path=/auth; HttpOnly",
      ])
    })

    it("should append provider setCookies alongside the session cookie", async () => {
      const provider = createTestProvider({
        verify: vi.fn().mockResolvedValue({
          success: true,
          user: { id: "user-1" },
          identity: createMockIdentity(),
          setCookies: ["auth_challenge=; Path=/auth; Max-Age=0"],
        }),
      })
      const handlers = createAuthHandlers(createRealAuth(provider), {
        successRedirect: "/dashboard",
      })

      const request = new Request(`${TEST_BASE_URL}/auth/email/verify`, {
        method: "POST",
      })
      const response = await handlers.handleAuth({ request })

      expect(response.status).toBe(302)
      const cookies = response.headers.getSetCookie()
      expect(cookies[0]).toContain("auth_session=")
      expect(cookies[1]).toBe("auth_challenge=; Path=/auth; Max-Age=0")
    })

    it("should pass through a Response from verify (e.g., the confirm page)", async () => {
      const confirmPage = new Response("<html>Confirm sign-in</html>", {
        headers: { "Content-Type": "text/html" },
      })
      const provider = createTestProvider({
        verify: vi.fn().mockResolvedValue(confirmPage),
      })
      const handlers = createAuthHandlers(createRealAuth(provider))

      const request = new Request(
        `${TEST_BASE_URL}/auth/email/verify?challenge=abc&key=def`,
      )
      const response = await handlers.handleAuth({ request })

      expect(response).toBe(confirmPage)
    })

    it("should use redirectTo query param after successful verify", async () => {
      const provider = createTestProvider()
      const handlers = createAuthHandlers(createRealAuth(provider))

      const request = new Request(
        `${TEST_BASE_URL}/auth/email/verify?token=abc&redirectTo=/settings`,
      )
      const response = await handlers.handleAuth({ request })

      expect(response.status).toBe(302)
      expect(response.headers.get("Location")).toBe("/settings")
    })

    it("should reduce an absolute same-origin redirectTo to a path", async () => {
      const provider = createTestProvider()
      const handlers = createAuthHandlers(createRealAuth(provider))

      const request = new Request(
        `${TEST_BASE_URL}/auth/email/verify?redirectTo=${encodeURIComponent(
          `${TEST_BASE_URL}/settings?tab=email`,
        )}`,
      )
      const response = await handlers.handleAuth({ request })

      expect(response.headers.get("Location")).toBe("/settings?tab=email")
    })

    it.each([
      ["another origin", "https://other.example/x"],
      ["protocol-relative", "//other.example"],
      ["backslash-prefixed", "/\\other.example"],
      ["javascript:", "javascript:alert(1)"],
    ])(
      "should use successRedirect when redirectTo names %s",
      async (_label, redirectTo) => {
        const provider = createTestProvider()
        const handlers = createAuthHandlers(createRealAuth(provider), {
          successRedirect: "/dashboard",
        })

        const request = new Request(
          `${TEST_BASE_URL}/auth/email/verify?redirectTo=${encodeURIComponent(redirectTo)}`,
        )
        const response = await handlers.handleAuth({ request })

        expect(response.status).toBe(302)
        expect(response.headers.get("Location")).toBe("/dashboard")
      },
    )

    it("should report a declined redirectTo to the configured logger", async () => {
      const warn = vi.fn()
      const provider = createTestProvider()
      const handlers = createAuthHandlers(createRealAuth(provider, { warn }), {
        successRedirect: "/dashboard",
      })

      const request = new Request(
        `${TEST_BASE_URL}/auth/email/verify?redirectTo=${encodeURIComponent(
          "https://other.example/x",
        )}`,
      )
      await handlers.handleAuth({ request })

      expect(warn).toHaveBeenCalledTimes(1)
      expect(warn.mock.calls[0]?.[1]).toMatchObject({
        source: "redirectTo",
        reason: "other-origin",
        origin: "https://other.example",
      })
    })

    it("should not log a redirectTo it honors", async () => {
      const warn = vi.fn()
      const provider = createTestProvider()
      const handlers = createAuthHandlers(createRealAuth(provider, { warn }))

      const request = new Request(
        `${TEST_BASE_URL}/auth/email/verify?redirectTo=/settings`,
      )
      await handlers.handleAuth({ request })

      expect(warn).not.toHaveBeenCalled()
    })
  })

  describe("logout", () => {
    it("should return redirect with destroy cookie", () => {
      const mockAuth = createMockAuth()
      const handlers = createAuthHandlers(mockAuth)

      const response = handlers.logout("/goodbye")

      expect(response.status).toBe(302)
      expect(response.headers.get("Location")).toBe("/goodbye")
      expect(response.headers.get("Set-Cookie")).toContain("Max-Age=0")
    })

    it("should default redirect to /", () => {
      const mockAuth = createMockAuth()
      const handlers = createAuthHandlers(mockAuth)

      const response = handlers.logout()

      expect(response.headers.get("Location")).toBe("/")
    })
  })

  describe("refreshSessionCookie", () => {
    it("should create new cookie with updated user", async () => {
      const mockAuth = createMockAuth({
        verifySession: vi.fn().mockResolvedValue({
          user: { id: "user-1" },
          identity: createMockIdentity(),
        }),
      })
      const handlers = createAuthHandlers(mockAuth)

      const request = new Request(TEST_BASE_URL, {
        headers: { Cookie: "auth_session=token" },
      })
      const cookie = await handlers.refreshSessionCookie(request, {
        id: "user-1",
        metadata: { handle: "new-handle" },
      })

      expect(cookie).toContain("auth_session=")
      expect(mockAuth.createSessionCookie).toHaveBeenCalled()
    })

    it("should throw when no active session", async () => {
      const mockAuth = createMockAuth()
      const handlers = createAuthHandlers(mockAuth)

      const request = new Request(TEST_BASE_URL)

      await expect(
        handlers.refreshSessionCookie(request, { id: "user-1" }),
      ).rejects.toThrow("no active session")
    })
  })

  describe("renewSessionCookie", () => {
    const SECONDS_PER_DAY = 86400
    const identity = createMockIdentity()

    // A session issued `ageDays` ago that still resolves to a user.
    function createAgingAuth(ageDays: number): Auth {
      const issuedAt =
        Math.floor(Date.now() / 1000) - Math.round(ageDays * SECONDS_PER_DAY)
      return createMockAuth({
        getSessionManager: vi.fn().mockReturnValue({
          getSession: vi.fn().mockResolvedValue({
            userId: "user-1",
            identifier: "user@example.com",
            provider: "email",
            issuedAt,
            expiresAt: issuedAt + 30 * SECONDS_PER_DAY,
          }),
        }),
        verifySession: vi.fn().mockResolvedValue({
          user: { id: "user-1" },
          identity,
        }),
      })
    }

    function createHandlers(auth: Auth, renewAfter = "7d") {
      return createAuthHandlers(auth, { session: { renewAfter } })
    }

    const request = new Request(TEST_BASE_URL, {
      headers: { Cookie: "auth_session=token" },
    })

    it("should return a cookie once the session is older than renewAfter", async () => {
      const mockAuth = createAgingAuth(10)
      const handlers = createHandlers(mockAuth)

      const cookie = await handlers.renewSessionCookie(request, {
        id: "user-1",
      })

      expect(cookie).toContain("auth_session=")
      expect(mockAuth.createSessionCookie).toHaveBeenCalledWith(
        { id: "user-1" },
        identity,
      )
    })

    it("should return null while the session is still fresh", async () => {
      const mockAuth = createAgingAuth(2)
      const handlers = createHandlers(mockAuth)

      const cookie = await handlers.renewSessionCookie(request, {
        id: "user-1",
      })

      expect(cookie).toBeNull()
      expect(mockAuth.createSessionCookie).not.toHaveBeenCalled()
    })

    it("should not verify the session when it is still fresh", async () => {
      const mockAuth = createAgingAuth(2)
      const handlers = createHandlers(mockAuth)

      await handlers.renewSessionCookie(request, { id: "user-1" })

      expect(mockAuth.verifySession).not.toHaveBeenCalled()
    })

    it("should return null when there is no session", async () => {
      const mockAuth = createMockAuth({
        getSessionManager: vi.fn().mockReturnValue({
          getSession: vi.fn().mockResolvedValue(null),
        }),
      })
      const handlers = createHandlers(mockAuth)

      expect(await handlers.renewSessionCookie(request, { id: "user-1" })).toBe(
        null,
      )
    })

    it("should return null when the session no longer resolves to a user", async () => {
      const mockAuth = createAgingAuth(10)
      mockAuth.verifySession = vi.fn().mockResolvedValue(null)
      const handlers = createHandlers(mockAuth)

      expect(await handlers.renewSessionCookie(request, { id: "user-1" })).toBe(
        null,
      )
      expect(mockAuth.createSessionCookie).not.toHaveBeenCalled()
    })

    it("should throw when renewAfter was not configured", async () => {
      const handlers = createAuthHandlers(createAgingAuth(10))

      await expect(
        handlers.renewSessionCookie(request, { id: "user-1" }),
      ).rejects.toThrow("session.renewAfter")
    })

    it("should reject an unparseable renewAfter at construction", () => {
      expect(() => createHandlers(createMockAuth(), "7 days")).toThrow(
        "Invalid session.renewAfter",
      )
    })
  })
})

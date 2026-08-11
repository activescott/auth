import { describe, it, expect, vi, afterEach } from "vitest"
import { createAuthHandlers } from "../handlers.js"
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import type { AuthProvider, AuthUser, Identity } from "@activescott/auth"

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

    function createRealAuth(provider: AuthProvider): Auth {
      const realAuth = new Auth({
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
})

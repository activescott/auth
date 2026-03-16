import { describe, it, expect, vi } from "vitest"
import { createAuthHandlers, sendMagicLink } from "../handlers.js"
import type { Auth, AuthUser, Identity } from "@activescott/auth"

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
    it("should delegate initiate requests to auth.handleRequest", async () => {
      const mockAuth = createMockAuth()
      const handlers = createAuthHandlers(mockAuth)

      const request = new Request(`${TEST_BASE_URL}/auth/email/initiate`, {
        method: "POST",
      })
      await handlers.handleAuth({ request })

      expect(mockAuth.handleRequest).toHaveBeenCalledWith(request)
    })

    it("should handle verify requests with session cookie and redirect", async () => {
      const provider = {
        id: "email",
        name: "Email",
        verify: vi.fn().mockResolvedValue({
          success: true,
          user: { id: "user-1" },
          identity: createMockIdentity(),
        }),
        initiate: vi.fn(),
        canHandle: vi.fn(),
        getRoutes: vi.fn(),
      }

      const mockAuth = createMockAuth({
        getProvider: vi.fn().mockReturnValue(provider),
        createContext: vi.fn().mockReturnValue({
          identityStore: {},
          userStore: {},
          baseUrl: TEST_BASE_URL,
          createSession: vi.fn(),
        }),
      })

      const handlers = createAuthHandlers(mockAuth, {
        successRedirect: "/dashboard",
      })

      const request = new Request(
        `${TEST_BASE_URL}/auth/email/verify?token=abc`,
      )
      const response = await handlers.handleAuth({ request })

      expect(response.status).toBe(302)
      expect(response.headers.get("Location")).toBe("/dashboard")
      expect(response.headers.get("Set-Cookie")).toContain("auth_session=")
    })

    it("should redirect to error page on verify failure", async () => {
      const provider = {
        id: "email",
        name: "Email",
        verify: vi.fn().mockResolvedValue({
          success: false,
          error: { code: "INVALID_TOKEN", message: "Bad token" },
        }),
        initiate: vi.fn(),
        canHandle: vi.fn(),
        getRoutes: vi.fn(),
      }

      const mockAuth = createMockAuth({
        getProvider: vi.fn().mockReturnValue(provider),
        createContext: vi.fn().mockReturnValue({
          identityStore: {},
          userStore: {},
          baseUrl: TEST_BASE_URL,
          createSession: vi.fn(),
        }),
      })

      const handlers = createAuthHandlers(mockAuth)

      const request = new Request(
        `${TEST_BASE_URL}/auth/email/verify?token=bad`,
      )
      const response = await handlers.handleAuth({ request })

      expect(response.status).toBe(302)
      expect(response.headers.get("Location")).toContain("/login?error=")
    })

    it("should use redirectTo query param after successful verify", async () => {
      const provider = {
        id: "email",
        name: "Email",
        verify: vi.fn().mockResolvedValue({
          success: true,
          user: { id: "user-1" },
          identity: createMockIdentity(),
        }),
        initiate: vi.fn(),
        canHandle: vi.fn(),
        getRoutes: vi.fn(),
      }

      const mockAuth = createMockAuth({
        getProvider: vi.fn().mockReturnValue(provider),
        createContext: vi.fn().mockReturnValue({
          identityStore: {},
          userStore: {},
          baseUrl: TEST_BASE_URL,
          createSession: vi.fn(),
        }),
      })

      const handlers = createAuthHandlers(mockAuth)

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

describe("sendMagicLink", () => {
  it("should delegate to email provider", async () => {
    const mockProvider = {
      id: "email",
      name: "Email",
      initiate: vi.fn().mockResolvedValue({
        success: true,
        message: "Magic link sent",
      }),
      verify: vi.fn(),
      canHandle: vi.fn(),
      getRoutes: vi.fn(),
    }

    const mockAuth = createMockAuth({
      getProvider: vi.fn().mockReturnValue(mockProvider),
    })

    const result = await sendMagicLink(
      mockAuth,
      "user@example.com",
      TEST_BASE_URL,
    )

    expect(result.success).toBe(true)
    expect(result.message).toContain("Magic link sent")
    expect(mockProvider.initiate).toHaveBeenCalledTimes(1)
  })

  it("should return error when email provider not configured", async () => {
    const mockAuth = createMockAuth()

    const result = await sendMagicLink(
      mockAuth,
      "user@example.com",
      TEST_BASE_URL,
    )

    expect(result.success).toBe(false)
    expect(result.error).toContain("not configured")
  })

  it("should pass redirectTo option to provider", async () => {
    const mockProvider = {
      id: "email",
      name: "Email",
      initiate: vi.fn().mockResolvedValue({
        success: true,
        message: "Sent",
      }),
      verify: vi.fn(),
      canHandle: vi.fn(),
      getRoutes: vi.fn(),
    }

    const mockAuth = createMockAuth({
      getProvider: vi.fn().mockReturnValue(mockProvider),
    })

    await sendMagicLink(mockAuth, "user@example.com", TEST_BASE_URL, {
      redirectTo: "/dashboard",
    })

    const calledRequest = mockProvider.initiate.mock.calls[0][0] as Request
    const body = await calledRequest.text()
    expect(body).toContain("redirectTo=%2Fdashboard")
  })

  it("should handle provider throwing error", async () => {
    const mockProvider = {
      id: "email",
      name: "Email",
      initiate: vi.fn().mockRejectedValue(new Error("SMTP down")),
      verify: vi.fn(),
      canHandle: vi.fn(),
      getRoutes: vi.fn(),
    }

    const mockAuth = createMockAuth({
      getProvider: vi.fn().mockReturnValue(mockProvider),
    })

    const result = await sendMagicLink(
      mockAuth,
      "user@example.com",
      TEST_BASE_URL,
    )

    expect(result.success).toBe(false)
    expect(result.error).toContain("SMTP down")
  })
})

import { describe, it, expect, vi, afterEach } from "vitest"
import jwt from "jsonwebtoken"
import { Auth } from "../auth.js"
import { SessionManager } from "../session/session-manager.js"
import type {
  AuthConfig,
  AuthProvider,
  IdentityStore,
  UserStore,
  Identity,
} from "../types.js"

const TEST_SECRET = "test-session-secret"
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

function createMockProvider(
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
    canHandle: vi.fn((request: Request) =>
      new URL(request.url).pathname.startsWith("/auth/email"),
    ),
    getRoutes: vi.fn().mockReturnValue([]),
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
    },
    userStore: {
      findById: vi.fn().mockResolvedValue({ id: "user-1" }),
      create: vi.fn().mockResolvedValue({ id: "user-1" }),
    },
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

    it("should route send action to provider initiate", async () => {
      const provider = createMockProvider()
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      const request = new Request(`${TEST_BASE_URL}/auth/email/send`, {
        method: "POST",
      })
      await auth.handleRequest(request)

      expect(provider.initiate).toHaveBeenCalledTimes(1)
    })

    it("should route callback action to provider verify", async () => {
      const provider = createMockProvider()
      auth = new Auth(createAuthConfig({ providers: [provider] }))

      const request = new Request(`${TEST_BASE_URL}/auth/email/callback`)
      await auth.handleRequest(request)

      expect(provider.verify).toHaveBeenCalledTimes(1)
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

    it("should return 404 for unknown action", async () => {
      auth = new Auth(createAuthConfig())

      const request = new Request(`${TEST_BASE_URL}/auth/email/unknown`)
      const response = await auth.handleRequest(request)

      expect(response.status).toBe(404)
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

    it("should find provider by request", () => {
      auth = new Auth(createAuthConfig())
      const request = new Request(`${TEST_BASE_URL}/auth/email/verify`)
      expect(auth.findProvider(request)).toBeDefined()
    })

    it("should return undefined for unmatched request", () => {
      auth = new Auth(createAuthConfig())
      const request = new Request(`${TEST_BASE_URL}/other/path`)
      expect(auth.findProvider(request)).toBeUndefined()
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
    const session = manager.verifyToken(token)

    expect(session).not.toBeNull()
    expect(session?.userId).toBe("user-1")
    expect(session?.provider).toBe("email")
    expect(session?.identifier).toBe("user@example.com")
  })

  it("should reject token signed with wrong secret", () => {
    const manager = new SessionManager(sessionConfig)
    const badToken = jwt.sign({ userId: "user-1" }, "wrong-secret", {
      issuer: "auth",
      audience: "users",
    })

    expect(manager.verifyToken(badToken)).toBeNull()
  })

  it("should accept token signed with additional secret", async () => {
    const manager = new SessionManager({
      ...sessionConfig,
      additionalSecrets: ["e2e-secret"],
    })

    const token = jwt.sign(
      { userId: "user-1", identifier: "user@example.com", provider: "email" },
      "e2e-secret",
      { issuer: "auth", audience: "users", expiresIn: "1h" },
    )

    const session = manager.verifyToken(token)
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

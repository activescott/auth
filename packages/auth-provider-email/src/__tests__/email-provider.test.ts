/**
 * EmailProvider Unit Tests
 *
 * Tests for the email magic link authentication provider.
 */
import { describe, it, expect, vi, beforeEach } from "vitest"
import jwt from "jsonwebtoken"
import { EmailProvider } from "../email-provider.js"
import type { AuthContext } from "@activescott/auth"
import type { EmailTransport } from "../types.js"

// Test configuration
const TEST_SECRET = "test-secret-key-for-jwt-signing"
const TEST_BASE_URL = "https://example.com"

// Mock email transport
const mockTransport: EmailTransport = {
  sendMagicLink: vi.fn().mockResolvedValue(true),
}

// Mock auth context
function createMockContext(overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    baseUrl: TEST_BASE_URL,
    userStore: {
      findById: vi.fn(),
      create: vi.fn(),
    },
    identityStore: {
      findByProviderAndIdentifier: vi.fn(),
      findByUserId: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
    },
    createSession: vi.fn().mockResolvedValue("session-token"),
    ...overrides,
  }
}

// Helper to create form request
function createFormRequest(
  data: Record<string, string>,
  baseUrl = TEST_BASE_URL,
): Request {
  return new Request(`${baseUrl}/auth/email/initiate`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(data).toString(),
  })
}

// Helper to create verify request
function createVerifyRequest(token: string, redirectTo?: string): Request {
  let url = `${TEST_BASE_URL}/auth/email/verify?token=${token}`
  if (redirectTo) {
    url += `&redirectTo=${encodeURIComponent(redirectTo)}`
  }
  return new Request(url, { method: "GET" })
}

describe("EmailProvider", () => {
  let provider: EmailProvider

  beforeEach(() => {
    vi.clearAllMocks()
    provider = new EmailProvider(
      {
        magicLinkSecret: TEST_SECRET,
        magicLinkExpiry: "5m",
        smtp: { host: "smtp.test.com", port: 587, user: "user", pass: "pass" },
        from: "test@example.com",
        template: {
          appName: "Test App",
          subject: "Sign In",
          primaryColor: "#000",
        },
      },
      mockTransport,
    )
  })

  describe("initiate", () => {
    it("should send magic link with email only", async () => {
      const request = createFormRequest({ email: "user@example.com" })
      const context = createMockContext()

      const result = await provider.initiate(request, context)

      expect(result.success).toBe(true)
      expect(mockTransport.sendMagicLink).toHaveBeenCalledTimes(1)

      // Verify the magic link URL format
      const [email, magicLink] = vi.mocked(mockTransport.sendMagicLink).mock
        .calls[0]
      expect(email).toBe("user@example.com")
      expect(magicLink).toContain(`${TEST_BASE_URL}/auth/email/verify?token=`)
      expect(magicLink).not.toContain("redirectTo=")
    })

    it("should include redirectTo in magic link URL when provided", async () => {
      const redirectTo = "/oauth/authorize?client_id=test&response_type=code"
      const request = createFormRequest({
        email: "user@example.com",
        redirectTo,
      })
      const context = createMockContext()

      const result = await provider.initiate(request, context)

      expect(result.success).toBe(true)

      // Verify redirectTo is in the magic link URL
      const [, magicLink] = vi.mocked(mockTransport.sendMagicLink).mock.calls[0]
      expect(magicLink).toContain(
        `&redirectTo=${encodeURIComponent(redirectTo)}`,
      )
    })

    it("should include redirectTo in JWT token payload", async () => {
      const redirectTo = "/oauth/authorize?client_id=test"
      const request = createFormRequest({
        email: "user@example.com",
        redirectTo,
      })
      const context = createMockContext()

      await provider.initiate(request, context)

      // Extract token from magic link and decode it
      const [, magicLink] = vi.mocked(mockTransport.sendMagicLink).mock.calls[0]
      const url = new URL(magicLink)
      const token = url.searchParams.get("token")

      expect(token).toBeTruthy()
      expect(token).not.toBeNull()
      const decoded = jwt.verify(token as string, TEST_SECRET) as {
        email: string
        redirectTo?: string
      }
      expect(decoded.email).toBe("user@example.com")
      expect(decoded.redirectTo).toBe(redirectTo)
    })

    it("should not include redirectTo in JWT when not provided", async () => {
      const request = createFormRequest({ email: "user@example.com" })
      const context = createMockContext()

      await provider.initiate(request, context)

      // Extract token and verify no redirectTo
      const [, magicLink] = vi.mocked(mockTransport.sendMagicLink).mock.calls[0]
      const url = new URL(magicLink)
      const token = url.searchParams.get("token")

      expect(token).not.toBeNull()
      const decoded = jwt.verify(token as string, TEST_SECRET) as {
        email: string
        redirectTo?: string
      }
      expect(decoded.email).toBe("user@example.com")
      expect(decoded.redirectTo).toBeUndefined()
    })

    it("should reject invalid email format", async () => {
      const request = createFormRequest({ email: "not-an-email" })
      const context = createMockContext()

      const result = await provider.initiate(request, context)

      expect(result.success).toBe(false)
      expect(mockTransport.sendMagicLink).not.toHaveBeenCalled()
    })

    it("should reject missing email", async () => {
      const request = createFormRequest({})
      const context = createMockContext()

      const result = await provider.initiate(request, context)

      expect(result.success).toBe(false)
      expect(mockTransport.sendMagicLink).not.toHaveBeenCalled()
    })

    it("should return error when transport fails", async () => {
      vi.mocked(mockTransport.sendMagicLink).mockResolvedValueOnce(false)
      const request = createFormRequest({ email: "user@example.com" })
      const context = createMockContext()

      const result = await provider.initiate(request, context)

      expect(result.success).toBe(false)
    })

    it("should normalize email to lowercase before sending", async () => {
      const request = createFormRequest({ email: "User@Example.COM" })
      const context = createMockContext()

      const result = await provider.initiate(request, context)

      expect(result.success).toBe(true)

      // Transport should receive lowercase email
      const [email, magicLink] = vi.mocked(mockTransport.sendMagicLink).mock
        .calls[0]
      expect(email).toBe("user@example.com")

      // JWT should also contain lowercase email
      const url = new URL(magicLink)
      const token = url.searchParams.get("token")
      expect(token).not.toBeNull()
      const decoded = jwt.verify(token as string, TEST_SECRET) as {
        email: string
      }
      expect(decoded.email).toBe("user@example.com")
    })

    it("should trim whitespace from email", async () => {
      const request = createFormRequest({ email: "  user@example.com  " })
      const context = createMockContext()

      const result = await provider.initiate(request, context)

      expect(result.success).toBe(true)

      const [email] = vi.mocked(mockTransport.sendMagicLink).mock.calls[0]
      expect(email).toBe("user@example.com")
    })
  })

  describe("verify", () => {
    it("should verify valid token and return user", async () => {
      const token = jwt.sign({ email: "user@example.com" }, TEST_SECRET, {
        expiresIn: "5m",
        issuer: "auth-magic-link",
        audience: "auth",
      })

      const mockUser = { id: "user-1", email: "user@example.com" }
      const mockIdentity = {
        id: "identity-1",
        userId: "user-1",
        provider: "email",
        identifier: "user@example.com",
        createdAt: new Date(),
      }

      const context = createMockContext({
        identityStore: {
          findByProviderAndIdentifier: vi.fn().mockResolvedValue(mockIdentity),
          findByUserId: vi.fn(),
          create: vi.fn(),
          update: vi.fn(),
        },
        userStore: {
          findById: vi.fn().mockResolvedValue(mockUser),
          create: vi.fn(),
        },
      })

      const request = createVerifyRequest(token)
      const result = await provider.verify(request, context)

      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.user.id).toBe("user-1")
        expect(result.identity.identifier).toBe("user@example.com")
      }
    })

    it("should reject expired token", async () => {
      const token = jwt.sign({ email: "user@example.com" }, TEST_SECRET, {
        expiresIn: "-1s", // Already expired
        issuer: "auth-magic-link",
        audience: "auth",
      })

      const context = createMockContext()
      const request = createVerifyRequest(token)
      const result = await provider.verify(request, context)

      expect(result.success).toBe(false)
    })

    it("should reject token with invalid signature", async () => {
      const token = jwt.sign({ email: "user@example.com" }, "wrong-secret", {
        expiresIn: "5m",
        issuer: "auth-magic-link",
        audience: "auth",
      })

      const context = createMockContext()
      const request = createVerifyRequest(token)
      const result = await provider.verify(request, context)

      expect(result.success).toBe(false)
    })

    it("should reject missing token", async () => {
      const request = new Request(`${TEST_BASE_URL}/auth/email/verify`, {
        method: "GET",
      })
      const context = createMockContext()

      const result = await provider.verify(request, context)

      expect(result.success).toBe(false)
    })

    it("should normalize email from token during verify", async () => {
      const token = jwt.sign({ email: "User@Example.COM" }, TEST_SECRET, {
        expiresIn: "5m",
        issuer: "auth-magic-link",
        audience: "auth",
      })

      const mockUser = { id: "user-1", email: "user@example.com" }
      const mockIdentity = {
        id: "identity-1",
        userId: "user-1",
        provider: "email",
        identifier: "user@example.com",
        createdAt: new Date(),
      }

      const context = createMockContext({
        identityStore: {
          findByProviderAndIdentifier: vi.fn().mockResolvedValue(mockIdentity),
          findByUserId: vi.fn(),
          create: vi.fn(),
          update: vi.fn(),
        },
        userStore: {
          findById: vi.fn().mockResolvedValue(mockUser),
          create: vi.fn(),
        },
      })

      const request = createVerifyRequest(token)
      const result = await provider.verify(request, context)

      expect(result.success).toBe(true)
      expect(
        context.identityStore.findByProviderAndIdentifier,
      ).toHaveBeenCalledWith("email", "user@example.com")
    })

    it("should normalize email when creating new identity", async () => {
      const token = jwt.sign({ email: "New@Example.COM" }, TEST_SECRET, {
        expiresIn: "5m",
        issuer: "auth-magic-link",
        audience: "auth",
      })

      const mockNewUser = { id: "user-new", email: "new@example.com" }
      const mockNewIdentity = {
        id: "identity-new",
        userId: "user-new",
        provider: "email",
        identifier: "new@example.com",
        createdAt: new Date(),
      }

      const context = createMockContext({
        identityStore: {
          findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
          findByUserId: vi.fn(),
          create: vi.fn().mockResolvedValue(mockNewIdentity),
          update: vi.fn(),
        },
        userStore: {
          findById: vi.fn(),
          create: vi.fn().mockResolvedValue(mockNewUser),
        },
      })

      const request = createVerifyRequest(token)
      const result = await provider.verify(request, context)

      expect(result.success).toBe(true)
      expect(context.userStore.create).toHaveBeenCalledWith({
        provider: "email",
        identifier: "new@example.com",
      })
      expect(context.identityStore.create).toHaveBeenCalledWith({
        userId: "user-new",
        provider: "email",
        identifier: "new@example.com",
      })
    })

    it("should create new user if identity does not exist", async () => {
      const token = jwt.sign({ email: "new@example.com" }, TEST_SECRET, {
        expiresIn: "5m",
        issuer: "auth-magic-link",
        audience: "auth",
      })

      const mockNewUser = { id: "user-new", email: "new@example.com" }
      const mockNewIdentity = {
        id: "identity-new",
        userId: "user-new",
        provider: "email",
        identifier: "new@example.com",
        createdAt: new Date(),
      }

      const context = createMockContext({
        identityStore: {
          findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
          findByUserId: vi.fn(),
          create: vi.fn().mockResolvedValue(mockNewIdentity),
          update: vi.fn(),
        },
        userStore: {
          findById: vi.fn(),
          create: vi.fn().mockResolvedValue(mockNewUser),
        },
      })

      const request = createVerifyRequest(token)
      const result = await provider.verify(request, context)

      expect(result.success).toBe(true)
      expect(context.userStore.create).toHaveBeenCalled()
      expect(context.identityStore.create).toHaveBeenCalled()
    })
  })

  describe("canHandle", () => {
    it("should handle /auth/email paths", () => {
      const request = new Request(`${TEST_BASE_URL}/auth/email/verify`)
      expect(provider.canHandle(request)).toBe(true)
    })

    it("should not handle other paths", () => {
      const request = new Request(`${TEST_BASE_URL}/auth/google/callback`)
      expect(provider.canHandle(request)).toBe(false)
    })
  })

  describe("getRoutes", () => {
    it("should return expected routes", () => {
      const routes = provider.getRoutes()

      expect(routes).toContainEqual({
        method: "POST",
        path: "/email/initiate",
        handler: "initiate",
      })
      expect(routes).toContainEqual({
        method: "GET",
        path: "/email/verify",
        handler: "verify",
      })
    })
  })
})

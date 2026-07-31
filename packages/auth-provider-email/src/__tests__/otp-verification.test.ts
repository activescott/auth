/**
 * Email OTP code tests: initiation creates a challenge and cookie, and
 * POST /auth/email/verify with a code authenticates against it.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { InMemoryChallengeStore } from "@activescott/auth"
import type { AuthContext, Identity } from "@activescott/auth"
import { EmailProvider } from "../email-provider.js"
import type { EmailTransport } from "../types.js"

const TEST_SECRET = "test-secret-key-for-jwt-signing"
const TEST_BASE_URL = "https://example.com"
const TEST_EMAIL = "user@example.com"
const OTP_MAX_ATTEMPTS = 5

const mockTransport: EmailTransport = {
  sendMagicLink: vi.fn().mockResolvedValue(true),
}

function createMockIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: "identity-1",
    userId: "user-1",
    provider: "email",
    identifier: TEST_EMAIL,
    createdAt: new Date(),
    ...overrides,
  }
}

function createMockContext(overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    baseUrl: TEST_BASE_URL,
    userStore: {
      findById: vi.fn().mockResolvedValue({ id: "user-1" }),
      create: vi.fn().mockResolvedValue({ id: "user-1" }),
    },
    identityStore: {
      findByProviderAndIdentifier: vi
        .fn()
        .mockResolvedValue(createMockIdentity()),
      findByUserId: vi.fn().mockResolvedValue([]),
      create: vi.fn().mockResolvedValue(createMockIdentity()),
      update: vi.fn().mockResolvedValue(createMockIdentity()),
    },
    createSession: vi.fn().mockResolvedValue("session-token"),
    ...overrides,
  }
}

function createProvider(
  otp: { enabled: boolean; maxAttempts?: number; expiry?: string } = {
    enabled: true,
  },
): EmailProvider {
  return new EmailProvider(
    {
      magicLinkSecret: TEST_SECRET,
      magicLinkExpiry: "5m",
      smtp: { host: "smtp.test.com", port: 587, user: "user", pass: "pass" },
      from: "test@example.com",
      otp: { maxAttempts: OTP_MAX_ATTEMPTS, ...otp },
    },
    mockTransport,
  )
}

function createInitiateRequest(email = TEST_EMAIL): Request {
  return new Request(`${TEST_BASE_URL}/auth/email/initiate`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email }).toString(),
  })
}

function createCodeRequest(code: string, cookie?: string): Request {
  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  }
  if (cookie) headers.Cookie = cookie
  return new Request(`${TEST_BASE_URL}/auth/email/verify`, {
    method: "POST",
    headers,
    body: new URLSearchParams({ code }).toString(),
  })
}

/** Run initiate and return the emailed code plus a Cookie header value */
async function initiateAndCapture(
  provider: EmailProvider,
  context: AuthContext,
): Promise<{ code: string; cookie: string }> {
  const result = await provider.initiate(createInitiateRequest(), context)
  if (!result.success) throw new Error("initiate failed")
  if (result instanceof Response) throw new Error("unexpected Response")

  const calls = vi.mocked(mockTransport.sendMagicLink).mock.calls
  const lastCall = calls.at(-1)
  const code = lastCall?.[3]?.code
  if (!code) throw new Error("no code passed to transport")

  const setCookie = result.setCookies?.[0]
  if (!setCookie) throw new Error("no challenge cookie set")
  const cookiePair = setCookie.split(";")[0]
  if (!cookiePair) throw new Error("malformed cookie")

  return { code, cookie: cookiePair }
}

describe("EmailProvider OTP", () => {
  let provider: EmailProvider
  let challengeStore: InMemoryChallengeStore
  let context: AuthContext

  beforeEach(() => {
    vi.clearAllMocks()
    provider = createProvider()
    challengeStore = new InMemoryChallengeStore()
    context = createMockContext({ challengeStore })
  })

  afterEach(() => {
    challengeStore.destroy()
  })

  describe("initiate with OTP enabled", () => {
    it("should pass a 6-digit code to the transport", async () => {
      const { code } = await initiateAndCapture(provider, context)
      expect(code).toMatch(/^[0-9]{6}$/)
    })

    it("should set an HttpOnly challenge cookie scoped to /auth", async () => {
      const result = await provider.initiate(createInitiateRequest(), context)
      if (!result.success || result instanceof Response) {
        throw new Error("initiate failed")
      }

      const cookie = result.setCookies?.[0]
      expect(cookie).toContain("auth_challenge=")
      expect(cookie).toContain("HttpOnly")
      expect(cookie).toContain("Path=/auth")
      expect(cookie).toContain("SameSite=Lax")
      expect(cookie).toContain("Secure")
      expect(cookie).toContain("Max-Age=600")
    })

    it("should store only a hash of the code", async () => {
      const { code, cookie } = await initiateAndCapture(provider, context)
      const challengeId = cookie.split("=")[1] ?? ""

      const challenge = await challengeStore.findById(challengeId)
      expect(challenge).not.toBeNull()
      expect(challenge?.hashedCode).toBeDefined()
      expect(challenge?.hashedCode).not.toContain(code)
      expect(challenge?.identifier).toBe(TEST_EMAIL)
      expect(challenge?.maxAttempts).toBe(OTP_MAX_ATTEMPTS)
    })

    it("should fail with CONFIGURATION_ERROR when no challengeStore is configured", async () => {
      const bare = createMockContext()
      const result = await provider.initiate(createInitiateRequest(), bare)

      expect(result.success).toBe(false)
      if (result.success || result instanceof Response) return
      expect(result.error.code).toBe("CONFIGURATION_ERROR")
    })

    it("should not create challenges or cookies when OTP is disabled", async () => {
      const plain = createProvider({ enabled: false })
      const result = await plain.initiate(createInitiateRequest(), context)

      if (!result.success || result instanceof Response) {
        throw new Error("initiate failed")
      }
      expect(result.setCookies).toBeUndefined()
      const lastCall = vi.mocked(mockTransport.sendMagicLink).mock.calls.at(-1)
      expect(lastCall?.[3]).toBeUndefined()
    })

    it("should default to sending codes when a challengeStore is configured", async () => {
      const noOtpConfig = new EmailProvider(
        {
          magicLinkSecret: TEST_SECRET,
          magicLinkExpiry: "5m",
          smtp: {
            host: "smtp.test.com",
            port: 587,
            user: "user",
            pass: "pass",
          },
          from: "test@example.com",
        },
        mockTransport,
      )

      const result = await noOtpConfig.initiate(
        createInitiateRequest(),
        context,
      )
      if (!result.success || result instanceof Response) {
        throw new Error("initiate failed")
      }

      expect(result.setCookies?.[0]).toContain("auth_challenge=")
      const lastCall = vi.mocked(mockTransport.sendMagicLink).mock.calls.at(-1)
      expect(lastCall?.[3]?.code).toMatch(/^[0-9]{6}$/)
    })

    it("should default to magic-link-only when no challengeStore is configured", async () => {
      const noOtpConfig = new EmailProvider(
        {
          magicLinkSecret: TEST_SECRET,
          magicLinkExpiry: "5m",
          smtp: {
            host: "smtp.test.com",
            port: 587,
            user: "user",
            pass: "pass",
          },
          from: "test@example.com",
        },
        mockTransport,
      )

      const bare = createMockContext()
      const result = await noOtpConfig.initiate(createInitiateRequest(), bare)
      if (!result.success || result instanceof Response) {
        throw new Error("initiate failed")
      }

      expect(result.setCookies).toBeUndefined()
      const lastCall = vi.mocked(mockTransport.sendMagicLink).mock.calls.at(-1)
      expect(lastCall?.[3]).toBeUndefined()
    })
  })

  describe("verify with OTP code", () => {
    it("should authenticate with the correct code and clear the cookie", async () => {
      const { code, cookie } = await initiateAndCapture(provider, context)

      const result = await provider.verify(
        createCodeRequest(code, cookie),
        context,
      )

      expect(result.success).toBe(true)
      if (!result.success) return
      expect(result.user.id).toBe("user-1")
      expect(result.setCookies?.[0]).toContain("auth_challenge=;")
      expect(result.setCookies?.[0]).toContain("Max-Age=0")
    })

    it("should consume the challenge so the code cannot be replayed", async () => {
      const { code, cookie } = await initiateAndCapture(provider, context)

      const first = await provider.verify(
        createCodeRequest(code, cookie),
        context,
      )
      expect(first.success).toBe(true)

      const replay = await provider.verify(
        createCodeRequest(code, cookie),
        context,
      )
      expect(replay.success).toBe(false)
      if (replay.success) return
      expect(replay.error.code).toBe("INVALID_CREDENTIALS")
    })

    it("should reject an incorrect code with INVALID_CREDENTIALS", async () => {
      const { code, cookie } = await initiateAndCapture(provider, context)
      const wrongCode = code === "000000" ? "111111" : "000000"

      const result = await provider.verify(
        createCodeRequest(wrongCode, cookie),
        context,
      )

      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("INVALID_CREDENTIALS")
    })

    it("should rate limit after max attempts even with the correct code", async () => {
      const { code, cookie } = await initiateAndCapture(provider, context)
      const wrongCode = code === "000000" ? "111111" : "000000"

      for (let attempt = 0; attempt < OTP_MAX_ATTEMPTS; attempt++) {
        await provider.verify(createCodeRequest(wrongCode, cookie), context)
      }

      const result = await provider.verify(
        createCodeRequest(code, cookie),
        context,
      )

      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("RATE_LIMITED")
    })

    it("should reject an expired code with EXPIRED_TOKEN", async () => {
      const shortLived = createProvider({ enabled: true, expiry: "1s" })
      const { code, cookie } = await initiateAndCapture(shortLived, context)

      const challengeId = cookie.split("=")[1] ?? ""
      const challenge = await challengeStore.findById(challengeId)
      if (challenge) challenge.expiresAt = new Date(Date.now() - 1000)

      const result = await shortLived.verify(
        createCodeRequest(code, cookie),
        context,
      )

      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("EXPIRED_TOKEN")
    })

    it("should reject when no challenge cookie is present", async () => {
      const { code } = await initiateAndCapture(provider, context)

      const result = await provider.verify(createCodeRequest(code), context)

      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("INVALID_CREDENTIALS")
    })

    it("should reject when the code is missing from the body", async () => {
      const { cookie } = await initiateAndCapture(provider, context)

      const request = new Request(`${TEST_BASE_URL}/auth/email/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: cookie,
        },
        body: "",
      })
      const result = await provider.verify(request, context)

      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("INVALID_CREDENTIALS")
    })

    it("should fail with CONFIGURATION_ERROR when OTP is disabled", async () => {
      const plain = createProvider({ enabled: false })
      const result = await plain.verify(
        createCodeRequest("123456", "auth_challenge=abc"),
        context,
      )

      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("CONFIGURATION_ERROR")
    })

    it("should issue a fresh challenge and cookie on resend", async () => {
      const first = await initiateAndCapture(provider, context)
      const second = await initiateAndCapture(provider, context)

      expect(second.cookie).not.toBe(first.cookie)

      // The newest code with the newest cookie works
      const result = await provider.verify(
        createCodeRequest(second.code, second.cookie),
        context,
      )
      expect(result.success).toBe(true)
    })
  })

  describe("magic link regression with OTP enabled", () => {
    it("should still verify magic link tokens via GET", async () => {
      await initiateAndCapture(provider, context)

      const calls = vi.mocked(mockTransport.sendMagicLink).mock.calls
      const magicLink = calls.at(-1)?.[1]
      if (!magicLink) throw new Error("no magic link sent")

      const result = await provider.verify(
        new Request(magicLink, { method: "GET" }),
        context,
      )

      expect(result.success).toBe(true)
    })
  })
})

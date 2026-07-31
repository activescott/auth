/**
 * Email OTP code tests: initiation creates a challenge and cookie, and
 * POST /auth/email/verify with a code authenticates against it.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { InMemoryChallengeStore } from "@activescott/auth"
import type { AuthContext, Identity } from "@activescott/auth"
import { EmailProvider } from "../email-provider.js"
import type { EmailTransport } from "../types.js"

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

function createMockContext(
  challengeStore: InMemoryChallengeStore,
): AuthContext {
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
    challengeStore,
  }
}

function createProvider(): EmailProvider {
  return new EmailProvider(
    {
      smtp: { host: "smtp.test.com", port: 587, user: "user", pass: "pass" },
      from: "test@example.com",
      otp: { maxAttempts: OTP_MAX_ATTEMPTS },
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
  if (result instanceof Response) throw new Error("unexpected Response")
  if (!result.success) throw new Error("initiate failed")

  const calls = vi.mocked(mockTransport.sendMagicLink).mock.calls
  const code = calls.at(-1)?.[3]?.code
  if (!code) throw new Error("no code passed to transport")

  const setCookie = result.setCookies?.[0]
  if (!setCookie) throw new Error("no challenge cookie set")
  const cookiePair = setCookie.split(";")[0]
  if (!cookiePair) throw new Error("malformed cookie")

  return { code, cookie: cookiePair }
}

async function verifyCode(
  provider: EmailProvider,
  context: AuthContext,
  code: string,
  cookie?: string,
) {
  const result = await provider.verify(createCodeRequest(code, cookie), context)
  if (result instanceof Response) throw new Error("unexpected Response")
  return result
}

describe("EmailProvider OTP codes", () => {
  let provider: EmailProvider
  let challengeStore: InMemoryChallengeStore
  let context: AuthContext

  beforeEach(() => {
    vi.clearAllMocks()
    provider = createProvider()
    challengeStore = new InMemoryChallengeStore()
    context = createMockContext(challengeStore)
  })

  afterEach(() => {
    challengeStore.destroy()
  })

  it("should always pass a 6-digit code to the transport", async () => {
    const { code } = await initiateAndCapture(provider, context)
    expect(code).toMatch(/^[0-9]{6}$/)
  })

  it("should store only a hash of the code", async () => {
    const { code, cookie } = await initiateAndCapture(provider, context)
    const challengeId = cookie.split("=")[1] ?? ""

    const challenge = await challengeStore.findById(challengeId)
    expect(challenge?.hashedCode).toBeDefined()
    expect(challenge?.hashedCode).not.toContain(code)
    expect(challenge?.maxAttempts).toBe(OTP_MAX_ATTEMPTS)
  })

  it("should authenticate with the correct code and clear the cookie", async () => {
    const { code, cookie } = await initiateAndCapture(provider, context)

    const result = await verifyCode(provider, context, code, cookie)

    expect(result.success).toBe(true)
    if (!result.success) return
    expect(result.user.id).toBe("user-1")
    expect(result.setCookies?.[0]).toContain("auth_challenge=;")
    expect(result.setCookies?.[0]).toContain("Max-Age=0")
  })

  it("should consume the challenge so the code cannot be replayed", async () => {
    const { code, cookie } = await initiateAndCapture(provider, context)

    const first = await verifyCode(provider, context, code, cookie)
    expect(first.success).toBe(true)

    const replay = await verifyCode(provider, context, code, cookie)
    expect(replay.success).toBe(false)
    if (replay.success) return
    expect(replay.error.code).toBe("INVALID_CREDENTIALS")
  })

  it("should reject an incorrect code with INVALID_CREDENTIALS", async () => {
    const { code, cookie } = await initiateAndCapture(provider, context)
    const wrongCode = code === "000000" ? "111111" : "000000"

    const result = await verifyCode(provider, context, wrongCode, cookie)

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("INVALID_CREDENTIALS")
  })

  it("should rate limit after max attempts even with the correct code", async () => {
    const { code, cookie } = await initiateAndCapture(provider, context)
    const wrongCode = code === "000000" ? "111111" : "000000"

    for (let attempt = 0; attempt < OTP_MAX_ATTEMPTS; attempt++) {
      await verifyCode(provider, context, wrongCode, cookie)
    }

    const result = await verifyCode(provider, context, code, cookie)

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("RATE_LIMITED")
  })

  it("should reject an expired code with EXPIRED_TOKEN", async () => {
    const { code, cookie } = await initiateAndCapture(provider, context)

    const challengeId = cookie.split("=")[1] ?? ""
    const challenge = await challengeStore.findById(challengeId)
    if (challenge) challenge.expiresAt = new Date(Date.now() - 1000)

    const result = await verifyCode(provider, context, code, cookie)

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("EXPIRED_TOKEN")
  })

  it("should reject when no challenge cookie is present", async () => {
    const { code } = await initiateAndCapture(provider, context)

    const result = await verifyCode(provider, context, code)

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("INVALID_CREDENTIALS")
  })

  it("should reject an empty body", async () => {
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

    if (result instanceof Response) throw new Error("unexpected Response")
    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("INVALID_CREDENTIALS")
  })

  it("should issue a fresh challenge and cookie on resend", async () => {
    const first = await initiateAndCapture(provider, context)
    const second = await initiateAndCapture(provider, context)

    expect(second.cookie).not.toBe(first.cookie)

    const result = await verifyCode(
      provider,
      context,
      second.code,
      second.cookie,
    )
    expect(result.success).toBe(true)
  })
})

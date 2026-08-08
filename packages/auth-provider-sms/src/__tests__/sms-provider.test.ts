import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { InMemoryChallengeStore } from "@activescott/auth"
import type { AuthContext, Identity } from "@activescott/auth"
import { SmsProvider, normalizePhoneNumber } from "../sms-provider.js"
import type {
  SmsTransport,
  VerificationCheck,
  VerificationTransport,
} from "../types.js"

const TEST_BASE_URL = "https://example.com"
const TEST_PHONE = "+14155550100"
const OTP_MAX_ATTEMPTS = 5

const mockTransport: SmsTransport = {
  sendMessage: vi.fn().mockResolvedValue(true),
}

function createMockIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: "identity-1",
    userId: "user-1",
    provider: "sms",
    identifier: TEST_PHONE,
    createdAt: new Date(),
    ...overrides,
  }
}

function createMockContext(
  challengeStore: InMemoryChallengeStore,
  overrides: Partial<AuthContext> = {},
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
    ...overrides,
  }
}

function createProvider(
  config: ConstructorParameters<typeof SmsProvider>[0] = {},
): SmsProvider {
  return new SmsProvider(
    {
      appName: "Test App",
      otp: { maxAttempts: OTP_MAX_ATTEMPTS },
      ...config,
    },
    mockTransport,
  )
}

function createInitiateRequest(
  phone = TEST_PHONE,
  headers: Record<string, string> = {},
): Request {
  return new Request(`${TEST_BASE_URL}/auth/sms/initiate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams({ phone }).toString(),
  })
}

function createCodeRequest(code: string, cookie?: string): Request {
  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  }
  if (cookie) headers.Cookie = cookie
  return new Request(`${TEST_BASE_URL}/auth/sms/verify`, {
    method: "POST",
    headers,
    body: new URLSearchParams({ code }).toString(),
  })
}

function lastMessage(): string {
  const calls = vi.mocked(mockTransport.sendMessage).mock.calls
  const message = calls.at(-1)?.[1]
  if (!message) throw new Error("no message sent")
  return message
}

/** Extract the code from the default message template */
function codeFromMessage(message: string): string {
  const match = message.match(/code is: (\d+)/)
  if (!match?.[1]) throw new Error(`no code in message: ${message}`)
  return match[1]
}

async function initiateAndCapture(
  provider: SmsProvider,
  context: AuthContext,
): Promise<{ code: string; cookie: string }> {
  const result = await provider.initiate(createInitiateRequest(), context)
  if (result instanceof Response) throw new Error("unexpected Response")
  if (!result.success) throw new Error("initiate failed")

  const code = codeFromMessage(lastMessage())

  const setCookie = result.setCookies?.[0]
  if (!setCookie) throw new Error("no challenge cookie set")
  const cookiePair = setCookie.split(";")[0]
  if (!cookiePair) throw new Error("malformed cookie")

  return { code, cookie: cookiePair }
}

async function verifyCode(
  provider: SmsProvider,
  context: AuthContext,
  code: string,
  cookie?: string,
) {
  const result = await provider.verify(createCodeRequest(code, cookie), context)
  if (result instanceof Response) throw new Error("unexpected Response")
  return result
}

describe("normalizePhoneNumber", () => {
  it.each([
    ["+14155550100", "+14155550100"],
    ["+1 (415) 555-0100", "+14155550100"],
    ["+44 20 7946 0958", "+442079460958"],
    ["0014155550100", "+14155550100"],
  ])("should normalize %s to %s", (input, expected) => {
    expect(normalizePhoneNumber(input)).toBe(expected)
  })

  it.each([
    ["4155550100"], // no country code — we never guess one
    ["+0123456"], // leading zero after +
    ["+1"], // too short
    ["not-a-phone"],
    ["+123456789012345678"], // too long
  ])("should reject %s", (input) => {
    expect(normalizePhoneNumber(input)).toBeNull()
  })
})

describe("SmsProvider", () => {
  let provider: SmsProvider
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

  describe("initiate", () => {
    it("should text a 6-digit code and store only its hash", async () => {
      const { code, cookie } = await initiateAndCapture(provider, context)
      expect(code).toMatch(/^[0-9]{6}$/)

      const challengeId = cookie.split("=")[1] ?? ""
      const challenge = await challengeStore.findById(challengeId)
      expect(challenge?.type).toBe("sms")
      expect(challenge?.identifier).toBe(TEST_PHONE)
      expect(challenge?.hashedCode).toBeDefined()
      expect(challenge?.hashedCode).not.toContain(code)
    })

    it("should include the app name in the default message", async () => {
      await initiateAndCapture(provider, context)
      expect(lastMessage()).toContain("Your Test App sign-in code is:")
    })

    it("should append the WebOTP line last when webOtpDomain is set", async () => {
      const webOtpProvider = createProvider({ webOtpDomain: "example.com" })
      await initiateAndCapture(webOtpProvider, context)

      const lines = lastMessage().split("\n")
      const lastLine = lines.at(-1) ?? ""
      const code = codeFromMessage(lastMessage())
      expect(lastLine).toBe(`@example.com #${code}`)
    })

    it("should not include a WebOTP line by default", async () => {
      await initiateAndCapture(provider, context)
      expect(lastMessage()).not.toContain("@")
    })

    it("should normalize the phone number before storing", async () => {
      const result = await provider.initiate(
        createInitiateRequest("+1 (415) 555-0100"),
        context,
      )
      if (result instanceof Response || !result.success) {
        throw new Error("initiate failed")
      }
      expect(vi.mocked(mockTransport.sendMessage).mock.calls.at(-1)?.[0]).toBe(
        TEST_PHONE,
      )
    })

    it("should reject a number without a country code", async () => {
      const result = await provider.initiate(
        createInitiateRequest("4155550100"),
        context,
      )
      if (result instanceof Response) throw new Error("expected result")
      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("INVALID_CREDENTIALS")
    })

    it("should reject a missing phone", async () => {
      const request = new Request(`${TEST_BASE_URL}/auth/sms/initiate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      })
      const result = await provider.initiate(request, context)
      if (result instanceof Response) throw new Error("expected result")
      expect(result.success).toBe(false)
    })

    it("should fail when the transport cannot send", async () => {
      vi.mocked(mockTransport.sendMessage).mockResolvedValueOnce(false)
      const result = await provider.initiate(createInitiateRequest(), context)
      if (result instanceof Response) throw new Error("expected result")
      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("PROVIDER_ERROR")
    })

    it("should redirect browser form posts back to the submitting page", async () => {
      const request = createInitiateRequest(TEST_PHONE, {
        Accept: "text/html",
        Referer: `${TEST_BASE_URL}/login`,
      })
      const result = await provider.initiate(request, context)

      if (!(result instanceof Response)) throw new Error("expected redirect")
      expect(result.status).toBe(302)
      const location = result.headers.get("Location") ?? ""
      expect(location).toContain("/login")
      expect(location).toContain("sent=1")
      expect(result.headers.get("Set-Cookie")).toContain("auth_sms_challenge=")
    })
  })

  describe("verify", () => {
    it("should authenticate with the correct code and clear the cookie", async () => {
      const { code, cookie } = await initiateAndCapture(provider, context)

      const result = await verifyCode(provider, context, code, cookie)

      expect(result.success).toBe(true)
      if (!result.success) return
      expect(result.user.id).toBe("user-1")
      expect(result.setCookies?.[0]).toContain("auth_sms_challenge=;")
      expect(result.setCookies?.[0]).toContain("Max-Age=0")
    })

    it("should consume the challenge so the code cannot be replayed", async () => {
      const { code, cookie } = await initiateAndCapture(provider, context)

      const first = await verifyCode(provider, context, code, cookie)
      expect(first.success).toBe(true)

      const replay = await verifyCode(provider, context, code, cookie)
      expect(replay.success).toBe(false)
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

    it("should create user and identity for a new phone number", async () => {
      const emptyIdentityContext = createMockContext(challengeStore, {
        identityStore: {
          findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
          findByUserId: vi.fn().mockResolvedValue([]),
          create: vi.fn().mockResolvedValue(createMockIdentity()),
          update: vi.fn().mockResolvedValue(createMockIdentity()),
        },
      })

      const { code, cookie } = await initiateAndCapture(
        provider,
        emptyIdentityContext,
      )
      const result = await verifyCode(
        provider,
        emptyIdentityContext,
        code,
        cookie,
      )

      expect(result.success).toBe(true)
      expect(emptyIdentityContext.userStore.create).toHaveBeenCalledWith({
        provider: "sms",
        identifier: TEST_PHONE,
      })
    })
  })

  describe("routing", () => {
    it("should handle /auth/sms paths only", () => {
      expect(
        provider.canHandle(new Request(`${TEST_BASE_URL}/auth/sms/initiate`)),
      ).toBe(true)
      expect(
        provider.canHandle(new Request(`${TEST_BASE_URL}/auth/email/verify`)),
      ).toBe(false)
    })
  })
})

describe("SmsProvider per-recipient throttling", () => {
  let challengeStore: InMemoryChallengeStore

  beforeEach(() => {
    vi.clearAllMocks()
    challengeStore = new InMemoryChallengeStore()
  })

  afterEach(() => {
    challengeStore.destroy()
  })

  it("texts nothing when the number is throttled", async () => {
    const provider = createProvider()
    const context = createMockContext(challengeStore, {
      abuse: {
        checkIdentifier: vi.fn().mockResolvedValue({
          allowed: false,
          event: {
            reason: "identifier_rate_limited",
            providerId: "sms",
            ip: null,
            identifier: TEST_PHONE,
            at: new Date(),
          },
        }),
      },
    })

    const result = await provider.initiate(createInitiateRequest(), context)

    expect(mockTransport.sendMessage).not.toHaveBeenCalled()
    expect(result).toEqual({
      success: true,
      message: provider.initiateSentMessage,
      setCookies: [],
    })
  })

  it("passes the E.164 number to the abuse check", async () => {
    const provider = createProvider()
    const checkIdentifier = vi.fn().mockResolvedValue({ allowed: true })
    const context = createMockContext(challengeStore, {
      abuse: { checkIdentifier },
    })

    await provider.initiate(createInitiateRequest("+1 (415) 555-0100"), context)

    expect(checkIdentifier).toHaveBeenCalledWith("sms", "+14155550100")
  })
})

const TEST_VERIFICATION_REFERENCE = "VE00000000000000000000000000000000"

function createVerificationTransport(
  check: VerificationCheck = { status: "approved" },
): VerificationTransport {
  return {
    startVerification: vi
      .fn()
      .mockResolvedValue({ ok: true, reference: TEST_VERIFICATION_REFERENCE }),
    checkVerification: vi.fn().mockResolvedValue(check),
  }
}

/** Initiate against a hosted verification service and return its cookie pair */
async function initiateVerification(
  provider: SmsProvider,
  context: AuthContext,
): Promise<string> {
  const result = await provider.initiate(createInitiateRequest(), context)
  if (result instanceof Response) throw new Error("unexpected Response")
  if (!result.success) throw new Error("initiate failed")

  const cookiePair = result.setCookies?.[0]?.split(";")[0]
  if (!cookiePair) throw new Error("no challenge cookie set")
  return cookiePair
}

describe("SmsProvider with a VerificationTransport", () => {
  let challengeStore: InMemoryChallengeStore
  let context: AuthContext

  beforeEach(() => {
    vi.clearAllMocks()
    challengeStore = new InMemoryChallengeStore()
    context = createMockContext(challengeStore)
  })

  afterEach(() => {
    challengeStore.destroy()
  })

  it("should delegate sending and store no code", async () => {
    const transport = createVerificationTransport()
    const provider = new SmsProvider({ appName: "Test App" }, transport)

    const cookie = await initiateVerification(provider, context)

    expect(transport.startVerification).toHaveBeenCalledWith(TEST_PHONE)

    const challenge = await challengeStore.findById(cookie.split("=")[1] ?? "")
    expect(challenge?.type).toBe("sms")
    expect(challenge?.identifier).toBe(TEST_PHONE)
    expect(challenge?.hashedCode).toBeUndefined()
    expect(challenge?.data).toEqual({
      verificationReference: TEST_VERIFICATION_REFERENCE,
    })
  })

  it("should fail initiate when the vendor will not send", async () => {
    const transport = createVerificationTransport()
    vi.mocked(transport.startVerification).mockResolvedValue({
      ok: false,
      message: "nope",
    })
    const provider = new SmsProvider({}, transport)

    const result = await provider.initiate(createInitiateRequest(), context)

    expect(result instanceof Response).toBe(false)
    if (result instanceof Response || result.success) {
      throw new Error("expected an initiate failure")
    }
    expect(result.error.code).toBe("PROVIDER_ERROR")
  })

  it("should not call the vendor when the number is throttled", async () => {
    const transport = createVerificationTransport()
    const provider = new SmsProvider({}, transport)
    const throttled = createMockContext(challengeStore, {
      abuse: {
        checkIdentifier: vi.fn().mockResolvedValue({
          allowed: false,
          event: {
            reason: "identifier_rate_limited",
            providerId: "sms",
            ip: null,
            identifier: TEST_PHONE,
            at: new Date(),
          },
        }),
      },
    })

    await provider.initiate(createInitiateRequest(), throttled)

    expect(transport.startVerification).not.toHaveBeenCalled()
  })

  it("should authenticate on approval and consume the challenge", async () => {
    const transport = createVerificationTransport()
    const provider = new SmsProvider({}, transport)
    const cookie = await initiateVerification(provider, context)

    const result = await verifyCode(provider, context, "123456", cookie)

    expect(transport.checkVerification).toHaveBeenCalledWith(
      TEST_PHONE,
      TEST_VERIFICATION_REFERENCE,
      "123456",
    )
    expect(result.success).toBe(true)
    if (!result.success) return
    expect(result.setCookies?.[0]).toContain("auth_sms_challenge=;")

    const replay = await verifyCode(provider, context, "123456", cookie)
    expect(replay.success).toBe(false)
  })

  it.each([
    ["invalid_code", "INVALID_CREDENTIALS"],
    ["expired", "EXPIRED_TOKEN"],
    ["rate_limited", "RATE_LIMITED"],
  ] as const)("should map %s to %s", async (status, expectedCode) => {
    const transport = createVerificationTransport({ status })
    const provider = new SmsProvider({}, transport)
    const cookie = await initiateVerification(provider, context)

    const result = await verifyCode(provider, context, "123456", cookie)

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe(expectedCode)
  })

  it("should report a vendor outage as a provider error, not a wrong code", async () => {
    const transport = createVerificationTransport({
      status: "error",
      message: "Twilio down",
    })
    const provider = new SmsProvider({}, transport)
    const cookie = await initiateVerification(provider, context)

    const result = await verifyCode(provider, context, "123456", cookie)

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("PROVIDER_ERROR")
  })

  it("should stop calling the vendor once attempts are exhausted", async () => {
    const transport = createVerificationTransport({ status: "invalid_code" })
    const provider = new SmsProvider(
      { otp: { maxAttempts: OTP_MAX_ATTEMPTS } },
      transport,
    )
    const cookie = await initiateVerification(provider, context)

    for (let attempt = 0; attempt < OTP_MAX_ATTEMPTS; attempt++) {
      await verifyCode(provider, context, "000000", cookie)
    }
    expect(transport.checkVerification).toHaveBeenCalledTimes(OTP_MAX_ATTEMPTS)

    const result = await verifyCode(provider, context, "000000", cookie)

    expect(transport.checkVerification).toHaveBeenCalledTimes(OTP_MAX_ATTEMPTS)
    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("RATE_LIMITED")
  })

  it("should reject an expired challenge without calling the vendor", async () => {
    const transport = createVerificationTransport()
    const provider = new SmsProvider({}, transport)
    const cookie = await initiateVerification(provider, context)

    const challenge = await challengeStore.findById(cookie.split("=")[1] ?? "")
    if (challenge) challenge.expiresAt = new Date(Date.now() - 1000)

    const result = await verifyCode(provider, context, "123456", cookie)

    expect(transport.checkVerification).not.toHaveBeenCalled()
    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("EXPIRED_TOKEN")
  })

  it("should reject when no challenge cookie is present", async () => {
    const transport = createVerificationTransport()
    const provider = new SmsProvider({}, transport)
    await initiateVerification(provider, context)

    const result = await verifyCode(provider, context, "123456")

    expect(transport.checkVerification).not.toHaveBeenCalled()
    expect(result.success).toBe(false)
  })
})

describe("describe", () => {
  it("reports the message settings when sending the code itself", () => {
    const settings = createProvider({ webOtpDomain: "example.com" }).describe()
      .settings

    expect(settings.transportKind).toBe("message sending")
    expect(settings.appName).toBe("Test App")
    expect(settings.expiry).toBe("10m")
    expect(settings["otp.length"]).toBe(6)
    expect(settings["otp.maxAttempts"]).toBe(OTP_MAX_ATTEMPTS)
    expect(settings.webOtpDomain).toBe("example.com")
    expect(settings.customMessageTemplate).toBe(false)
  })

  it("nulls the message settings under a hosted verification transport, which owns the message", () => {
    const provider = new SmsProvider(
      { appName: "Test App", webOtpDomain: "example.com" },
      {
        startVerification: vi.fn(),
        checkVerification: vi.fn(),
      },
    )

    const settings = provider.describe().settings

    expect(settings.transportKind).toBe("hosted verification")
    expect(settings.appName).toBeNull()
    expect(settings["otp.length"]).toBeNull()
    expect(settings.webOtpDomain).toBeNull()
    // still ours to enforce, so still reported
    expect(settings.expiry).toBe("10m")
    expect(settings["otp.maxAttempts"]).toBe(5)
  })

  it("names the transport class without exposing the transport itself", () => {
    const settings = createProvider().describe().settings

    expect(typeof settings.transport).toBe("string")
    for (const value of Object.values(settings)) {
      if (value === null) continue
      expect(typeof value).not.toBe("object")
    }
  })
})

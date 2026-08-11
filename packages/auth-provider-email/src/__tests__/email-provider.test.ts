/**
 * EmailProvider tests: challenge-backed magic links with the confirm-page
 * redemption flow.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { InMemoryChallengeStore } from "@activescott/auth"
import type { AuthContext, Identity } from "@activescott/auth"
import { EmailProvider } from "../email-provider.js"
import type { EmailTransport } from "../types.js"

const TEST_BASE_URL = "https://example.com"
const TEST_EMAIL = "user@example.com"

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

function createProvider(): EmailProvider {
  return new EmailProvider(
    {
      smtp: { host: "smtp.test.com", port: 587, user: "user", pass: "pass" },
      from: "test@example.com",
      template: { appName: "Test App" },
    },
    mockTransport,
  )
}

function createInitiateRequest(
  email = TEST_EMAIL,
  headers: Record<string, string> = {},
): Request {
  return new Request(`${TEST_BASE_URL}/auth/email/initiate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams({ email }).toString(),
  })
}

function lastMagicLink(): string {
  const calls = vi.mocked(mockTransport.sendMagicLink).mock.calls
  const link = calls.at(-1)?.[1]
  if (!link) throw new Error("no magic link sent")
  return link
}

function createRedeemRequest(magicLink: string): Request {
  const url = new URL(magicLink)
  const body = new URLSearchParams({
    challenge: url.searchParams.get("challenge") ?? "",
    key: url.searchParams.get("key") ?? "",
  })
  return new Request(magicLink, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  })
}

describe("EmailProvider", () => {
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

  describe("initiate", () => {
    it("should email a challenge-backed magic link", async () => {
      const result = await provider.initiate(createInitiateRequest(), context)

      expect(result instanceof Response).toBe(false)
      if (result instanceof Response || !result.success) {
        throw new Error("initiate failed")
      }

      const link = new URL(lastMagicLink())
      expect(link.pathname).toBe("/auth/email/verify")
      const challengeId = link.searchParams.get("challenge")
      expect(challengeId).toBeTruthy()
      expect(link.searchParams.get("key")).toBeTruthy()

      const challenge = await challengeStore.findById(challengeId ?? "")
      expect(challenge?.identifier).toBe(TEST_EMAIL)
      expect(challenge?.type).toBe("email")
      expect(typeof challenge?.data?.hashedKey).toBe("string")
    })

    it("should reject a missing email", async () => {
      const request = new Request(`${TEST_BASE_URL}/auth/email/initiate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      })
      const result = await provider.initiate(request, context)

      if (result instanceof Response) throw new Error("expected result")
      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("INVALID_CREDENTIALS")
    })

    it("should reject an invalid email format", async () => {
      const result = await provider.initiate(
        createInitiateRequest("not-an-email"),
        context,
      )

      if (result instanceof Response) throw new Error("expected result")
      expect(result.success).toBe(false)
    })

    it("should redirect browser form posts back to the submitting page", async () => {
      const request = createInitiateRequest(TEST_EMAIL, {
        Accept: "text/html",
        Referer: `${TEST_BASE_URL}/login`,
      })
      const result = await provider.initiate(request, context)

      if (!(result instanceof Response)) throw new Error("expected redirect")
      expect(result.status).toBe(302)
      const location = result.headers.get("Location") ?? ""
      expect(location).toContain("/login")
      expect(location).toContain("sent=1")
      expect(result.headers.get("Set-Cookie")).toContain("auth_challenge=")
    })

    it("should redirect browser form posts with an error code on failure", async () => {
      const request = createInitiateRequest("not-an-email", {
        Accept: "text/html",
        Referer: `${TEST_BASE_URL}/login`,
      })
      const result = await provider.initiate(request, context)

      if (!(result instanceof Response)) throw new Error("expected redirect")
      expect(result.status).toBe(302)
      expect(result.headers.get("Location")).toContain(
        "error=INVALID_CREDENTIALS",
      )
    })

    it("should return JSON-style results with setCookies for non-browser callers", async () => {
      const result = await provider.initiate(createInitiateRequest(), context)

      if (result instanceof Response || !result.success) {
        throw new Error("initiate failed")
      }
      expect(result.setCookies?.[0]).toContain("auth_challenge=")
      expect(result.setCookies?.[0]).toContain("HttpOnly")
    })
  })

  describe("magic link confirm flow", () => {
    it("should render a confirm page on GET without consuming the link", async () => {
      await provider.initiate(createInitiateRequest(), context)
      const magicLink = lastMagicLink()

      const first = await provider.verify(new Request(magicLink), context)
      if (!(first instanceof Response)) throw new Error("expected page")
      expect(first.status).toBe(200)
      const html = await first.text()
      expect(html).toContain("Confirm sign-in")
      expect(html).toContain(TEST_EMAIL)

      // A scanner can GET repeatedly; the link must survive
      const second = await provider.verify(new Request(magicLink), context)
      expect(second instanceof Response).toBe(true)
    })

    it("should redeem on POST and consume the challenge", async () => {
      await provider.initiate(createInitiateRequest(), context)
      const magicLink = lastMagicLink()

      const result = await provider.verify(
        createRedeemRequest(magicLink),
        context,
      )
      if (result instanceof Response) throw new Error("expected result")
      expect(result.success).toBe(true)
      if (!result.success) return
      expect(result.user.id).toBe("user-1")

      // Single use: the link is dead after redemption
      const replay = await provider.verify(
        createRedeemRequest(magicLink),
        context,
      )
      if (replay instanceof Response) throw new Error("expected result")
      expect(replay.success).toBe(false)
    })

    it("should reject a tampered key", async () => {
      await provider.initiate(createInitiateRequest(), context)
      const url = new URL(lastMagicLink())
      url.searchParams.set("key", "wrong-key-entirely")

      const result = await provider.verify(
        createRedeemRequest(url.toString()),
        context,
      )
      if (result instanceof Response) throw new Error("expected result")
      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("INVALID_TOKEN")
    })

    it("should reject an expired link", async () => {
      await provider.initiate(createInitiateRequest(), context)
      const magicLink = lastMagicLink()
      const challengeId = new URL(magicLink).searchParams.get("challenge") ?? ""
      const challenge = await challengeStore.findById(challengeId)
      if (challenge) challenge.expiresAt = new Date(Date.now() - 1000)

      const result = await provider.verify(
        createRedeemRequest(magicLink),
        context,
      )
      if (result instanceof Response) throw new Error("expected result")
      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("EXPIRED_TOKEN")
    })

    it("should fail a GET without challenge params", async () => {
      const result = await provider.verify(
        new Request(`${TEST_BASE_URL}/auth/email/verify?token=old-style`),
        context,
      )
      if (result instanceof Response) throw new Error("expected result")
      expect(result.success).toBe(false)
    })
  })

  describe("user and identity handling", () => {
    it("should create user and identity for a new email", async () => {
      const emptyIdentityContext = createMockContext(challengeStore, {
        identityStore: {
          findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
          findByUserId: vi.fn().mockResolvedValue([]),
          create: vi.fn().mockResolvedValue(createMockIdentity()),
          update: vi.fn().mockResolvedValue(createMockIdentity()),
        },
      })

      await provider.initiate(createInitiateRequest(), emptyIdentityContext)
      const result = await provider.verify(
        createRedeemRequest(lastMagicLink()),
        emptyIdentityContext,
      )

      if (result instanceof Response) throw new Error("expected result")
      expect(result.success).toBe(true)
      expect(emptyIdentityContext.userStore.create).toHaveBeenCalledWith({
        provider: "email",
        identifier: TEST_EMAIL,
      })
      expect(emptyIdentityContext.identityStore.create).toHaveBeenCalledTimes(1)
    })

    it("should update verifiedAt for an existing identity", async () => {
      await provider.initiate(createInitiateRequest(), context)
      await provider.verify(createRedeemRequest(lastMagicLink()), context)

      expect(context.identityStore.update).toHaveBeenCalledWith(
        "identity-1",
        expect.objectContaining({ verifiedAt: expect.any(Date) }),
      )
    })

    it("should fail when the identity's user no longer exists", async () => {
      const orphanContext = createMockContext(challengeStore, {
        userStore: {
          findById: vi.fn().mockResolvedValue(null),
          create: vi.fn(),
        },
      })

      await provider.initiate(createInitiateRequest(), orphanContext)
      const result = await provider.verify(
        createRedeemRequest(lastMagicLink()),
        orphanContext,
      )

      if (result instanceof Response) throw new Error("expected result")
      expect(result.success).toBe(false)
      if (result.success) return
      expect(result.error.code).toBe("USER_NOT_FOUND")
    })
  })
})

describe("EmailProvider per-recipient throttling", () => {
  let challengeStore: InMemoryChallengeStore

  beforeEach(() => {
    vi.clearAllMocks()
    challengeStore = new InMemoryChallengeStore()
  })

  afterEach(() => {
    challengeStore.destroy()
  })

  it("sends nothing when the recipient is throttled", async () => {
    const provider = createProvider()
    const context = createMockContext(challengeStore, {
      abuse: {
        checkIdentifier: vi.fn().mockResolvedValue({
          allowed: false,
          event: {
            reason: "identifier_rate_limited",
            providerId: "email",
            ip: null,
            identifier: TEST_EMAIL,
            at: new Date(),
          },
        }),
      },
    })

    const result = await provider.initiate(createInitiateRequest(), context)

    expect(mockTransport.sendMagicLink).not.toHaveBeenCalled()
    expect(result).toEqual({
      success: true,
      message: provider.initiateSentMessage,
      setCookies: [],
    })
  })

  it("answers a throttled browser form post exactly like a sent one", async () => {
    const provider = createProvider()
    const sentContext = createMockContext(challengeStore)
    const throttledContext = createMockContext(challengeStore, {
      abuse: {
        checkIdentifier: vi.fn().mockResolvedValue({
          allowed: false,
          event: {
            reason: "identifier_rate_limited",
            providerId: "email",
            ip: null,
            identifier: TEST_EMAIL,
            at: new Date(),
          },
        }),
      },
    })
    const headers = { Accept: "text/html", Referer: `${TEST_BASE_URL}/login` }

    const sent = await provider.initiate(
      createInitiateRequest(TEST_EMAIL, headers),
      sentContext,
    )
    const throttled = await provider.initiate(
      createInitiateRequest(TEST_EMAIL, headers),
      throttledContext,
    )

    expect(sent).toBeInstanceOf(Response)
    expect(throttled).toBeInstanceOf(Response)
    if (!(sent instanceof Response) || !(throttled instanceof Response)) return
    expect(throttled.status).toBe(sent.status)
    expect(throttled.headers.get("Location")).toBe(sent.headers.get("Location"))
    // The one difference is invisible to the caller's eyes on the page: no
    // challenge exists, so no challenge cookie is set
    expect(throttled.headers.get("Set-Cookie")).toBeNull()
  })

  it("passes the normalized address to the abuse check", async () => {
    const provider = createProvider()
    const checkIdentifier = vi.fn().mockResolvedValue({ allowed: true })
    const context = createMockContext(challengeStore, {
      abuse: { checkIdentifier },
    })

    await provider.initiate(
      createInitiateRequest("  USER@Example.com "),
      context,
    )

    expect(checkIdentifier).toHaveBeenCalledWith("email", TEST_EMAIL)
  })
})

describe("describe", () => {
  it("reports the non-secret settings with defaults resolved", () => {
    const settings = createProvider().describe().settings

    expect(settings.from).toBe("test@example.com")
    expect(settings.expiry).toBe("15m")
    expect(settings["otp.length"]).toBe(6)
    expect(settings["otp.maxAttempts"]).toBe(5)
    expect(settings["template.appName"]).toBe("Test App")
    expect(settings["smtp.host"]).toBe("smtp.test.com")
    expect(settings["smtp.port"]).toBe(587)
  })

  it("omits the SMTP credentials", () => {
    const settings = createProvider().describe().settings

    expect(Object.keys(settings)).not.toContain("smtp.pass")
    expect(Object.keys(settings)).not.toContain("smtp.user")
    expect(JSON.stringify(settings)).not.toContain("pass")
  })
})

describe("EmailProvider link mode", () => {
  let provider: EmailProvider
  let challengeStore: InMemoryChallengeStore

  const sessionUser = { id: "user-2" }
  const session = {
    user: sessionUser,
    identity: createMockIdentity({ id: "identity-2", userId: "user-2" }),
  }

  beforeEach(() => {
    vi.clearAllMocks()
    provider = createProvider()
    challengeStore = new InMemoryChallengeStore()
  })

  afterEach(() => {
    challengeStore.destroy()
  })

  function createLinkInitiateRequest(email = TEST_EMAIL): Request {
    return new Request(`${TEST_BASE_URL}/auth/email/initiate`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ email, mode: "link" }).toString(),
    })
  }

  it("should refuse initiate without a session", async () => {
    const context = createMockContext(challengeStore, {
      getSession: vi.fn().mockResolvedValue(null),
    })

    const result = await provider.initiate(createLinkInitiateRequest(), context)

    if (result instanceof Response) throw new Error("expected a result object")
    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("SESSION_INVALID")
    expect(mockTransport.sendMagicLink).not.toHaveBeenCalled()
  })

  it("should stamp the challenge with the session user id", async () => {
    const context = createMockContext(challengeStore, {
      getSession: vi.fn().mockResolvedValue(session),
    })

    await provider.initiate(createLinkInitiateRequest(), context)

    const challengeId =
      new URL(lastMagicLink()).searchParams.get("challenge") ?? ""
    const challenge = await challengeStore.findById(challengeId)
    expect(challenge?.data?.linkUserId).toBe("user-2")
  })

  it("should link a new email to the session user on verify", async () => {
    const linked = createMockIdentity({
      id: "identity-3",
      userId: "user-2",
      identifier: TEST_EMAIL,
    })
    const context = createMockContext(challengeStore, {
      getSession: vi.fn().mockResolvedValue(session),
      identityStore: {
        findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
        findByUserId: vi.fn().mockResolvedValue([]),
        create: vi.fn().mockResolvedValue(linked),
        update: vi.fn().mockResolvedValue(linked),
      },
    })

    await provider.initiate(createLinkInitiateRequest(), context)
    const result = await provider.verify(
      createRedeemRequest(lastMagicLink()),
      context,
    )

    if (result instanceof Response) throw new Error("expected a result object")
    expect(result.success).toBe(true)
    if (!result.success) return
    expect(result.user.id).toBe("user-2")
    expect(context.identityStore.create).toHaveBeenCalledWith({
      userId: "user-2",
      provider: "email",
      identifier: TEST_EMAIL,
      metadata: {},
    })
    // Linking never creates a user from the identifier
    expect(context.userStore.create).not.toHaveBeenCalled()
  })

  it("should answer IDENTITY_CONFLICT with a merge ticket when the email belongs to another user", async () => {
    const context = createMockContext(challengeStore, {
      getSession: vi.fn().mockResolvedValue(session),
      identityStore: {
        findByProviderAndIdentifier: vi
          .fn()
          .mockResolvedValue(createMockIdentity({ userId: "user-9" })),
        findByUserId: vi.fn().mockResolvedValue([]),
        create: vi.fn(),
        update: vi.fn(),
      },
    })

    await provider.initiate(createLinkInitiateRequest(), context)
    const result = await provider.verify(
      createRedeemRequest(lastMagicLink()),
      context,
    )

    if (result instanceof Response) throw new Error("expected a result object")
    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("IDENTITY_CONFLICT")
    expect(context.identityStore.create).not.toHaveBeenCalled()

    const cookies = result.setCookies ?? []
    expect(
      cookies.some((cookie) => cookie.startsWith("auth_merge_ticket=")),
    ).toBe(true)
    // The consumed challenge's cookie is cleared alongside the ticket
    expect(
      cookies.some(
        (cookie) =>
          cookie.startsWith("auth_challenge=;") && cookie.includes("Max-Age=0"),
      ),
    ).toBe(true)
  })

  it("should render link wording on the confirm page", async () => {
    const context = createMockContext(challengeStore, {
      getSession: vi.fn().mockResolvedValue(session),
    })

    await provider.initiate(createLinkInitiateRequest(), context)
    const response = await provider.verify(
      new Request(lastMagicLink()),
      context,
    )

    if (!(response instanceof Response)) throw new Error("expected a page")
    const html = await response.text()
    expect(html).toContain("Link your email")
    expect(html).toContain("Confirm link")
  })
})

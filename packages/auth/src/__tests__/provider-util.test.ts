import { describe, it, expect, vi } from "vitest"
import {
  parseRequestBody,
  isBrowserFormPost,
  buildReturnUrl,
  buildChallengeCookie,
  buildChallengeClearingCookie,
  readCookie,
  parseDuration,
  authenticateWithIdentifier,
  completeLinkVerification,
  linkUserIdFromChallenge,
  resolveRedirectTarget,
} from "../provider-util.js"
import type { AuthContext, Identity } from "../types.js"
import { InMemoryChallengeStore } from "../stores/in-memory-challenge-store.js"

const TEST_URL = "https://example.com/auth/sms/initiate"

function createMockIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: "identity-1",
    userId: "user-1",
    provider: "sms",
    identifier: "+14155550100",
    providerState: {},
    createdAt: new Date(),
    ...overrides,
  }
}

function createMockContext(overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    baseUrl: "https://example.com",
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
    challengeStore: new InMemoryChallengeStore(),
    ...overrides,
  }
}

describe("parseRequestBody", () => {
  it("should parse JSON bodies", async () => {
    const request = new Request(TEST_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone: "+14155550100" }),
    })
    expect(await parseRequestBody(request)).toEqual({ phone: "+14155550100" })
  })

  it("should parse urlencoded bodies", async () => {
    const request = new Request(TEST_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ code: "123456" }).toString(),
    })
    expect(await parseRequestBody(request)).toEqual({ code: "123456" })
  })

  it("should return an empty object for unparseable bodies", async () => {
    const request = new Request(TEST_URL, { method: "POST", body: "not-json" })
    expect(await parseRequestBody(request)).toEqual({})
  })
})

describe("isBrowserFormPost", () => {
  it("should detect a browser form post", () => {
    const request = new Request(TEST_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "text/html,application/xhtml+xml",
      },
    })
    expect(isBrowserFormPost(request)).toBe(true)
  })

  it("should not match JSON/fetch callers", () => {
    const request = new Request(TEST_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "*/*" },
    })
    expect(isBrowserFormPost(request)).toBe(false)
  })
})

describe("buildReturnUrl", () => {
  it("should merge params onto the referer", () => {
    const request = new Request(TEST_URL, {
      headers: { Referer: "https://example.com/login?theme=dark" },
    })
    const url = new URL(buildReturnUrl(request, { sent: "1" }))
    expect(url.pathname).toBe("/login")
    expect(url.searchParams.get("theme")).toBe("dark")
    expect(url.searchParams.get("sent")).toBe("1")
  })

  it("should fall back to /login without a referer", () => {
    const request = new Request(TEST_URL)
    const url = new URL(buildReturnUrl(request, { error: "RATE_LIMITED" }))
    expect(url.pathname).toBe("/login")
    expect(url.searchParams.get("error")).toBe("RATE_LIMITED")
  })

  it("should fall back to /login when the referer is another origin", () => {
    const request = new Request(TEST_URL, {
      headers: { Referer: "https://other.example/login" },
    })
    const url = new URL(buildReturnUrl(request, { error: "RATE_LIMITED" }))
    expect(url.origin).toBe("https://example.com")
    expect(url.pathname).toBe("/login")
  })
})

describe("resolveRedirectTarget", () => {
  const FALLBACK = "/dashboard"

  it("should keep a same-origin path with its query and hash", () => {
    expect(
      resolveRedirectTarget("/settings?tab=email#top", TEST_URL, FALLBACK),
    ).toBe("/settings?tab=email#top")
  })

  it("should reduce an absolute same-origin URL to a path", () => {
    expect(
      resolveRedirectTarget(
        "https://example.com/settings?tab=email",
        TEST_URL,
        FALLBACK,
      ),
    ).toBe("/settings?tab=email")
  })

  it("should use the fallback for another origin", () => {
    expect(
      resolveRedirectTarget("https://other.example/x", TEST_URL, FALLBACK),
    ).toBe(FALLBACK)
  })

  it("should use the fallback for a protocol-relative destination", () => {
    expect(resolveRedirectTarget("//other.example", TEST_URL, FALLBACK)).toBe(
      FALLBACK,
    )
  })

  it("should use the fallback for a backslash-prefixed destination", () => {
    expect(resolveRedirectTarget("/\\other.example", TEST_URL, FALLBACK)).toBe(
      FALLBACK,
    )
    expect(resolveRedirectTarget("\\/other.example", TEST_URL, FALLBACK)).toBe(
      FALLBACK,
    )
  })

  it("should use the fallback for a javascript: destination", () => {
    expect(
      resolveRedirectTarget("javascript:alert(1)", TEST_URL, FALLBACK),
    ).toBe(FALLBACK)
  })

  it("should use the fallback for empty and unparseable input", () => {
    expect(resolveRedirectTarget(undefined, TEST_URL, FALLBACK)).toBe(FALLBACK)
    expect(resolveRedirectTarget(null, TEST_URL, FALLBACK)).toBe(FALLBACK)
    expect(resolveRedirectTarget("", TEST_URL, FALLBACK)).toBe(FALLBACK)
    expect(resolveRedirectTarget("/ok", "not a url", FALLBACK)).toBe(FALLBACK)
  })
})

describe("resolveRedirectTarget logging", () => {
  const FALLBACK = "/dashboard"

  function recordingLogger(): {
    warn: (message: string, context?: Record<string, unknown>) => void
    calls: { message: string; context?: Record<string, unknown> }[]
  } {
    const calls: { message: string; context?: Record<string, unknown> }[] = []
    return {
      calls,
      warn: (message, context) => calls.push({ message, context }),
    }
  }

  it("should warn once with the source and the origin of the declined value", () => {
    const logger = recordingLogger()
    expect(
      resolveRedirectTarget("https://other.example/x", TEST_URL, FALLBACK, {
        logger,
        source: "redirectTo",
      }),
    ).toBe(FALLBACK)
    expect(logger.calls).toHaveLength(1)
    expect(logger.calls[0]?.context).toMatchObject({
      source: "redirectTo",
      reason: "other-origin",
      origin: "https://other.example",
      fallback: FALLBACK,
    })
  })

  it("should keep the declined value's path and query out of the log", () => {
    const logger = recordingLogger()
    resolveRedirectTarget(
      "https://other.example/collect?key=s3cret-link-key",
      TEST_URL,
      FALLBACK,
      { logger, source: "redirectTo" },
    )
    expect(JSON.stringify(logger.calls)).not.toContain("s3cret-link-key")
  })

  it("should leave the fallback out when the caller has none yet", () => {
    const logger = recordingLogger()
    resolveRedirectTarget("https://other.example/x", TEST_URL, "", {
      logger,
      source: "redirectTo",
    })
    expect(logger.calls[0]?.context).not.toHaveProperty("fallback")
  })

  it("should report the scheme when that is what was wrong", () => {
    const logger = recordingLogger()
    resolveRedirectTarget("javascript:alert(1)", TEST_URL, FALLBACK, {
      logger,
      source: "redirectTo",
    })
    expect(logger.calls[0]?.context).toMatchObject({
      reason: "scheme",
      scheme: "javascript:",
    })
  })

  it("should warn for an unparseable value", () => {
    const logger = recordingLogger()
    resolveRedirectTarget("/ok", "not a url", FALLBACK, { logger })
    expect(logger.calls[0]?.context).toMatchObject({ reason: "unparseable" })
  })

  it("should stay quiet for a destination on this origin", () => {
    const logger = recordingLogger()
    resolveRedirectTarget("/settings?tab=email", TEST_URL, FALLBACK, { logger })
    resolveRedirectTarget("https://example.com/settings", TEST_URL, FALLBACK, {
      logger,
    })
    expect(logger.calls).toEqual([])
  })

  it("should stay quiet when there is no destination to decline", () => {
    const logger = recordingLogger()
    resolveRedirectTarget(undefined, TEST_URL, FALLBACK, { logger })
    resolveRedirectTarget(null, TEST_URL, FALLBACK, { logger })
    resolveRedirectTarget("", TEST_URL, FALLBACK, { logger })
    expect(logger.calls).toEqual([])
  })

  it("should log nowhere when no logger is configured", () => {
    const consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => {})
    try {
      expect(
        resolveRedirectTarget("https://other.example/x", TEST_URL, FALLBACK),
      ).toBe(FALLBACK)
      expect(
        resolveRedirectTarget("https://other.example/x", TEST_URL, FALLBACK, {
          source: "redirectTo",
        }),
      ).toBe(FALLBACK)
      expect(consoleWarn).not.toHaveBeenCalled()
    } finally {
      consoleWarn.mockRestore()
    }
  })

  it("should name the Referer as the source from buildReturnUrl", () => {
    const logger = recordingLogger()
    const request = new Request(TEST_URL, {
      headers: { Referer: "https://other.example/login" },
    })
    const url = new URL(buildReturnUrl(request, { sent: "1" }, logger))
    expect(url.pathname).toBe("/login")
    expect(logger.calls).toHaveLength(1)
    expect(logger.calls[0]?.context).toMatchObject({
      source: "Referer",
      reason: "other-origin",
      origin: "https://other.example",
    })
  })

  it("should stay quiet from buildReturnUrl when there is no Referer", () => {
    const logger = recordingLogger()
    buildReturnUrl(new Request(TEST_URL), { sent: "1" }, logger)
    expect(logger.calls).toEqual([])
  })
})

describe("challenge cookies", () => {
  it("should build a scoped HttpOnly cookie, Secure on https", () => {
    const cookie = buildChallengeCookie(
      "auth_challenge",
      "chal-1",
      900,
      "https://example.com",
    )
    expect(cookie).toContain("auth_challenge=chal-1")
    expect(cookie).toContain("Path=/auth")
    expect(cookie).toContain("HttpOnly")
    expect(cookie).toContain("Max-Age=900")
    expect(cookie).toContain("Secure")
  })

  it("should omit Secure on http", () => {
    const cookie = buildChallengeCookie(
      "auth_challenge",
      "chal-1",
      900,
      "http://localhost:3000",
    )
    expect(cookie).not.toContain("Secure")
  })

  it("should build a clearing cookie with Max-Age=0", () => {
    const cookie = buildChallengeClearingCookie(
      "auth_challenge",
      "https://example.com",
    )
    expect(cookie).toContain("auth_challenge=;")
    expect(cookie).toContain("Max-Age=0")
  })

  it("should read a cookie back from a request", () => {
    const request = new Request(TEST_URL, {
      headers: { Cookie: "other=x; auth_challenge=chal-1" },
    })
    expect(readCookie(request, "auth_challenge")).toBe("chal-1")
    expect(readCookie(request, "missing")).toBeNull()
  })
})

describe("parseDuration", () => {
  it.each([
    ["30s", 30],
    ["15m", 900],
    ["24h", 86_400],
    ["30d", 2_592_000],
    ["garbage", 0],
  ])("should parse %s to %d seconds", (input, expected) => {
    expect(parseDuration(input)).toBe(expected)
  })
})

describe("authenticateWithIdentifier", () => {
  it("should return the existing user for a known identifier", async () => {
    const context = createMockContext()
    const result = await authenticateWithIdentifier(
      "sms",
      "+14155550100",
      context,
    )

    expect(result.success).toBe(true)
    if (!result.success) return
    expect(result.user.id).toBe("user-1")
    expect(context.userStore.create).not.toHaveBeenCalled()
  })

  it("should create user and identity for a new identifier", async () => {
    const context = createMockContext({
      identityStore: {
        findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
        findByUserId: vi.fn().mockResolvedValue([]),
        create: vi.fn().mockResolvedValue(createMockIdentity()),
        update: vi.fn().mockResolvedValue(createMockIdentity()),
      },
    })

    const result = await authenticateWithIdentifier(
      "sms",
      "+14155550100",
      context,
    )

    expect(result.success).toBe(true)
    expect(context.userStore.create).toHaveBeenCalledWith({
      provider: "sms",
      identifier: "+14155550100",
    })
    expect(context.identityStore.create).toHaveBeenCalledWith({
      userId: "user-1",
      provider: "sms",
      identifier: "+14155550100",
      providerState: {},
    })
  })

  it("should update verifiedAt on success", async () => {
    const context = createMockContext()
    await authenticateWithIdentifier("sms", "+14155550100", context)

    expect(context.identityStore.update).toHaveBeenCalledWith(
      "identity-1",
      expect.objectContaining({ verifiedAt: expect.any(Date) }),
    )
  })

  it("should return the identity as the store holds it after the update", async () => {
    // a store that persists, so verifiedAt is absent until the update lands
    const stored = new Map<string, Identity>()
    const context = createMockContext({
      userStore: {
        findById: vi.fn().mockResolvedValue(null),
        create: vi.fn().mockResolvedValue({ id: "user-1" }),
      },
      identityStore: {
        findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
        findByUserId: vi.fn().mockResolvedValue([]),
        create: vi.fn(async () => {
          const identity = createMockIdentity({ verifiedAt: undefined })
          stored.set(identity.id, identity)
          return identity
        }),
        update: vi.fn(async (id: string, data: Partial<Identity>) => {
          const updated = { ...stored.get(id)!, ...data }
          stored.set(id, updated)
          return updated
        }),
      },
    })

    const result = await authenticateWithIdentifier(
      "sms",
      "+14155550100",
      context,
    )

    expect(result.success).toBe(true)
    if (!result.success) return
    expect(result.identity.verifiedAt).toBeInstanceOf(Date)
    expect(result.identity).toEqual(stored.get(result.identity.id))
  })

  it("should fail when the identity's user no longer exists", async () => {
    const context = createMockContext({
      userStore: {
        findById: vi.fn().mockResolvedValue(null),
        create: vi.fn(),
      },
    })

    const result = await authenticateWithIdentifier(
      "sms",
      "+14155550100",
      context,
    )

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("USER_NOT_FOUND")
  })
})

describe("linkUserIdFromChallenge", () => {
  it("should return the stamped user id", () => {
    expect(linkUserIdFromChallenge({ data: { linkUserId: "user-1" } })).toBe(
      "user-1",
    )
  })

  it("should return undefined for sign-in challenges", () => {
    expect(linkUserIdFromChallenge({ data: undefined })).toBeUndefined()
    expect(linkUserIdFromChallenge({ data: {} })).toBeUndefined()
    expect(
      linkUserIdFromChallenge({ data: { linkUserId: 42 } }),
    ).toBeUndefined()
  })
})

describe("completeLinkVerification", () => {
  const LINK_REQUEST = new Request("https://example.com/auth/sms/verify", {
    method: "POST",
  })

  function createLinkContext(
    overrides: Partial<AuthContext> = {},
  ): AuthContext {
    return createMockContext({
      getSession: vi.fn().mockResolvedValue({
        user: { id: "user-1" },
        identity: createMockIdentity(),
      }),
      ...overrides,
    })
  }

  it("should report a configuration error without getSession", async () => {
    const context = createLinkContext({ getSession: undefined })

    const result = await completeLinkVerification(
      "sms",
      "+14155550100",
      "user-1",
      LINK_REQUEST,
      context,
    )

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("CONFIGURATION_ERROR")
  })

  it("should fail without a session", async () => {
    const context = createLinkContext({
      getSession: vi.fn().mockResolvedValue(null),
    })

    const result = await completeLinkVerification(
      "sms",
      "+14155550100",
      "user-1",
      LINK_REQUEST,
      context,
    )

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("SESSION_INVALID")
  })

  it("should fail when the session user differs from the challenge's", async () => {
    const context = createLinkContext({
      getSession: vi.fn().mockResolvedValue({
        user: { id: "user-2" },
        identity: createMockIdentity({ userId: "user-2" }),
      }),
    })

    const result = await completeLinkVerification(
      "sms",
      "+14155550100",
      "user-1",
      LINK_REQUEST,
      context,
    )

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("SESSION_INVALID")
  })

  it("should create the identity for the session user when the identifier is new", async () => {
    const linked = createMockIdentity({
      id: "identity-2",
      provider: "sms",
      identifier: "+14155550100",
      verifiedAt: new Date(),
    })
    const context = createLinkContext({
      identityStore: {
        findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
        findByUserId: vi.fn().mockResolvedValue([]),
        create: vi.fn().mockResolvedValue(linked),
        update: vi.fn().mockResolvedValue(linked),
      },
    })

    const result = await completeLinkVerification(
      "sms",
      "+14155550100",
      "user-1",
      LINK_REQUEST,
      context,
    )

    expect(result.success).toBe(true)
    if (!result.success) return
    expect(result.user.id).toBe("user-1")
    expect(result.identity.id).toBe("identity-2")
    expect(context.identityStore.create).toHaveBeenCalledWith({
      userId: "user-1",
      provider: "sms",
      identifier: "+14155550100",
      providerState: {},
    })
    // No user was created or resolved from the identifier
    expect(context.userStore.create).not.toHaveBeenCalled()
  })

  it("should be idempotent when the identifier is already on the session user", async () => {
    const existing = createMockIdentity({
      provider: "sms",
      identifier: "+14155550100",
    })
    const context = createLinkContext({
      identityStore: {
        findByProviderAndIdentifier: vi.fn().mockResolvedValue(existing),
        findByUserId: vi.fn().mockResolvedValue([existing]),
        create: vi.fn(),
        update: vi.fn().mockResolvedValue(existing),
      },
    })

    const result = await completeLinkVerification(
      "sms",
      "+14155550100",
      "user-1",
      LINK_REQUEST,
      context,
    )

    expect(result.success).toBe(true)
    expect(context.identityStore.create).not.toHaveBeenCalled()
    expect(context.identityStore.update).toHaveBeenCalledWith(
      "identity-1",
      expect.objectContaining({ verifiedAt: expect.any(Date) }),
    )
  })

  it("should mint a merge ticket when the identifier belongs to another user", async () => {
    const otherUsers = createMockIdentity({
      id: "identity-9",
      userId: "user-9",
      provider: "sms",
      identifier: "+14155550100",
    })
    const challengeStore = new InMemoryChallengeStore()
    const context = createLinkContext({
      challengeStore,
      identityStore: {
        findByProviderAndIdentifier: vi.fn().mockResolvedValue(otherUsers),
        findByUserId: vi.fn().mockResolvedValue([]),
        create: vi.fn(),
        update: vi.fn(),
      },
    })

    const result = await completeLinkVerification(
      "sms",
      "+14155550100",
      "user-1",
      LINK_REQUEST,
      context,
    )

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("IDENTITY_CONFLICT")
    expect(context.identityStore.create).not.toHaveBeenCalled()

    const cookie = result.setCookies?.find((value) =>
      value.startsWith("auth_merge_ticket="),
    )
    expect(cookie).toBeDefined()
    expect(cookie).toContain("HttpOnly")

    const ticketId = cookie?.split(";")[0]?.split("=")[1] ?? ""
    const ticket = await challengeStore.findById(ticketId)
    expect(ticket?.type).toBe("account-merge")
    expect(ticket?.data).toEqual({
      fromUserId: "user-9",
      intoUserId: "user-1",
      provider: "sms",
    })
  })
})

describe("completeLinkVerification onIdentityLinked hook", () => {
  const LINK_REQUEST = new Request("https://example.com/auth/sms/verify", {
    method: "POST",
  })

  it("should notify the user store when a new identifier is linked", async () => {
    const onIdentityLinked = vi.fn()
    const linked = createMockIdentity({
      id: "identity-2",
      identifier: "+14155550100",
    })
    const context = createMockContext({
      getSession: vi.fn().mockResolvedValue({
        user: { id: "user-1" },
        identity: createMockIdentity(),
      }),
      userStore: {
        findById: vi.fn(),
        create: vi.fn(),
        onIdentityLinked,
      },
      identityStore: {
        findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
        findByUserId: vi.fn().mockResolvedValue([]),
        create: vi.fn().mockResolvedValue(linked),
        update: vi.fn().mockResolvedValue(linked),
      },
    })

    const result = await completeLinkVerification(
      "sms",
      "+14155550100",
      "user-1",
      LINK_REQUEST,
      context,
    )

    expect(result.success).toBe(true)
    expect(onIdentityLinked).toHaveBeenCalledWith({ id: "user-1" }, linked)
  })

  it("should not notify when the identifier was already linked", async () => {
    const onIdentityLinked = vi.fn()
    const existing = createMockIdentity({ identifier: "+14155550100" })
    const context = createMockContext({
      getSession: vi.fn().mockResolvedValue({
        user: { id: "user-1" },
        identity: existing,
      }),
      userStore: {
        findById: vi.fn(),
        create: vi.fn(),
        onIdentityLinked,
      },
      identityStore: {
        findByProviderAndIdentifier: vi.fn().mockResolvedValue(existing),
        findByUserId: vi.fn().mockResolvedValue([existing]),
        create: vi.fn(),
        update: vi.fn().mockResolvedValue(existing),
      },
    })

    const result = await completeLinkVerification(
      "sms",
      "+14155550100",
      "user-1",
      LINK_REQUEST,
      context,
    )

    expect(result.success).toBe(true)
    expect(onIdentityLinked).not.toHaveBeenCalled()
  })
})

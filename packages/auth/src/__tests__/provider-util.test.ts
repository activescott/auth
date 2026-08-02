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
    metadata: {},
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
      metadata: {},
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

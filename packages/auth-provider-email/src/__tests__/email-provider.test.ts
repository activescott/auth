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

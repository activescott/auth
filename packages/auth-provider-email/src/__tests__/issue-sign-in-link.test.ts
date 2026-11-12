/**
 * EmailProvider.issueSignInLink: a sign-in link minted server-side for
 * someone other than the requester (an invite), redeemed through the
 * ordinary verify route from whatever browser opens the email.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import type { AuthLogger, Identity, InitiateGate } from "@activescott/auth"
import { EmailProvider } from "../email-provider.js"
import type { EmailTransport } from "../types.js"

const BASE_URL = "https://example.com"
const INVITER_EMAIL = "inviter@example.com"
const INVITEE_EMAIL = "invitee@example.com"
const SECONDS_PER_DAY = 86_400
const MS_PER_SECOND = 1000

const transport: EmailTransport = {
  sendMagicLink: vi.fn().mockResolvedValue(true),
}

function identityFor(identifier: string, userId: string): Identity {
  return {
    id: `identity-${userId}`,
    userId,
    provider: "email",
    identifier,
    providerState: {},
    createdAt: new Date(),
  }
}

interface Harness {
  auth: Auth
  provider: EmailProvider
  challengeStore: InMemoryChallengeStore
  logger: AuthLogger & { warn: ReturnType<typeof vi.fn> }
}

function createHarness(gate?: InitiateGate): Harness {
  const provider = new EmailProvider(
    {
      smtp: { host: "smtp.test.com", port: 587, user: "user", pass: "pass" },
      from: "test@example.com",
      template: { appName: "Test App" },
    },
    transport,
  )
  const challengeStore = new InMemoryChallengeStore()
  const logger = { warn: vi.fn() }
  const invitee = identityFor(INVITEE_EMAIL, "user-invitee")
  const auth = new Auth({
    session: {
      secret: "test-session-secret",
      maxAge: "7d",
      cookieName: "auth_session",
      cookie: { secure: false, sameSite: "lax" },
    },
    userStore: {
      findById: vi.fn().mockResolvedValue({ id: "user-invitee" }),
      create: vi.fn().mockResolvedValue({ id: "user-invitee" }),
      onMerge: vi.fn(),
    },
    identityStore: {
      // The invitee has no account yet: the link signs them up
      findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
      findByUserId: vi.fn().mockResolvedValue([invitee]),
      create: vi.fn().mockResolvedValue(invitee),
      update: vi.fn().mockResolvedValue(invitee),
      delete: vi.fn(),
      reassignByUserId: vi.fn(),
    },
    challengeStore,
    providers: [provider],
    logger,
    ...(gate ? { gate } : {}),
  })
  return { auth, provider, challengeStore, logger }
}

/** The inviter's own request (e.g. POST /games), signed in as the inviter */
async function inviterRequest(auth: Auth): Promise<Request> {
  const cookie = await auth.createSessionCookie(
    { id: "user-inviter" },
    identityFor(INVITER_EMAIL, "user-inviter"),
  )
  return new Request(`${BASE_URL}/games`, {
    method: "POST",
    headers: {
      Cookie: cookie.split(";")[0] ?? "",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ email: INVITEE_EMAIL }).toString(),
  })
}

/**
 * The confirm form's POST, as the invitee's browser sends it: a fresh
 * browser with no cookies at all, so no challenge cookie and no session.
 */
function redeemFromAnotherBrowser(link: string): Request {
  const url = new URL(link)
  return new Request(link, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      challenge: url.searchParams.get("challenge") ?? "",
      key: url.searchParams.get("key") ?? "",
    }).toString(),
  })
}

async function issue(
  harness: Harness,
  options: Parameters<EmailProvider["issueSignInLink"]>[1],
): ReturnType<EmailProvider["issueSignInLink"]> {
  const context = harness.auth.createContext(await inviterRequest(harness.auth))
  return harness.provider.issueSignInLink(context, options)
}

async function issueLink(
  harness: Harness,
  options: Parameters<EmailProvider["issueSignInLink"]>[1],
): Promise<string> {
  const result = await issue(harness, options)
  if (!result.success) throw new Error(`issue failed: ${result.error.code}`)
  return result.link
}

describe("EmailProvider.issueSignInLink", () => {
  let harness: Harness

  beforeEach(() => {
    vi.clearAllMocks()
    harness = createHarness()
  })

  afterEach(() => {
    harness.auth.destroy()
    harness.challengeStore.destroy()
  })

  it("returns a verify link for the invitee and sends no email itself", async () => {
    const result = await issue(harness, {
      email: "  Invitee@Example.COM ",
      redirectTo: "/invite/game-1",
    })

    if (!result.success) throw new Error("issue failed")
    const link = new URL(result.link)
    expect(link.origin).toBe(BASE_URL)
    expect(link.pathname).toBe("/auth/email/verify")
    expect(link.searchParams.get("redirectTo")).toBe("/invite/game-1")
    expect(transport.sendMagicLink).not.toHaveBeenCalled()

    const challenge = await harness.challengeStore.findById(
      link.searchParams.get("challenge") ?? "",
    )
    expect(challenge?.identifier).toBe(INVITEE_EMAIL)
  })

  it("has no one-time code, so the link is the only way to redeem it", async () => {
    const link = await issueLink(harness, { email: INVITEE_EMAIL })
    const challengeId = new URL(link).searchParams.get("challenge") ?? ""

    const challenge = await harness.challengeStore.findById(challengeId)
    expect(challenge?.hashedCode).toBeUndefined()

    // Even someone holding a cookie naming the challenge cannot use a code
    const response = await harness.auth.handleRequest(
      new Request(`${BASE_URL}/auth/email/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: `auth_challenge=${challengeId}`,
        },
        body: new URLSearchParams({ code: "000000" }).toString(),
      }),
    )
    expect(response.status).not.toBe(200)
    expect(response.headers.get("Set-Cookie") ?? "").not.toContain(
      "auth_session=",
    )
  })

  it("defaults to a 7-day expiry", async () => {
    const result = await issue(harness, { email: INVITEE_EMAIL })

    if (!result.success) throw new Error("issue failed")
    const expected = Date.now() + 7 * SECONDS_PER_DAY * MS_PER_SECOND
    expect(Math.abs(result.expiresAt.getTime() - expected)).toBeLessThan(5000)
  })

  it("honors a caller-set expiry", async () => {
    const result = await issue(harness, {
      email: INVITEE_EMAIL,
      expiresIn: "3d",
    })

    if (!result.success) throw new Error("issue failed")
    const expected = Date.now() + 3 * SECONDS_PER_DAY * MS_PER_SECOND
    expect(Math.abs(result.expiresAt.getTime() - expected)).toBeLessThan(5000)
    const challenge = await harness.challengeStore.findById(
      new URL(result.link).searchParams.get("challenge") ?? "",
    )
    expect(challenge?.expiresAt.getTime()).toBe(result.expiresAt.getTime())
  })

  it.each(["31d", "1000h", "soon", "0d", ""])(
    "refuses expiresIn %j (over 30 days or not a duration)",
    async (expiresIn) => {
      await expect(
        issue(harness, { email: INVITEE_EMAIL, expiresIn }),
      ).rejects.toThrow(/expiresIn/)
    },
  )

  it("signs in from a different browser with no challenge cookie", async () => {
    const link = await issueLink(harness, {
      email: INVITEE_EMAIL,
      redirectTo: "/invite/game-1",
    })

    // The confirm page renders for a cookieless GET too
    const confirm = await harness.auth.handleRequest(new Request(link))
    expect(confirm.status).toBe(200)
    expect(await confirm.text()).toContain(INVITEE_EMAIL)

    const response = await harness.auth.handleRequest(
      redeemFromAnotherBrowser(link),
    )

    expect(response.status).toBe(200)
    const body = (await response.json()) as {
      success: boolean
      user: { id: string }
    }
    expect(body).toEqual({ success: true, user: { id: "user-invitee" } })
  })

  it("is single use: a second redemption fails", async () => {
    const link = await issueLink(harness, { email: INVITEE_EMAIL })

    const first = await harness.auth.handleRequest(
      redeemFromAnotherBrowser(link),
    )
    expect(first.status).toBe(200)

    const second = await harness.auth.handleRequest(
      redeemFromAnotherBrowser(link),
    )
    expect(second.status).not.toBe(200)
    const body = (await second.json()) as { error: { code: string } }
    expect(body.error.code).toBe("INVALID_TOKEN")
  })

  it("fails once expired", async () => {
    const link = await issueLink(harness, {
      email: INVITEE_EMAIL,
      expiresIn: "1d",
    })
    const challenge = await harness.challengeStore.findById(
      new URL(link).searchParams.get("challenge") ?? "",
    )
    if (!challenge) throw new Error("challenge missing")
    challenge.expiresAt = new Date(Date.now() - 1000)

    const response = await harness.auth.handleRequest(
      redeemFromAnotherBrowser(link),
    )

    const body = (await response.json()) as { error: { code: string } }
    expect(body.error.code).toBe("EXPIRED_TOKEN")
  })

  it("drops an open redirect exactly as initiate does, and logs it", async () => {
    const link = await issueLink(harness, {
      email: INVITEE_EMAIL,
      redirectTo: "https://evil.example/phish",
    })

    expect(new URL(link).searchParams.get("redirectTo")).toBeNull()
    expect(link).not.toContain("evil.example")
    const challenge = await harness.challengeStore.findById(
      new URL(link).searchParams.get("challenge") ?? "",
    )
    expect(challenge?.data?.redirectTo).toBeUndefined()
    expect(harness.logger.warn).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ source: "redirectTo" }),
    )
  })

  it("rejects an invalid address without creating a challenge", async () => {
    const createSpy = vi.spyOn(harness.challengeStore, "create")

    const result = await issue(harness, { email: "not-an-email" })

    expect(result.success).toBe(false)
    if (result.success) return
    expect(result.error.code).toBe("INVALID_CREDENTIALS")
    expect(createSpy).not.toHaveBeenCalled()
  })

  it("logs when a link is issued and when it is redeemed", async () => {
    const link = await issueLink(harness, {
      email: INVITEE_EMAIL,
      redirectTo: "/invite/game-1",
    })
    const challengeId = new URL(link).searchParams.get("challenge")

    expect(harness.logger.warn).toHaveBeenCalledWith(
      "Issued an email sign-in link",
      expect.objectContaining({
        provider: "email",
        challengeId,
        expiresAt: expect.any(String),
        redirectTo: "/invite/game-1",
      }),
    )

    await harness.auth.handleRequest(redeemFromAnotherBrowser(link))

    expect(harness.logger.warn).toHaveBeenCalledWith(
      "Redeemed an issued email sign-in link",
      expect.objectContaining({
        provider: "email",
        challengeId,
        userId: "user-invitee",
      }),
    )
  })

  it("keeps the address and link key out of the log", async () => {
    const link = await issueLink(harness, { email: INVITEE_EMAIL })
    await harness.auth.handleRequest(redeemFromAnotherBrowser(link))

    const logged = JSON.stringify(harness.logger.warn.mock.calls)
    expect(logged).not.toContain(INVITEE_EMAIL)
    expect(logged).not.toContain(new URL(link).searchParams.get("key"))
  })

  it("does not log an ordinary initiate's link as issued", async () => {
    await harness.auth.handleRequest(
      new Request(`${BASE_URL}/auth/email/initiate`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ email: INVITEE_EMAIL }).toString(),
      }),
    )
    const link = vi.mocked(transport.sendMagicLink).mock.calls.at(-1)?.[1]
    if (!link) throw new Error("no link sent")
    await harness.auth.handleRequest(redeemFromAnotherBrowser(link))

    expect(harness.logger.warn).not.toHaveBeenCalled()
  })
})

describe("EmailProvider.issueSignInLink behind an initiate gate", () => {
  let harness: Harness

  afterEach(() => {
    harness.auth.destroy()
    harness.challengeStore.destroy()
  })

  it("hands the gate the invitee's normalized address in signin mode", async () => {
    const onInitiate = vi.fn().mockReturnValue("allow")
    harness = createHarness({ onInitiate })

    const result = await issue(harness, { email: " Invitee@Example.com" })

    expect(result.success).toBe(true)
    expect(onInitiate).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "email",
        identifier: INVITEE_EMAIL,
        mode: "signin",
      }),
    )
  })

  it("refuses when the gate returns an error, creating nothing", async () => {
    harness = createHarness({
      onInitiate: () => ({
        error: { code: "INVALID_CREDENTIALS", message: "Invite only" },
      }),
    })
    const createSpy = vi.spyOn(harness.challengeStore, "create")

    const result = await issue(harness, { email: INVITEE_EMAIL })

    expect(result).toEqual({
      success: false,
      error: { code: "INVALID_CREDENTIALS", message: "Invite only" },
    })
    expect(createSpy).not.toHaveBeenCalled()
  })

  it("refuses when the gate redirects (e.g. to a waitlist)", async () => {
    harness = createHarness({ onInitiate: () => ({ redirect: "/waitlist" }) })
    const createSpy = vi.spyOn(harness.challengeStore, "create")

    const result = await issue(harness, { email: INVITEE_EMAIL })

    expect(result.success).toBe(false)
    expect(createSpy).not.toHaveBeenCalled()
  })
})

describe("EmailProvider.issueSignInLink per-recipient throttling", () => {
  it("refuses with RATE_LIMITED once the recipient's cap is hit", async () => {
    const harness = createHarness()
    const provider = harness.provider
    const context = {
      ...harness.auth.createContext(await inviterRequest(harness.auth)),
      abuse: {
        checkIdentifier: vi.fn().mockResolvedValue({
          allowed: false,
          event: {
            reason: "identifier_rate_limited" as const,
            providerId: "email",
            ip: null,
            identifier: INVITEE_EMAIL,
            at: new Date(),
          },
        }),
      },
    }

    const result = await provider.issueSignInLink(context, {
      email: INVITEE_EMAIL,
    })

    expect(result.success).toBe(false)
    if (!result.success) expect(result.error.code).toBe("RATE_LIMITED")
    expect(context.abuse.checkIdentifier).toHaveBeenCalledWith(
      "email",
      INVITEE_EMAIL,
    )
    harness.auth.destroy()
    harness.challengeStore.destroy()
  })
})

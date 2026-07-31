import type {
  AuthProvider,
  AuthContext,
  AuthResult,
  AuthInitResult,
  Challenge,
  ChallengeStore,
  ProviderRoute,
} from "@activescott/auth"
import {
  AuthErrors,
  generateOtpCode,
  hashOtpCode,
  verifyOtpCode,
} from "@activescott/auth"
import type { EmailProviderConfig, EmailTransport } from "./types.js"
import { NodemailerTransport } from "./transports/nodemailer.js"

// Time unit multipliers in seconds
const SECONDS_PER_MINUTE = 60
const SECONDS_PER_HOUR = 3600
const SECONDS_PER_DAY = 86_400
const MS_PER_SECOND = 1000

const CHALLENGE_TYPE = "email"
const DEFAULT_EXPIRY = "15m"
const DEFAULT_OTP_LENGTH = 6
const DEFAULT_OTP_MAX_ATTEMPTS = 5
const DEFAULT_OTP_COOKIE_NAME = "auth_challenge"
/** Bytes of entropy in the magic-link key (256 bits) */
const LINK_KEY_BYTES = 32

/**
 * Email authentication provider. Each send creates one server-side
 * challenge with two redemption paths: a single-use magic link
 * (?challenge=<id>&key=<secret>) and a numeric one-time code.
 *
 * Magic-link GETs render a confirm page; redemption only happens on the
 * confirm form's POST. Email security scanners (Outlook SafeLinks,
 * Mimecast, link previews) prefetch URLs with GET but never submit forms,
 * so they cannot consume the single-use link before the user clicks it.
 */
export class EmailProvider implements AuthProvider {
  public readonly id = "email"
  public readonly name = "Email"

  private transport: EmailTransport

  public constructor(
    private readonly config: EmailProviderConfig,
    transport?: EmailTransport,
  ) {
    this.transport =
      transport ??
      new NodemailerTransport(process.env.NODE_ENV === "development")
  }

  /**
   * Create a challenge and email the magic link + code.
   * Browser form posts (urlencoded + Accept: text/html) are answered with
   * a redirect back to the submitting page (?sent=1) so login forms can
   * post directly to /auth/email/initiate; other callers get JSON. Both
   * carry the challenge cookie.
   */
  public async initiate(
    request: Request,
    context: AuthContext,
  ): Promise<AuthInitResult | Response> {
    try {
      const body = await this.parseRequestBody(request)
      const rawEmail = body.email

      if (!rawEmail || typeof rawEmail !== "string") {
        return this.initiateFailure(
          request,
          AuthErrors.invalidCredentials({ reason: "Email is required" }),
        )
      }

      const email = rawEmail.toLowerCase().trim()

      if (!this.isValidEmail(email)) {
        return this.initiateFailure(
          request,
          AuthErrors.invalidCredentials({ reason: "Invalid email format" }),
        )
      }

      const redirectTo =
        typeof body.redirectTo === "string" ? body.redirectTo : undefined

      const challengeId = crypto.randomUUID()
      const linkKey = this.generateLinkKey()
      const code = generateOtpCode(
        this.config.otp?.length ?? DEFAULT_OTP_LENGTH,
      )
      const expirySeconds = this.parseMaxAge(
        this.config.expiry ?? DEFAULT_EXPIRY,
      )

      await context.challengeStore.create({
        id: challengeId,
        type: CHALLENGE_TYPE,
        identifier: email,
        hashedCode: await hashOtpCode(challengeId, code),
        data: {
          hashedKey: await hashOtpCode(challengeId, linkKey),
          ...(redirectTo ? { redirectTo } : {}),
        },
        maxAttempts: this.config.otp?.maxAttempts ?? DEFAULT_OTP_MAX_ATTEMPTS,
        expiresAt: new Date(Date.now() + expirySeconds * MS_PER_SECOND),
      })

      let magicLink = `${context.baseUrl}/auth/email/verify?challenge=${challengeId}&key=${linkKey}`
      if (redirectTo) {
        magicLink += `&redirectTo=${encodeURIComponent(redirectTo)}`
      }

      const sent = await this.transport.sendMagicLink(
        email,
        magicLink,
        this.config,
        { code },
      )

      if (!sent) {
        return this.initiateFailure(
          request,
          AuthErrors.providerError("Failed to send magic link email"),
        )
      }

      const challengeCookie = this.buildChallengeCookie(
        challengeId,
        expirySeconds,
        context,
      )

      if (this.isBrowserFormPost(request)) {
        const returnUrl = this.buildReturnUrl(request, { sent: "1" })
        return new Response(null, {
          status: 302,
          headers: {
            Location: returnUrl,
            "Set-Cookie": challengeCookie,
          },
        })
      }

      return {
        success: true,
        message: "Magic link sent. Please check your email.",
        setCookies: [challengeCookie],
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("Error in email provider initiate:", error)
      return this.initiateFailure(
        request,
        AuthErrors.providerError(
          error instanceof Error ? error.message : "Unknown error",
        ),
      )
    }
  }

  /**
   * GET with challenge+key renders the confirm page (no state change).
   * POST with challenge+key redeems the magic link.
   * POST with a code redeems via the code + challenge cookie.
   */
  public async verify(
    request: Request,
    context: AuthContext,
  ): Promise<AuthResult | Response> {
    try {
      const url = new URL(request.url)

      if (request.method === "GET") {
        const challengeId = url.searchParams.get("challenge")
        const key = url.searchParams.get("key")
        if (!challengeId || !key) {
          return {
            success: false,
            error: AuthErrors.invalidToken({
              reason: "This sign-in link is invalid.",
            }),
          }
        }
        return this.renderConfirmPage(request, context, challengeId, key)
      }

      const body = await this.parseRequestBody(request)

      if (typeof body.challenge === "string" && typeof body.key === "string") {
        return this.redeemLink(context, body.challenge, body.key)
      }

      if (typeof body.code === "string") {
        return this.redeemCode(request, context, body.code)
      }

      return {
        success: false,
        error: AuthErrors.invalidCredentials({
          reason: "Code or sign-in link is required",
        }),
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("Error in email provider verify:", error)
      return {
        success: false,
        error: AuthErrors.providerError(
          error instanceof Error ? error.message : "Unknown error",
        ),
      }
    }
  }

  /**
   * Validate the link without consuming it and render the confirm page.
   * The page's form POSTs the challenge+key back to this endpoint, where
   * redemption actually happens — scanners GET but never POST.
   */
  private async renderConfirmPage(
    request: Request,
    context: AuthContext,
    challengeId: string,
    key: string,
  ): Promise<AuthResult | Response> {
    const challenge = await this.loadLinkChallenge(context, challengeId, key)
    if ("error" in challenge) return { success: false, error: challenge.error }

    const url = new URL(request.url)
    const redirectTo = url.searchParams.get("redirectTo")
    const appName = this.config.template?.appName ?? "App"
    const primaryColor = this.config.template?.primaryColor ?? "#6366f1"

    const action = redirectTo
      ? `?redirectTo=${encodeURIComponent(redirectTo)}`
      : ""

    const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Sign in to ${escapeHtml(appName)}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; padding: 48px 16px; margin: 0;">
  <main style="max-width: 360px; text-align: center;">
    <h1 style="font-size: 22px;">Sign in to ${escapeHtml(appName)}</h1>
    <p style="color: #6b7280;">Confirm to finish signing in as <strong>${escapeHtml(challenge.identifier)}</strong>.</p>
    <form method="post" action="${escapeHtml(action)}">
      <input type="hidden" name="challenge" value="${escapeHtml(challengeId)}">
      <input type="hidden" name="key" value="${escapeHtml(key)}">
      <button type="submit" style="background: ${escapeHtml(primaryColor)}; color: white; border: 0; padding: 12px 32px; border-radius: 6px; font-size: 16px; cursor: pointer;">Confirm sign-in</button>
    </form>
  </main>
</body>
</html>`

    return new Response(html, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    })
  }

  /**
   * Redeem a magic link: consume the challenge and authenticate
   */
  private async redeemLink(
    context: AuthContext,
    challengeId: string,
    key: string,
  ): Promise<AuthResult> {
    const challenge = await this.loadLinkChallenge(context, challengeId, key)
    if ("error" in challenge) return { success: false, error: challenge.error }

    // Single use: consumed by redemption
    await context.challengeStore.delete(challenge.id)

    const result = await this.authenticateEmail(challenge.identifier, context)
    if (!result.success) return result

    return {
      ...result,
      setCookies: [this.buildChallengeClearingCookie(context)],
    }
  }

  /**
   * Load a challenge and verify the link key against its stored hash.
   * The 256-bit key makes brute force infeasible, so link attempts do not
   * count against maxAttempts (which guards the short numeric code).
   */
  private async loadLinkChallenge(
    context: AuthContext,
    challengeId: string,
    key: string,
  ): Promise<
    Challenge | { error: ReturnType<typeof AuthErrors.invalidToken> }
  > {
    const challenge = await context.challengeStore.findById(challengeId)
    if (!challenge || challenge.type !== CHALLENGE_TYPE) {
      return {
        error: AuthErrors.invalidToken({
          reason: "This sign-in link is invalid or has already been used.",
        }),
      }
    }

    if (challenge.expiresAt.getTime() < Date.now()) {
      return {
        error: AuthErrors.expiredToken({
          reason: "This sign-in link has expired. Request a new one.",
        }),
      }
    }

    const hashedKey = challenge.data?.hashedKey
    if (typeof hashedKey !== "string") {
      return {
        error: AuthErrors.invalidToken({ reason: "Malformed challenge" }),
      }
    }

    const submitted = await hashOtpCode(challenge.id, key)
    if (!constantTimeEqual(submitted, hashedKey)) {
      return {
        error: AuthErrors.invalidToken({
          reason: "This sign-in link is invalid.",
        }),
      }
    }

    return challenge
  }

  /**
   * Redeem a one-time code against the challenge cookie
   */
  private async redeemCode(
    request: Request,
    context: AuthContext,
    code: string,
  ): Promise<AuthResult> {
    const challengeStore: ChallengeStore = context.challengeStore

    const challengeId = this.readChallengeCookie(request)
    if (!challengeId) {
      return {
        success: false,
        error: AuthErrors.invalidCredentials({
          reason:
            "No verification in progress in this browser. Request a new code.",
        }),
      }
    }

    const challenge = await challengeStore.findById(challengeId)
    if (!challenge || challenge.type !== CHALLENGE_TYPE) {
      return {
        success: false,
        error: AuthErrors.invalidCredentials({
          reason: "Verification not found. Request a new code.",
        }),
      }
    }

    if (challenge.expiresAt.getTime() < Date.now()) {
      return {
        success: false,
        error: AuthErrors.expiredToken({ reason: "Code has expired" }),
      }
    }

    // Count the attempt before comparing so failed comparisons can't be
    // retried indefinitely
    const attempts = await challengeStore.incrementAttempts(challenge.id)
    if (attempts > challenge.maxAttempts) {
      return {
        success: false,
        error: AuthErrors.rateLimited({ reason: "Too many attempts" }),
      }
    }

    const valid = await verifyOtpCode(challenge, code.trim())
    if (!valid) {
      return {
        success: false,
        error: AuthErrors.invalidCredentials({ reason: "Incorrect code" }),
      }
    }

    // Single use: the challenge is consumed by successful verification
    await challengeStore.delete(challenge.id)

    const result = await this.authenticateEmail(challenge.identifier, context)
    if (!result.success) return result

    return {
      ...result,
      setCookies: [this.buildChallengeClearingCookie(context)],
    }
  }

  /**
   * Look up or create the user and identity for a verified email address.
   * Link and code redemption both converge here.
   */
  private async authenticateEmail(
    email: string,
    context: AuthContext,
  ): Promise<AuthResult> {
    let identity = await context.identityStore.findByProviderAndIdentifier(
      this.id,
      email,
    )

    let user

    if (identity) {
      user = await context.userStore.findById(identity.userId)
      if (!user) {
        return {
          success: false,
          error: AuthErrors.userNotFound({ email }),
        }
      }
    } else {
      user = await context.userStore.create({
        provider: this.id,
        identifier: email,
      })

      identity = await context.identityStore.create({
        userId: user.id,
        provider: this.id,
        identifier: email,
      })
    }

    if (context.identityStore.update) {
      await context.identityStore.update(identity.id, {
        verifiedAt: new Date(),
      })
    }

    return {
      success: true,
      user,
      identity,
    }
  }

  public canHandle(request: Request): boolean {
    const url = new URL(request.url)
    return url.pathname.startsWith("/auth/email")
  }

  public getRoutes(): ProviderRoute[] {
    return [
      { method: "POST", path: "/email/send", handler: "initiate" },
      { method: "POST", path: "/email/initiate", handler: "initiate" },
      { method: "GET", path: "/email/verify", handler: "verify" },
      { method: "POST", path: "/email/verify", handler: "verify" },
      { method: "GET", path: "/email/callback", handler: "verify" },
    ]
  }

  /**
   * A browser form post: urlencoded body and the client renders HTML.
   * These get redirect responses; JSON/fetch callers get AuthInitResult.
   */
  private isBrowserFormPost(request: Request): boolean {
    const contentType = request.headers.get("content-type") ?? ""
    const accept = request.headers.get("accept") ?? ""
    return (
      contentType.includes("application/x-www-form-urlencoded") &&
      accept.includes("text/html")
    )
  }

  /**
   * Where to send the browser back after a form post to initiate:
   * the submitting page (Referer) with the given query params merged in,
   * falling back to /login.
   */
  private buildReturnUrl(
    request: Request,
    params: Record<string, string>,
  ): string {
    const referer = request.headers.get("referer")
    let url: URL
    try {
      url = new URL(referer ?? "/login", request.url)
    } catch {
      url = new URL("/login", request.url)
    }
    for (const [name, value] of Object.entries(params)) {
      url.searchParams.set(name, value)
    }
    return url.toString()
  }

  /**
   * Failure counterpart of the browser-form redirect: send the browser
   * back with ?error=<code>; other callers get the AuthInitResult.
   */
  private initiateFailure(
    request: Request,
    error: ReturnType<typeof AuthErrors.invalidCredentials>,
  ): AuthInitResult | Response {
    if (this.isBrowserFormPost(request)) {
      return new Response(null, {
        status: 302,
        headers: {
          Location: this.buildReturnUrl(request, { error: error.code }),
        },
      })
    }
    return { success: false, error }
  }

  /**
   * Random URL-safe key for the magic link (base64url, 256 bits)
   */
  private generateLinkKey(): string {
    const bytes = new Uint8Array(LINK_KEY_BYTES)
    crypto.getRandomValues(bytes)
    let binary = ""
    for (const byte of bytes) {
      binary += String.fromCharCode(byte)
    }
    return btoa(binary)
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "")
  }

  /**
   * Build the Set-Cookie value binding the challenge to this browser
   */
  private buildChallengeCookie(
    challengeId: string,
    maxAgeSeconds: number,
    context: AuthContext,
  ): string {
    const name = this.config.otp?.cookieName ?? DEFAULT_OTP_COOKIE_NAME
    const secure = context.baseUrl.startsWith("https://") ? "; Secure" : ""
    return `${name}=${challengeId}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`
  }

  /**
   * Build a Set-Cookie value that clears the challenge cookie
   */
  private buildChallengeClearingCookie(context: AuthContext): string {
    const name = this.config.otp?.cookieName ?? DEFAULT_OTP_COOKIE_NAME
    const secure = context.baseUrl.startsWith("https://") ? "; Secure" : ""
    return `${name}=; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=0${secure}`
  }

  /**
   * Read the challenge ID from the request's challenge cookie
   */
  private readChallengeCookie(request: Request): string | null {
    const cookieHeader = request.headers.get("Cookie")
    if (!cookieHeader) return null

    const name = this.config.otp?.cookieName ?? DEFAULT_OTP_COOKIE_NAME
    const cookies = cookieHeader.split(";").map((part) => part.trim())
    const target = cookies.find((part) => part.startsWith(`${name}=`))
    if (!target) return null

    const value = target.slice(name.length + 1)
    return value || null
  }

  /**
   * Parse request body (handles both JSON and form data)
   */
  private async parseRequestBody(
    request: Request,
  ): Promise<Record<string, unknown>> {
    const contentType = request.headers.get("content-type") ?? ""

    if (contentType.includes("application/json")) {
      return (await request.json()) as Record<string, unknown>
    }

    if (contentType.includes("application/x-www-form-urlencoded")) {
      const text = await request.text()
      const parameters = new URLSearchParams(text)
      const result: Record<string, unknown> = {}
      for (const [key, value] of parameters.entries()) {
        result[key] = value
      }
      return result
    }

    // Try to parse as JSON anyway
    try {
      return (await request.json()) as Record<string, unknown>
    } catch {
      return {}
    }
  }

  /**
   * Basic email validation
   */
  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  }

  /**
   * Parse a max age string like "30d", "7d", "24h" to seconds
   */
  private parseMaxAge(maxAge: string): number {
    const match = maxAge.match(/^(\d+)([dhms])$/)
    if (!match) return 0

    const [, valueString, unitChar] = match
    if (!valueString || !unitChar) return 0

    const value = Number.parseInt(valueString, 10)
    const multipliers: Record<string, number> = {
      s: 1,
      m: SECONDS_PER_MINUTE,
      h: SECONDS_PER_HOUR,
      d: SECONDS_PER_DAY,
    }

    return value * (multipliers[unitChar] ?? 1)
  }
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let index = 0; index < a.length; index++) {
    diff |= a.charCodeAt(index) ^ b.charCodeAt(index)
  }
  return diff === 0
}

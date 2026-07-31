import jwt from "jsonwebtoken"
import type {
  AuthProvider,
  AuthContext,
  AuthResult,
  AuthInitResult,
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

const OTP_CHALLENGE_TYPE = "email-otp"
const DEFAULT_OTP_LENGTH = 6
const DEFAULT_OTP_EXPIRY = "10m"
const DEFAULT_OTP_MAX_ATTEMPTS = 5
const DEFAULT_OTP_COOKIE_NAME = "auth_challenge"

/**
 * JWT payload for magic link tokens
 */
interface MagicLinkPayload {
  email: string
  redirectTo?: string
  iat: number
  exp: number
}

/**
 * Email-based magic link authentication provider
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
   * Send a magic link to the user's email
   */
  public async initiate(
    request: Request,
    context: AuthContext,
  ): Promise<AuthInitResult> {
    try {
      // Get email from request body
      const body = await this.parseRequestBody(request)
      const rawEmail = body.email

      if (!rawEmail || typeof rawEmail !== "string") {
        return {
          success: false,
          error: AuthErrors.invalidCredentials({ reason: "Email is required" }),
        }
      }

      const email = rawEmail.toLowerCase().trim()

      // Validate email format
      if (!this.isValidEmail(email)) {
        return {
          success: false,
          error: AuthErrors.invalidCredentials({
            reason: "Invalid email format",
          }),
        }
      }

      // Get optional redirectTo from request body
      const redirectTo = body.redirectTo as string | undefined

      // Generate magic link token with email and optional redirectTo
      const expiresInSeconds = this.parseMaxAge(this.config.magicLinkExpiry)
      const tokenPayload: { email: string; redirectTo?: string } = { email }
      if (redirectTo) {
        tokenPayload.redirectTo = redirectTo
      }
      const token = jwt.sign(tokenPayload, this.config.magicLinkSecret, {
        expiresIn: expiresInSeconds,
        issuer: "auth-magic-link",
        audience: "auth",
      })

      // Build magic link URL
      let magicLink = `${context.baseUrl}/auth/email/verify?token=${token}`
      if (redirectTo) {
        magicLink += `&redirectTo=${encodeURIComponent(redirectTo)}`
      }

      // When OTP is enabled, create a challenge and include the code in the email
      let code: string | undefined
      let challengeCookie: string | undefined

      if (this.isOtpEnabled(context)) {
        const challengeStore = context.challengeStore
        if (!challengeStore) {
          return {
            success: false,
            error: AuthErrors.configurationError(
              "Email OTP requires a challengeStore on the Auth config",
            ),
          }
        }

        code = generateOtpCode(this.config.otp?.length ?? DEFAULT_OTP_LENGTH)
        const challengeId = crypto.randomUUID()
        const expirySeconds = this.parseMaxAge(
          this.config.otp?.expiry ?? DEFAULT_OTP_EXPIRY,
        )

        await challengeStore.create({
          id: challengeId,
          type: OTP_CHALLENGE_TYPE,
          identifier: email,
          hashedCode: await hashOtpCode(challengeId, code),
          maxAttempts:
            this.config.otp?.maxAttempts ?? DEFAULT_OTP_MAX_ATTEMPTS,
          expiresAt: new Date(Date.now() + expirySeconds * MS_PER_SECOND),
        })

        challengeCookie = this.buildChallengeCookie(
          challengeId,
          expirySeconds,
          context,
        )
      }

      // Send email
      const sent = await this.transport.sendMagicLink(
        email,
        magicLink,
        this.config,
        code ? { code } : undefined,
      )

      if (!sent) {
        return {
          success: false,
          error: AuthErrors.providerError("Failed to send magic link email"),
        }
      }

      return {
        success: true,
        message: "Magic link sent. Please check your email.",
        ...(challengeCookie ? { setCookies: [challengeCookie] } : {}),
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("Error in email provider initiate:", error)
      return {
        success: false,
        error: AuthErrors.providerError(
          error instanceof Error ? error.message : "Unknown error",
        ),
      }
    }
  }

  /**
   * Verify a magic link token or an OTP code and authenticate the user.
   * GET with a token query param verifies a magic link; POST with a code
   * in the body verifies an OTP code against the challenge cookie.
   */
  public async verify(
    request: Request,
    context: AuthContext,
  ): Promise<AuthResult> {
    try {
      const url = new URL(request.url)
      const token = url.searchParams.get("token")

      if (!token && request.method === "POST") {
        return this.verifyOtp(request, context)
      }

      if (!token) {
        return {
          success: false,
          error: AuthErrors.invalidToken({ reason: "Token is required" }),
        }
      }

      // Verify token with primary secret, fall back to additional secrets
      const payload = this.verifyToken(token)

      if (!payload) {
        return {
          success: false,
          error: AuthErrors.invalidToken({
            reason: "Invalid or expired token",
          }),
        }
      }

      const email = payload.email.toLowerCase().trim()
      return await this.authenticateEmail(email, context)
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
   * Verify a submitted OTP code against the challenge referenced by the
   * challenge cookie
   */
  private async verifyOtp(
    request: Request,
    context: AuthContext,
  ): Promise<AuthResult> {
    const challengeStore = context.challengeStore
    if (!this.isOtpEnabled(context) || !challengeStore) {
      return {
        success: false,
        error: AuthErrors.configurationError(
          "Email OTP verification requires a challengeStore on the Auth config",
        ),
      }
    }

    const body = await this.parseRequestBody(request)
    const code = body.code

    if (!code || typeof code !== "string") {
      return {
        success: false,
        error: AuthErrors.invalidCredentials({ reason: "Code is required" }),
      }
    }

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
    if (!challenge || challenge.type !== OTP_CHALLENGE_TYPE) {
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
   * Both the magic link and OTP verification paths converge here.
   */
  private async authenticateEmail(
    email: string,
    context: AuthContext,
  ): Promise<AuthResult> {
    // Look up existing identity
    let identity = await context.identityStore.findByProviderAndIdentifier(
      this.id,
      email,
    )

    let user

    if (identity) {
      // Existing user - look them up
      user = await context.userStore.findById(identity.userId)
      if (!user) {
        return {
          success: false,
          error: AuthErrors.userNotFound({ email }),
        }
      }
    } else {
      // New user - create user and identity
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

    // Update verifiedAt if the store supports it
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

  /**
   * Check if this provider can handle the given request
   */
  public canHandle(request: Request): boolean {
    const url = new URL(request.url)
    return url.pathname.startsWith("/auth/email")
  }

  /**
   * Get the routes this provider needs
   */
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
   * OTP codes default to on whenever a challengeStore is configured;
   * otp.enabled overrides in either direction (true forces a
   * CONFIGURATION_ERROR if the store is missing, false opts out)
   */
  private isOtpEnabled(context: AuthContext): boolean {
    return this.config.otp?.enabled ?? Boolean(context.challengeStore)
  }

  /**
   * Build the Set-Cookie value binding the OTP challenge to this browser
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
   * Verify a magic link token
   */
  private verifyToken(token: string): MagicLinkPayload | null {
    // Try primary secret first, then additional secrets
    const secrets = [
      this.config.magicLinkSecret,
      ...(this.config.additionalSecrets ?? []),
    ]

    for (const secret of secrets) {
      try {
        const payload = jwt.verify(token, secret, {
          issuer: "auth-magic-link",
          audience: "auth",
        }) as MagicLinkPayload

        if (payload.email) {
          return payload
        }
      } catch {
        // Try next secret
        continue
      }
    }

    return null
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

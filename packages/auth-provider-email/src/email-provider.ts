import jwt from "jsonwebtoken"
import type {
  AuthProvider,
  AuthContext,
  AuthResult,
  AuthInitResult,
  ProviderRoute,
} from "@activescott/auth"
import { AuthErrors } from "@activescott/auth"
import type { EmailProviderConfig, EmailTransport } from "./types.js"
import { NodemailerTransport } from "./transports/nodemailer.js"

// Time unit multipliers in seconds
const SECONDS_PER_MINUTE = 60
const SECONDS_PER_HOUR = 3600
const SECONDS_PER_DAY = 86_400

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

      // Send email
      const sent = await this.transport.sendMagicLink(
        email,
        magicLink,
        this.config,
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
   * Verify a magic link token and authenticate the user
   */
  public async verify(
    request: Request,
    context: AuthContext,
  ): Promise<AuthResult> {
    try {
      // Get token from query params
      const url = new URL(request.url)
      const token = url.searchParams.get("token")

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
      { method: "GET", path: "/email/callback", handler: "verify" },
    ]
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

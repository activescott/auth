import jwt from "jsonwebtoken"
import type { Session, SessionConfig, AuthUser, Identity } from "../types.js"

/**
 * JWT payload structure for sessions
 */
interface SessionJwtPayload {
  userId: string
  identifier: string
  provider: string
  iat: number
  exp: number
}

// Time unit multipliers in seconds
const SECONDS_PER_MINUTE = 60
const SECONDS_PER_HOUR = 3600
const SECONDS_PER_DAY = 86_400

/**
 * Manages session creation, verification, and cookie handling
 */
export class SessionManager {
  public constructor(private readonly config: SessionConfig) {}

  /**
   * Create a session JWT for a user
   */
  public async createSession(
    user: AuthUser,
    identity: Identity,
  ): Promise<string> {
    // Convert maxAge string to seconds for jwt.sign
    const expiresInSeconds = this.parseMaxAge(this.config.maxAge)

    const token = jwt.sign(
      {
        userId: user.id,
        identifier: identity.identifier,
        provider: identity.provider,
      },
      this.config.secret,
      {
        expiresIn: expiresInSeconds,
        issuer: this.config.issuer ?? "auth",
        audience: this.config.audience ?? "users",
      },
    )

    return token
  }

  /**
   * Create a serialized cookie string containing the session
   */
  public async createSessionCookie(
    user: AuthUser,
    identity: Identity,
  ): Promise<string> {
    const token = await this.createSession(user, identity)
    return this.serializeCookie(token)
  }

  /**
   * Get session from a request
   */
  public async getSession(request: Request): Promise<Session | null> {
    const cookieHeader = request.headers.get("Cookie")
    if (!cookieHeader) return null

    const token = this.parseCookie(cookieHeader)
    if (!token) return null

    return this.verifyToken(token)
  }

  /**
   * Verify a session token and return the session data
   */
  public verifyToken(token: string): Session | null {
    // Try primary secret first, then additional secrets (e.g., for E2E testing)
    const secrets = [
      this.config.secret,
      ...(this.config.additionalSecrets ?? []),
    ]

    for (const secret of secrets) {
      try {
        const payload = jwt.verify(token, secret, {
          issuer: this.config.issuer ?? "auth",
          audience: this.config.audience ?? "users",
        }) as SessionJwtPayload

        return {
          userId: payload.userId,
          identifier: payload.identifier,
          provider: payload.provider,
          issuedAt: payload.iat,
          expiresAt: payload.exp,
        }
      } catch {
        // Try next secret
        continue
      }
    }

    // All secrets failed
    return null
  }

  /**
   * Create a cookie string that destroys the session
   */
  public destroySessionCookie(): string {
    return this.serializeCookie("", { maxAge: 0 })
  }

  /**
   * Get the cookie name
   */
  public getCookieName(): string {
    return this.config.cookieName
  }

  /**
   * Serialize a value into a cookie string
   */
  private serializeCookie(
    value: string,
    overrides?: { maxAge?: number },
  ): string {
    const { cookieName, cookie, maxAge } = this.config
    const maxAgeSeconds = overrides?.maxAge ?? this.parseMaxAge(maxAge)

    const parts = [
      `${cookieName}=${encodeURIComponent(value)}`,
      `Path=${cookie.path ?? "/"}`,
      `Max-Age=${maxAgeSeconds}`,
      "HttpOnly",
      `SameSite=${this.capitalizeSameSite(cookie.sameSite)}`,
    ]

    if (cookie.secure) {
      parts.push("Secure")
    }

    if (cookie.domain) {
      parts.push(`Domain=${cookie.domain}`)
    }

    return parts.join("; ")
  }

  /**
   * Parse a cookie header and extract the session token
   */
  private parseCookie(cookieHeader: string): string | null {
    const cookies = cookieHeader.split(";").map((c) => c.trim())
    const target = cookies.find((c) =>
      c.startsWith(`${this.config.cookieName}=`),
    )
    if (!target) return null
    return decodeURIComponent(target.split("=")[1] ?? "")
  }

  /**
   * Parse a max age string like "30d", "7d", "24h" to seconds
   */
  private parseMaxAge(maxAge: string): number {
    // Match patterns like "30d", "7d", "24h", "60m", "3600s"
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

  /**
   * Capitalize SameSite value for cookie header
   */
  private capitalizeSameSite(sameSite: "strict" | "lax" | "none"): string {
    return sameSite.charAt(0).toUpperCase() + sameSite.slice(1)
  }
}

import { SignJWT, jwtVerify } from "jose"
import type { Session, SessionConfig, AuthUser, Identity } from "../types.js"
import { parseDuration } from "../provider-util.js"

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
    const expiresInSeconds = parseDuration(this.config.maxAge)

    return new SignJWT({
      userId: user.id,
      identifier: identity.identifier,
      provider: identity.provider,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime(`${expiresInSeconds}s`)
      .setIssuer(this.config.issuer ?? "auth")
      .setAudience(this.config.audience ?? "users")
      .sign(new TextEncoder().encode(this.config.secret))
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
  public async verifyToken(token: string): Promise<Session | null> {
    // Try primary secret first, then additional secrets (e.g., for E2E testing)
    const secrets = [
      this.config.secret,
      ...(this.config.additionalSecrets ?? []),
    ]

    for (const secret of secrets) {
      try {
        const { payload } = await jwtVerify(
          token,
          new TextEncoder().encode(secret),
          {
            issuer: this.config.issuer ?? "auth",
            audience: this.config.audience ?? "users",
          },
        )

        const { userId, identifier, provider, iat, exp } = payload
        if (
          typeof userId !== "string" ||
          typeof identifier !== "string" ||
          typeof provider !== "string" ||
          typeof iat !== "number" ||
          typeof exp !== "number"
        ) {
          continue
        }

        return {
          userId,
          identifier,
          provider,
          issuedAt: iat,
          expiresAt: exp,
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
    const maxAgeSeconds = overrides?.maxAge ?? parseDuration(maxAge)

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
   * Capitalize SameSite value for cookie header
   */
  private capitalizeSameSite(sameSite: "strict" | "lax" | "none"): string {
    return sameSite.charAt(0).toUpperCase() + sameSite.slice(1)
  }
}

import type {
  AuthConfig,
  AuthContext,
  AuthError,
  AuthProvider,
  AuthResult,
  AuthUser,
  Identity,
  SessionConfig,
} from "./types.js"
import { SessionManager } from "./session/session-manager.js"
import { AuthErrors } from "./errors.js"

// Time constants
const MS_PER_SECOND = 1000
const SECONDS_PER_MINUTE = 60
/** Default session cache TTL in minutes */
const DEFAULT_CACHE_TTL_MINUTES = 2
/** Interval between cache cleanups in minutes */
const CACHE_CLEANUP_INTERVAL_MINUTES = 5

// Regex capture group indices for auth route parsing
const PROVIDER_ID_GROUP = 1
const ACTION_GROUP = 2

/**
 * In-memory cache for session verification to reduce DB queries
 */
interface SessionCacheEntry {
  user: AuthUser | null
  identity: Identity | null
  timestamp: number
}

class SessionCache {
  private cache = new Map<string, SessionCacheEntry>()
  private readonly ttl: number

  public constructor(
    ttlMs: number = DEFAULT_CACHE_TTL_MINUTES *
      SECONDS_PER_MINUTE *
      MS_PER_SECOND,
  ) {
    this.ttl = ttlMs
  }

  public get(token: string): SessionCacheEntry | undefined {
    const entry = this.cache.get(token)
    if (!entry) return undefined

    // Check if expired
    if (Date.now() - entry.timestamp > this.ttl) {
      this.cache.delete(token)
      return undefined
    }

    return entry
  }

  public set(
    token: string,
    user: AuthUser | null,
    identity: Identity | null,
  ): void {
    this.cache.set(token, {
      user,
      identity,
      timestamp: Date.now(),
    })
  }

  public cleanup(): void {
    const now = Date.now()
    for (const [token, entry] of this.cache.entries()) {
      if (now - entry.timestamp > this.ttl) {
        this.cache.delete(token)
      }
    }
  }
}

/**
 * Main authentication class that orchestrates providers
 */
export class Auth {
  private providers = new Map<string, AuthProvider>()
  private sessionManager: SessionManager
  private sessionCache: SessionCache
  private cleanupInterval: ReturnType<typeof setInterval> | null = null

  public constructor(private readonly config: AuthConfig) {
    this.sessionManager = new SessionManager(config.session)
    this.sessionCache = new SessionCache()

    // Register providers
    for (const provider of config.providers) {
      this.providers.set(provider.id, provider)
    }

    // Start cache cleanup interval
    this.cleanupInterval = setInterval(
      () => this.sessionCache.cleanup(),
      CACHE_CLEANUP_INTERVAL_MINUTES * SECONDS_PER_MINUTE * MS_PER_SECOND,
    )
  }

  /**
   * Clean up resources (call when shutting down)
   */
  public destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }
  }

  /**
   * Get a specific provider by ID
   */
  public getProvider(id: string): AuthProvider | undefined {
    return this.providers.get(id)
  }

  /**
   * Get all registered providers
   */
  public getProviders(): AuthProvider[] {
    return [...this.providers.values()]
  }

  /**
   * Find provider that can handle the request
   */
  public findProvider(request: Request): AuthProvider | undefined {
    for (const provider of this.providers.values()) {
      if (provider.canHandle(request)) {
        return provider
      }
    }
    return undefined
  }

  /**
   * Handle an authentication request.
   * Routes to appropriate provider based on URL pattern.
   * URL format: /auth/{provider}/{action}
   */
  public async handleRequest(request: Request): Promise<Response> {
    const url = new URL(request.url)
    const path = url.pathname

    // Route format: /auth/{provider}/{action}
    const match = path.match(/\/auth\/([^/]+)\/([^/]+)/)

    if (!match) {
      return new Response("Not Found", { status: 404 })
    }

    const providerId = match[PROVIDER_ID_GROUP]
    const action = match[ACTION_GROUP]

    if (!providerId || !action) {
      return new Response("Not Found", { status: 404 })
    }

    const provider = this.providers.get(providerId)

    if (!provider) {
      return new Response(`Unknown provider: ${providerId}`, { status: 404 })
    }

    const context = this.createContext(request)

    try {
      if (action === "initiate" || action === "send") {
        const result = await provider.initiate(request, context)
        if (result instanceof Response) return result
        return this.initResultToResponse(result)
      }

      if (action === "verify" || action === "callback") {
        const result = await provider.verify(request, context)
        return this.authResultToResponse(result)
      }

      return new Response("Unknown action", { status: 404 })
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error(`Auth error in ${providerId}/${action}:`, error)
      return this.errorToResponse(
        AuthErrors.providerError(
          error instanceof Error ? error.message : "Unknown error",
        ),
      )
    }
  }

  /**
   * Verify session from request and return user
   */
  public async verifySession(
    request: Request,
  ): Promise<{ user: AuthUser; identity: Identity } | null> {
    const session = await this.sessionManager.getSession(request)
    if (!session) return null

    // Get the raw token for caching
    const cookieHeader = request.headers.get("Cookie")
    const token = cookieHeader ? this.extractToken(cookieHeader) : null

    // Check cache
    if (token) {
      const cached = this.sessionCache.get(token)
      if (cached !== undefined) {
        if (cached.user && cached.identity) {
          return { user: cached.user, identity: cached.identity }
        }
        return null
      }
    }

    // Verify user still exists
    const user = await this.config.userStore.findById(session.userId)
    if (!user) {
      if (token) this.sessionCache.set(token, null, null)
      return null
    }

    // Get identity
    const identities = await this.config.identityStore.findByUserId(user.id)
    const identity = identities.find(
      (index) =>
        index.provider === session.provider &&
        index.identifier === session.identifier,
    )

    if (!identity) {
      if (token) this.sessionCache.set(token, null, null)
      return null
    }

    // Cache the result
    if (token) this.sessionCache.set(token, user, identity)

    return { user, identity }
  }

  /**
   * Create a session for a user and return the cookie string
   */
  public async createSessionCookie(
    user: AuthUser,
    identity: Identity,
  ): Promise<string> {
    return this.sessionManager.createSessionCookie(user, identity)
  }

  /**
   * Get a cookie string that destroys the session
   */
  public destroySessionCookie(): string {
    return this.sessionManager.destroySessionCookie()
  }

  /**
   * Get session manager (for advanced use cases)
   */
  public getSessionManager(): SessionManager {
    return this.sessionManager
  }

  /**
   * Get the session configuration
   */
  public getSessionConfig(): SessionConfig {
    return this.config.session
  }

  /**
   * Create the auth context for providers
   * Useful when manually calling provider methods outside of handleRequest
   */
  public createContext(request: Request): AuthContext {
    return {
      identityStore: this.config.identityStore,
      userStore: this.config.userStore,
      baseUrl: this.getBaseUrl(request),
      createSession: (user, identity) =>
        this.sessionManager.createSessionCookie(user, identity),
    }
  }

  /**
   * Extract base URL from request
   */
  private getBaseUrl(request: Request): string {
    const url = new URL(request.url)
    const proto =
      request.headers.get("x-forwarded-proto") ?? url.protocol.replace(":", "")
    return `${proto}://${url.host}`
  }

  /**
   * Extract token from cookie header
   */
  private extractToken(cookieHeader: string): string | null {
    const cookieName = this.config.session.cookieName
    const cookies = cookieHeader.split(";").map((c) => c.trim())
    const target = cookies.find((c) => c.startsWith(`${cookieName}=`))
    if (!target) return null
    return decodeURIComponent(target.split("=")[1] ?? "")
  }

  /**
   * Convert init result to Response
   */
  private initResultToResponse(
    result:
      | { success: true; message: string }
      | { success: false; error: AuthError },
  ): Response {
    if (result.success) {
      return new Response(
        JSON.stringify({ success: true, message: result.message }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      )
    }
    return this.errorToResponse(result.error)
  }

  /**
   * Convert auth result to Response
   */
  private authResultToResponse(result: AuthResult): Response {
    if (result.success) {
      // For successful auth, the provider should have already handled
      // creating the session and redirect. This is a fallback.
      return new Response(
        JSON.stringify({
          success: true,
          user: result.user,
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      )
    }
    return this.errorToResponse(result.error)
  }

  /**
   * Convert error to Response
   */
  private errorToResponse(error: AuthError): Response {
    const statusMap: Record<string, number> = {
      INVALID_TOKEN: 401,
      EXPIRED_TOKEN: 401,
      INVALID_CREDENTIALS: 401,
      SESSION_EXPIRED: 401,
      SESSION_INVALID: 401,
      USER_NOT_FOUND: 404,
      IDENTITY_NOT_FOUND: 404,
      RATE_LIMITED: 429,
      CONFIGURATION_ERROR: 500,
      PROVIDER_ERROR: 500,
    }

    return new Response(JSON.stringify({ success: false, error }), {
      status: statusMap[error.code] ?? 500,
      headers: { "Content-Type": "application/json" },
    })
  }
}

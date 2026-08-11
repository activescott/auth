import type {
  AuthConfig,
  AuthConfigDescription,
  AuthContext,
  AuthError,
  AuthInitResult,
  AuthProvider,
  AuthResponders,
  AuthResult,
  AuthUser,
  ChallengeStore,
  Identity,
  IdentityStore,
  MergeResult,
  SessionConfig,
  UserStore,
} from "./types.js"
import { REDACTED } from "./types.js"
import { SessionManager } from "./session/session-manager.js"
import { AuthenticationError, AuthErrors } from "./errors.js"
import { AbuseGuard } from "./abuse/abuse-guard.js"
import {
  buildChallengeClearingCookie,
  buildReturnUrl,
  initiateAccepted,
  isBrowserFormPost,
  MERGE_TICKET_COOKIE_NAME,
  MERGE_TICKET_TYPE,
  readCookie,
} from "./provider-util.js"

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

/** Sent-message fallback for providers that declare none */
const DEFAULT_SENT_MESSAGE =
  "If that account exists, a sign-in message has been sent."

/**
 * Best-effort name for a store implementation. Stores are usually plain object
 * literals, whose constructor is `Object` — report that plainly instead of
 * showing a misleading "Object".
 */
function describeStoreType(store: object): string {
  const name = store.constructor?.name
  return !name || name === "Object" ? "(object literal)" : name
}

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
  private abuseGuard: AbuseGuard
  private cleanupInterval: ReturnType<typeof setInterval> | null = null

  public constructor(private readonly config: AuthConfig) {
    this.sessionManager = new SessionManager(config.session)
    this.sessionCache = new SessionCache()
    this.abuseGuard = new AbuseGuard(config.abuse, config.session.secret)

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
    this.abuseGuard.destroy()
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
   * Handle an authentication request. URL format: /auth/{provider}/{action}.
   *
   * Dispatch is driven by the provider's declared route table
   * (`getRoutes()`): the route's `handler` decides whether the abuse guard
   * runs (initiate), the verify path is taken, or `handleAction` is called.
   * A method+path with no declared route is 404 (405 when only the method
   * differs). The core-owned `link-merge` action (account merging) is served
   * for every provider.
   *
   * `responders` lets the caller (typically a framework adapter) turn
   * verify outcomes into its own responses — see {@link AuthResponders}.
   */
  public async handleRequest(
    request: Request,
    responders?: AuthResponders,
  ): Promise<Response> {
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
      if (action === "link-merge") {
        return await this.handleLinkMerge(request, providerId)
      }

      const routePath = `/${providerId}/${action}`
      const routes = provider.getRoutes()
      const route = routes.find(
        (candidate) =>
          candidate.path === routePath && candidate.method === request.method,
      )
      if (!route) {
        const pathDeclared = routes.some(
          (candidate) => candidate.path === routePath,
        )
        return pathDeclared
          ? new Response("Method Not Allowed", { status: 405 })
          : new Response("Not Found", { status: 404 })
      }

      switch (route.handler) {
        case "initiate": {
          const decision = await this.abuseGuard.checkInitiate(
            request,
            providerId,
          )
          if (!decision.allowed) {
            return this.blockedInitiateResponse(request, provider, decision)
          }
          const result = await provider.initiate(request, context)
          if (result instanceof Response) return result
          return this.initResultToResponse(result)
        }
        case "verify": {
          const result = await provider.verify(request, context)
          if (result instanceof Response) return result
          return await this.authResultToResponse(result, request, responders)
        }
        case "action": {
          if (!provider.handleAction) {
            return new Response("Not Found", { status: 404 })
          }
          return await provider.handleAction(action, request, context)
        }
      }
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
   * Merge one user's identities into another: every identity of
   * `fromUserId` is reassigned to `intoUserId` (via the store's bulk
   * `reassignByUserId`), then `UserStore.onMerge` lets the application
   * migrate or delete its own data keyed by the absorbed user id. The
   * library never deletes user rows; once the application does, the
   * absorbed user's outstanding sessions die naturally because session
   * verification re-checks `findById` on each request.
   *
   * This is mechanism only — it does not verify that the caller may merge
   * these two users. The built-in `/auth/{provider}/link-merge` endpoint
   * performs that authorization (authenticated session for `intoUserId`
   * plus a merge ticket minted by a fresh possession proof); call this
   * directly only with equivalent checks of your own.
   *
   * @throws AuthenticationError CONFIGURATION_ERROR when the identity store
   * lacks `reassignByUserId`; USER_NOT_FOUND when either user is missing.
   */
  public async mergeUsers(
    fromUserId: string,
    intoUserId: string,
  ): Promise<MergeResult> {
    const { identityStore, userStore } = this.config

    if (fromUserId === intoUserId) {
      throw new AuthenticationError(
        "IDENTITY_CONFLICT",
        "Cannot merge a user into itself",
      )
    }

    const [fromUser, intoUser] = await Promise.all([
      userStore.findById(fromUserId),
      userStore.findById(intoUserId),
    ])
    if (!fromUser || !intoUser) {
      throw new AuthenticationError(
        "USER_NOT_FOUND",
        "Both users must exist to merge them",
        { fromUserFound: Boolean(fromUser), intoUserFound: Boolean(intoUser) },
      )
    }

    const movedIdentities = await identityStore.findByUserId(fromUserId)
    await identityStore.reassignByUserId(fromUserId, intoUserId)
    await userStore.onMerge(fromUser, intoUser)

    return { fromUserId, intoUserId, movedIdentities }
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
   * Get the configured stores.
   * `createContext` exposes the same objects but needs a Request; this is for
   * callers that operate outside a provider flow, such as the admin dashboard.
   */
  public getStores(): {
    identityStore: IdentityStore
    userStore: UserStore
    challengeStore: ChallengeStore
  } {
    return {
      identityStore: this.config.identityStore,
      userStore: this.config.userStore,
      challengeStore: this.config.challengeStore,
    }
  }

  /**
   * Describe the running configuration with every secret removed and every
   * default resolved, for the admin dashboard's config page.
   *
   * Deliberately built field by field rather than by copying `AuthConfig`, so
   * a field added to the config later cannot leak by default — it has to be
   * added here to appear.
   */
  public describeConfig(): AuthConfigDescription {
    const { session, identityStore, userStore, challengeStore } = this.config
    return {
      session: {
        cookieName: session.cookieName,
        maxAge: session.maxAge,
        issuer: session.issuer,
        audience: session.audience,
        cookie: { ...session.cookie },
        secret: REDACTED,
        additionalSecretCount: session.additionalSecrets?.length ?? 0,
      },
      providers: this.getProviders().map((provider) => ({
        id: provider.id,
        name: provider.name,
        initiateSentMessage: provider.initiateSentMessage,
        routes: provider.getRoutes(),
        settings: provider.describe().settings,
      })),
      abuse: this.abuseGuard.describe(),
      stores: {
        userStore: describeStoreType(userStore),
        identityStore: describeStoreType(identityStore),
        challengeStore: describeStoreType(challengeStore),
        capabilities: {
          listUsers: typeof userStore.listUsers === "function",
          findByUserIds: typeof identityStore.findByUserIds === "function",
        },
      },
    }
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
      challengeStore: this.config.challengeStore,
      getSession: (sessionRequest) => this.verifySession(sessionRequest),
      abuse: this.abuseGuard.contextFor(request),
    }
  }

  /**
   * Redeem a merge ticket minted by a link-mode verify that hit an
   * IDENTITY_CONFLICT (see completeLinkVerification). Requirements:
   * the ticket cookie from the browser that proved possession, an
   * unexpired single-use ticket row, and an authenticated session for the
   * user the ticket says survives the merge. Browser form posts are
   * answered with a redirect back to the submitting page (?merged=1);
   * fetch callers get JSON.
   */
  private async handleLinkMerge(
    request: Request,
    providerId: string,
  ): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 })
    }

    const invalidTicket = () =>
      this.errorToResponse(
        AuthErrors.invalidToken({
          reason:
            "Missing, expired, or already-used merge ticket. Verify the identifier again.",
        }),
      )

    const ticketId = readCookie(request, MERGE_TICKET_COOKIE_NAME)
    if (!ticketId) return invalidTicket()

    const ticket = await this.config.challengeStore.findById(ticketId)
    if (!ticket || ticket.type !== MERGE_TICKET_TYPE) return invalidTicket()
    if (ticket.expiresAt.getTime() < Date.now()) return invalidTicket()

    // One redemption attempt per ticket, success or not: a failed attempt
    // (e.g. wrong session) burns it and the user re-verifies possession.
    const attempts = await this.config.challengeStore.incrementAttempts(
      ticket.id,
    )
    if (attempts > ticket.maxAttempts) return invalidTicket()

    const fromUserId = ticket.data?.fromUserId
    const intoUserId = ticket.data?.intoUserId
    const mintedBy = ticket.data?.provider
    if (
      typeof fromUserId !== "string" ||
      typeof intoUserId !== "string" ||
      mintedBy !== providerId
    ) {
      return invalidTicket()
    }

    const session = await this.verifySession(request)
    if (!session || session.user.id !== intoUserId) {
      return this.errorToResponse(
        AuthErrors.sessionInvalid({
          reason: "Sign in as the account you are merging into",
        }),
      )
    }

    // The identifier's ownership can change within the ticket's lifetime
    // (another merge, an unlink); merge only if it still belongs to the user
    // the ticket was minted against.
    const currentOwner =
      await this.config.identityStore.findByProviderAndIdentifier(
        mintedBy,
        ticket.identifier,
      )
    if (!currentOwner || currentOwner.userId !== fromUserId) {
      return invalidTicket()
    }

    await this.config.challengeStore.delete(ticket.id)

    let merged: MergeResult
    try {
      merged = await this.mergeUsers(fromUserId, intoUserId)
    } catch (error) {
      if (error instanceof AuthenticationError) {
        return this.errorToResponse(error.toAuthError())
      }
      throw error
    }

    const clearingCookie = buildChallengeClearingCookie(
      MERGE_TICKET_COOKIE_NAME,
      this.getBaseUrl(request),
    )

    if (isBrowserFormPost(request)) {
      // The submitting page's URL still carries the ?error=IDENTITY_CONFLICT
      // that prompted the merge; drop it so the outcome reads as resolved.
      const returnUrl = new URL(buildReturnUrl(request, { merged: "1" }))
      returnUrl.searchParams.delete("error")
      const headers = new Headers({ Location: returnUrl.toString() })
      headers.append("Set-Cookie", clearingCookie)
      return new Response(null, { status: 302, headers })
    }

    return new Response(
      JSON.stringify({
        success: true,
        merged: {
          fromUserId: merged.fromUserId,
          intoUserId: merged.intoUserId,
          movedIdentityCount: merged.movedIdentities.length,
        },
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": clearingCookie,
        },
      },
    )
  }

  /**
   * Answer a blocked initiate. By default this is byte-identical to what the
   * provider would have returned on success (minus the challenge cookie),
   * so bots get no feedback about which addresses or IPs are throttled;
   * `abuse.respondWith: "rateLimited"` opts into an explicit 429 instead.
   */
  private blockedInitiateResponse(
    request: Request,
    provider: AuthProvider,
    decision: { retryAfterSeconds?: number },
  ): Response {
    if (this.abuseGuard.respondWith === "rateLimited") {
      const response = this.errorToResponse(
        AuthErrors.rateLimited(
          decision.retryAfterSeconds
            ? { retryAfterSeconds: decision.retryAfterSeconds }
            : undefined,
        ),
      )
      if (decision.retryAfterSeconds) {
        response.headers.set("Retry-After", String(decision.retryAfterSeconds))
      }
      return response
    }

    const accepted = initiateAccepted(
      request,
      provider.initiateSentMessage ?? DEFAULT_SENT_MESSAGE,
    )
    return accepted instanceof Response
      ? accepted
      : this.initResultToResponse(accepted)
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
  private initResultToResponse(result: AuthInitResult): Response {
    if (result.success) {
      const headers = new Headers({ "Content-Type": "application/json" })
      for (const cookie of result.setCookies ?? []) {
        headers.append("Set-Cookie", cookie)
      }
      return new Response(
        JSON.stringify({ success: true, message: result.message }),
        {
          status: 200,
          headers,
        },
      )
    }
    return this.errorToResponse(result.error)
  }

  /**
   * Convert a verify outcome to a Response, preferring the caller's
   * responders (a framework adapter creating a session cookie and redirect)
   * over the default JSON.
   */
  private async authResultToResponse(
    result: AuthResult,
    request: Request,
    responders?: AuthResponders,
  ): Promise<Response> {
    if (result.success) {
      if (responders?.onSuccess) {
        return responders.onSuccess(result, request)
      }
      const headers = new Headers({ "Content-Type": "application/json" })
      for (const cookie of result.setCookies ?? []) {
        headers.append("Set-Cookie", cookie)
      }
      return new Response(
        JSON.stringify({
          success: true,
          user: result.user,
        }),
        {
          status: 200,
          headers,
        },
      )
    }
    if (responders?.onFailure) {
      return responders.onFailure(result, request)
    }
    return this.errorToResponse(result.error, result.setCookies)
  }

  /**
   * Convert error to Response. Failures can carry cookies too — e.g. the
   * merge ticket that accompanies an IDENTITY_CONFLICT.
   */
  private errorToResponse(error: AuthError, setCookies?: string[]): Response {
    const statusMap: Record<string, number> = {
      INVALID_TOKEN: 401,
      EXPIRED_TOKEN: 401,
      INVALID_CREDENTIALS: 401,
      SESSION_EXPIRED: 401,
      SESSION_INVALID: 401,
      USER_NOT_FOUND: 404,
      IDENTITY_NOT_FOUND: 404,
      IDENTITY_CONFLICT: 409,
      RATE_LIMITED: 429,
      CONFIGURATION_ERROR: 500,
      PROVIDER_ERROR: 500,
    }

    const headers = new Headers({ "Content-Type": "application/json" })
    for (const cookie of setCookies ?? []) {
      headers.append("Set-Cookie", cookie)
    }
    return new Response(JSON.stringify({ success: false, error }), {
      status: statusMap[error.code] ?? 500,
      headers,
    })
  }
}

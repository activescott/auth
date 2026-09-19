import { parseDuration, resolveRedirectTarget } from "@activescott/auth"
import type { Auth, AuthUser, Identity, AuthError } from "@activescott/auth"

const MS_PER_SECOND = 1000

/**
 * Rolling-session settings for {@link AuthHandlers.renewSessionCookie}
 */
export interface SessionRenewalOptions {
  /**
   * How old a session may get before `renewSessionCookie` re-issues it, as a
   * duration string like `"7d"` (same format as `SessionConfig.maxAge`).
   * Somewhere well inside `maxAge`: a session older than `maxAge` is already
   * gone, and renewing on every request re-signs a JWT the visitor did not
   * need.
   */
  renewAfter: string
}

/**
 * Runs on every verified session, before `getSession`, `requireAuth` and
 * `optionalAuth` hand it to your loader. Return or throw a `Response` to
 * bounce the request with it (a redirect to a waitlist page, a logout);
 * return nothing to let the session through.
 *
 * This is where a check that has to be current lives: whether the account is
 * still approved, whether it was blocked a second ago. Pair it with
 * `session.cacheTtlMs: 0` on `AuthConfig` so `session.user` is what your
 * store says right now rather than what it said up to two minutes ago.
 *
 * It does not run in `renewSessionCookie` or `refreshSessionCookie`; those
 * re-issue a cookie for a session a loader already accepted.
 *
 * @typeParam TUser - Your application's user type (defaults to AuthUser)
 */
export type OnSessionVerified<TUser = AuthUser> = (
  session: AuthSession<TUser>,
  request: Request,
) => void | Response | Promise<void | Response>

/**
 * Options for creating auth handlers
 * @typeParam TUser - Your application's user type (defaults to AuthUser)
 */
export interface CreateAuthHandlersOptions<TUser = AuthUser> {
  /** URL to redirect to after successful authentication */
  successRedirect?: string | ((user: AuthUser, identity: Identity) => string)
  /**
   * URL to redirect to on authentication error. The string form appends
   * `?error=<code>` to a fixed path, which drops any query the form was
   * submitted from (a `?tab=` or `?via=` selection, for example). The
   * function form receives the failing request, so pass core's
   * `buildReturnUrl(request, { error: error.code })` to send the browser back
   * to the exact page it posted from.
   */
  errorRedirect?: string | ((error: AuthError, request: Request) => string)
  /** URL to redirect unauthenticated users to */
  loginUrl?: string
  /**
   * Map AuthUser to your application's user type.
   * If provided, requireAuth and optionalAuth will return TUser instead of AuthUser.
   */
  mapUser?: (user: AuthUser, identity: Identity) => TUser
  /**
   * Rolling sessions. Required by `renewSessionCookie`, which throws
   * without it.
   */
  session?: SessionRenewalOptions
  /**
   * Last word on whether a verified session may proceed. See
   * {@link OnSessionVerified}. Runs in `getSession`, `requireAuth` and
   * `optionalAuth`, after `mapUser`.
   */
  onSessionVerified?: OnSessionVerified<TUser>
}

/**
 * Result of getSession - includes both user and identity
 * @typeParam TUser - Your application's user type (defaults to AuthUser)
 */
export interface AuthSession<TUser = AuthUser> {
  user: TUser
  identity: Identity
}

/**
 * Auth handlers returned by createAuthHandlers
 * @typeParam TUser - Your application's user type (defaults to AuthUser)
 */
export interface AuthHandlers<TUser = AuthUser> {
  handleAuth: (context: { request: Request }) => Promise<Response>
  getSession: (request: Request) => Promise<AuthSession<TUser> | null>
  requireAuth: (request: Request, redirectTo?: string) => Promise<TUser>
  optionalAuth: (request: Request) => Promise<TUser | null>
  renewSessionCookie: (
    request: Request,
    user: AuthUser,
  ) => Promise<string | null>
  refreshSessionCookie: (
    request: Request,
    updatedUser: AuthUser,
  ) => Promise<string>
  clearSessionCookie: () => string
  logout: (redirectTo?: string) => Response
  getAuth: () => Auth
}

/**
 * Create a redirect Response
 */
function redirect(url: string, init?: ResponseInit): Response {
  // Copy via Headers (not Object.fromEntries) so multiple Set-Cookie
  // headers survive
  const headers = new Headers(init?.headers)
  headers.set("Location", url)
  return new Response(null, {
    ...init,
    status: 302,
    headers,
  })
}

/**
 * Create React Router compatible auth handlers
 * @typeParam TUser - Your application's user type (defaults to AuthUser)
 */
export function createAuthHandlers<TUser = AuthUser>(
  auth: Auth,
  options: CreateAuthHandlersOptions<TUser> = {},
): AuthHandlers<TUser> {
  const {
    successRedirect = "/",
    errorRedirect = "/login",
    loginUrl = "/login",
    mapUser,
    session: sessionOptions,
    onSessionVerified,
  } = options

  // Default mapper returns user as-is (safe when TUser = AuthUser)
  const userMapper = mapUser ?? ((user: AuthUser) => user as unknown as TUser)

  /**
   * The one path to a session the app is allowed to act on: verify the
   * cookie, map the user, then give `onSessionVerified` its veto. A hook that
   * returns a Response is thrown, so returning and throwing one mean the same
   * thing to the caller and the loader above never sees the session.
   */
  async function verifiedSession(
    request: Request,
  ): Promise<AuthSession<TUser> | null> {
    const session = await auth.verifySession(request)
    if (!session) return null

    const mapped: AuthSession<TUser> = {
      user: userMapper(session.user, session.identity),
      identity: session.identity,
    }
    if (onSessionVerified) {
      const bounce = await onSessionVerified(mapped, request)
      if (bounce instanceof Response) throw bounce
    }
    return mapped
  }

  // Parse the renewal threshold once, at startup: a typo here would
  // otherwise read as zero and renew the cookie on every single request.
  const renewAfterSeconds = sessionOptions
    ? parseDuration(sessionOptions.renewAfter)
    : 0
  if (sessionOptions && renewAfterSeconds <= 0) {
    throw new Error(
      `Invalid session.renewAfter ${JSON.stringify(sessionOptions.renewAfter)}: expected a duration like "7d"`,
    )
  }

  return {
    /**
     * Handle auth requests (for catch-all auth routes).
     * Use in a route like /auth/$provider/$action.
     *
     * All dispatch lives in `Auth.handleRequest`; this adapter only supplies
     * the responders that turn a verify outcome into a browser flow —
     * session cookie plus redirect on success, error redirect on failure.
     * Providers that answer with a Response themselves (the email confirm
     * page, passkey JSON) pass through untouched, as do initiate results.
     */
    async handleAuth({ request }: { request: Request }): Promise<Response> {
      return auth.handleRequest(request, {
        onSuccess: async (result, successRequest) => {
          const sessionCookie = await auth.createSessionCookie(
            result.user,
            result.identity,
          )

          // ?redirectTo= on the verify URL (saved during the login flow)
          // wins over the configured default, as long as it names a page on
          // this app. Anything else falls through to successRedirect, and is
          // reported to the app's logger when it configured one.
          const requestedRedirect = resolveRedirectTarget(
            new URL(successRequest.url).searchParams.get("redirectTo"),
            successRequest.url,
            "",
            { logger: auth.getLogger(), source: "redirectTo" },
          )
          let redirectUrl: string
          if (requestedRedirect) {
            redirectUrl = requestedRedirect
          } else if (typeof successRedirect === "function") {
            redirectUrl = successRedirect(result.user, result.identity)
          } else {
            redirectUrl = successRedirect
          }

          // Providers may return additional cookies to set (e.g., clearing
          // an OTP challenge cookie after successful code verification)
          const headers = new Headers()
          headers.append("Set-Cookie", sessionCookie)
          for (const cookie of result.setCookies ?? []) {
            headers.append("Set-Cookie", cookie)
          }
          return redirect(redirectUrl, { headers })
        },
        onFailure: async (failure, failureRequest) => {
          const errorUrl =
            typeof errorRedirect === "function"
              ? errorRedirect(failure.error, failureRequest)
              : `${errorRedirect}?error=${encodeURIComponent(failure.error.code)}`
          // Failures can carry cookies — e.g. the merge ticket accompanying
          // an IDENTITY_CONFLICT from a link-mode verify.
          const headers = new Headers()
          for (const cookie of failure.setCookies ?? []) {
            headers.append("Set-Cookie", cookie)
          }
          return redirect(errorUrl, { headers })
        },
      })
    },

    /**
     * Get current session (returns null if not authenticated)
     * Returns both the mapped user and identity
     *
     * @throws Response whatever `onSessionVerified` returned or threw
     */
    async getSession(request: Request): Promise<AuthSession<TUser> | null> {
      return verifiedSession(request)
    },

    /**
     * Require authentication - redirects to login if not authenticated
     * Returns the mapped user
     *
     * @throws Response the login redirect, or whatever `onSessionVerified`
     * returned or threw
     */
    async requireAuth(request: Request, redirectTo?: string): Promise<TUser> {
      const session = await verifiedSession(request)

      if (!session) {
        const url = new URL(request.url)
        const returnTo = url.pathname + url.search
        const loginRedirect = `${redirectTo ?? loginUrl}?redirectTo=${encodeURIComponent(returnTo)}`
        throw redirect(loginRedirect)
      }

      return session.user
    },

    /**
     * Optional authentication - returns null if not authenticated
     * Returns the mapped user or null
     *
     * @throws Response whatever `onSessionVerified` returned or threw
     */
    async optionalAuth(request: Request): Promise<TUser | null> {
      const session = await verifiedSession(request)
      return session?.user ?? null
    },

    /**
     * Rolling sessions: re-issue the session cookie once it is older than
     * `session.renewAfter`, so someone who keeps using the app stays signed
     * in while an idle session still expires at `maxAge`. Returns null when
     * the session is still fresh, when there is no session, and when the
     * session no longer resolves to a user (blocked, deleted); pass the
     * cookie to `Set-Cookie` when you get one.
     *
     * Call it from the root loader, which every navigation runs.
     *
     * @param request - The current request
     * @param user - The user to encode, normally the one you just loaded
     * @returns A Set-Cookie header value, or null to leave the cookie alone
     * @throws Error if `session.renewAfter` was not configured
     *
     * @example
     * ```typescript
     * // In your root loader, after loading the session user:
     * const cookie = user && (await renewSessionCookie(request, user))
     * if (cookie) {
     *   return data(loaderData, { headers: { "Set-Cookie": cookie } })
     * }
     * return loaderData
     * ```
     */
    async renewSessionCookie(
      request: Request,
      user: AuthUser,
    ): Promise<string | null> {
      if (renewAfterSeconds <= 0) {
        throw new Error(
          "Cannot renew session: pass session.renewAfter to createAuthHandlers",
        )
      }

      // The raw session carries issuedAt, which verifySession drops. Read it
      // first so a fresh session costs one signature check and nothing else.
      const current = await auth.getSessionManager().getSession(request)
      if (!current) return null
      const ageSeconds =
        Math.floor(Date.now() / MS_PER_SECOND) - current.issuedAt
      if (ageSeconds < renewAfterSeconds) return null

      const session = await auth.verifySession(request)
      if (!session) return null
      return auth.createSessionCookie(user, session.identity)
    },

    /**
     * Refresh the session cookie with updated user data.
     * Use this when user profile data changes (e.g., handle, display name)
     * to update the session without requiring re-authentication. To extend a
     * session that is merely getting old, use `renewSessionCookie`.
     *
     * @param request - The current request (to get existing session/identity)
     * @param updatedUser - The user object with updated fields
     * @returns The Set-Cookie header value for the new session
     * @throws Error if no active session exists
     *
     * @example
     * ```typescript
     * // In a profile update action:
     * await userRepository.updateHandle(user.id, newHandle)
     * const updatedUser = { ...user, handle: newHandle }
     * const cookie = await refreshSessionCookie(request, updatedUser)
     * throw redirect("/profile?success=updated", {
     *   headers: { "Set-Cookie": cookie }
     * })
     * ```
     */
    async refreshSessionCookie(
      request: Request,
      updatedUser: AuthUser,
    ): Promise<string> {
      const session = await auth.verifySession(request)
      if (!session) {
        throw new Error("Cannot refresh session: no active session found")
      }
      return auth.createSessionCookie(updatedUser, session.identity)
    },

    /**
     * The `Set-Cookie` value that expires the session cookie, for when you
     * want the header and not the redirect `logout` wraps it in: attaching it
     * to a page you are already rendering, or to a Response you throw from
     * `onSessionVerified`.
     *
     * @example
     * ```typescript
     * // In a loader that decided this session should not continue:
     * throw redirect("/login", {
     *   headers: { "Set-Cookie": clearSessionCookie() },
     * })
     * ```
     */
    clearSessionCookie(): string {
      return auth.destroySessionCookie()
    },

    /**
     * Create a logout response that clears the session
     */
    logout(redirectTo = "/"): Response {
      const cookie = auth.destroySessionCookie()
      return redirect(redirectTo, {
        headers: {
          "Set-Cookie": cookie,
        },
      })
    },

    /**
     * Get the auth instance for advanced use cases
     */
    getAuth(): Auth {
      return auth
    },
  }
}

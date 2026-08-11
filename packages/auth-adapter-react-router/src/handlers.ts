import type { Auth, AuthUser, Identity, AuthError } from "@activescott/auth"

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
  refreshSessionCookie: (
    request: Request,
    updatedUser: AuthUser,
  ) => Promise<string>
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
  } = options

  // Default mapper returns user as-is (safe when TUser = AuthUser)
  const userMapper = mapUser ?? ((user: AuthUser) => user as unknown as TUser)

  return {
    /**
     * Handle auth requests (for catch-all auth routes)
     * Use in a route like /auth/$provider/$action
     */
    async handleAuth({ request }: { request: Request }): Promise<Response> {
      const url = new URL(request.url)
      const path = url.pathname

      // Exact action match: only the verify|callback actions get the
      // session-and-redirect handling below. Provider-specific actions
      // whose names merely contain "verify" (e.g. the passkey
      // provider's register-verify) fall through to auth.handleRequest.
      const actionMatch = path.match(/\/auth\/[^/]+\/([^/]+)/)
      const action = actionMatch?.[1]
      const isVerify = action === "verify" || action === "callback"

      if (!isVerify) {
        // For initiate requests, use the default handler
        return auth.handleRequest(request)
      }

      // For verify requests, we need to handle the response specially
      // to create a session and redirect
      const match = path.match(/\/auth\/([^/]+)\//)
      if (!match) {
        return new Response("Not Found", { status: 404 })
      }

      const providerId = match[1]
      if (!providerId) {
        return new Response("Not Found", { status: 404 })
      }

      const provider = auth.getProvider(providerId)

      if (!provider) {
        return new Response(`Unknown provider: ${providerId}`, { status: 404 })
      }

      // Create context and verify
      const context = auth.createContext(request)
      const result = await provider.verify(request, context)

      // Providers may answer with a page instead of an auth outcome —
      // e.g., the email provider's confirm page on magic-link GET
      if (result instanceof Response) {
        return result
      }

      if (!result.success) {
        const errorUrl =
          typeof errorRedirect === "function"
            ? errorRedirect(result.error, request)
            : `${errorRedirect}?error=${encodeURIComponent(result.error.code)}`
        // Failures can carry cookies — e.g. the merge ticket accompanying
        // an IDENTITY_CONFLICT from a link-mode verify.
        const headers = new Headers()
        for (const cookie of result.setCookies ?? []) {
          headers.append("Set-Cookie", cookie)
        }
        return redirect(errorUrl, { headers })
      }

      // Create session cookie
      const sessionCookie = await auth.createSessionCookie(
        result.user,
        result.identity,
      )

      // Providers may return additional cookies to set (e.g., clearing an
      // OTP challenge cookie after successful code verification)
      const extraCookies = result.setCookies ?? []

      // Check for redirectTo query param (set during login flow)
      const redirectToParameter = url.searchParams.get("redirectTo")

      // Determine redirect URL: use redirectTo param if present, otherwise use configured default
      let redirectUrl: string
      if (redirectToParameter) {
        // Use the saved redirect destination from before login
        redirectUrl = redirectToParameter
      } else if (typeof successRedirect === "function") {
        redirectUrl = successRedirect(result.user, result.identity)
      } else {
        redirectUrl = successRedirect
      }

      const headers = new Headers()
      headers.append("Set-Cookie", sessionCookie)
      for (const cookie of extraCookies) {
        headers.append("Set-Cookie", cookie)
      }
      return redirect(redirectUrl, { headers })
    },

    /**
     * Get current session (returns null if not authenticated)
     * Returns both the mapped user and identity
     */
    async getSession(request: Request): Promise<AuthSession<TUser> | null> {
      const session = await auth.verifySession(request)
      if (!session) return null
      return {
        user: userMapper(session.user, session.identity),
        identity: session.identity,
      }
    },

    /**
     * Require authentication - redirects to login if not authenticated
     * Returns the mapped user
     */
    async requireAuth(request: Request, redirectTo?: string): Promise<TUser> {
      const session = await auth.verifySession(request)

      if (!session) {
        const url = new URL(request.url)
        const returnTo = url.pathname + url.search
        const loginRedirect = `${redirectTo ?? loginUrl}?redirectTo=${encodeURIComponent(returnTo)}`
        throw redirect(loginRedirect)
      }

      return userMapper(session.user, session.identity)
    },

    /**
     * Optional authentication - returns null if not authenticated
     * Returns the mapped user or null
     */
    async optionalAuth(request: Request): Promise<TUser | null> {
      const session = await auth.verifySession(request)
      if (!session) return null
      return userMapper(session.user, session.identity)
    },

    /**
     * Refresh the session cookie with updated user data.
     * Use this when user profile data changes (e.g., handle, display name)
     * to update the session without requiring re-authentication.
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

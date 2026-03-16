import type { Auth, AuthUser, Identity, AuthError } from "@activescott/auth"

/**
 * Options for creating auth handlers
 * @typeParam TUser - Your application's user type (defaults to AuthUser)
 */
export interface CreateAuthHandlersOptions<TUser = AuthUser> {
  /** URL to redirect to after successful authentication */
  successRedirect?: string | ((user: AuthUser, identity: Identity) => string)
  /** URL to redirect to on authentication error */
  errorRedirect?: string | ((error: AuthError) => string)
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
  return new Response(null, {
    ...init,
    status: 302,
    headers: {
      ...Object.fromEntries(new Headers(init?.headers).entries()),
      Location: url,
    },
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

      // Check if this is a verify/callback request
      const isVerify = path.includes("/verify") || path.includes("/callback")

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

      if (!result.success) {
        const errorUrl =
          typeof errorRedirect === "function"
            ? errorRedirect(result.error)
            : `${errorRedirect}?error=${encodeURIComponent(result.error.code)}`
        return redirect(errorUrl)
      }

      // Create session cookie
      const sessionCookie = await auth.createSessionCookie(
        result.user,
        result.identity,
      )

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

      return redirect(redirectUrl, {
        headers: {
          "Set-Cookie": sessionCookie,
        },
      })
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

/**
 * Result of sendMagicLink operation
 */
export interface SendMagicLinkResult {
  success: boolean
  message?: string
  error?: string
}

/**
 * Options for sending a magic link
 */
export interface SendMagicLinkOptions {
  /** URL to redirect to after successful authentication */
  redirectTo?: string
}

/**
 * Send a magic link email to the user.
 * This is a convenience function for login pages that want to stay on the page
 * and show success/error messages rather than redirecting.
 *
 * @param auth - The Auth instance
 * @param email - The email address to send the magic link to
 * @param baseUrl - The base URL of the application (e.g., "https://example.com")
 * @param options - Optional settings including redirectTo URL
 * @returns Result indicating success or failure with appropriate message
 *
 * @example
 * ```typescript
 * export async function action({ request }: ActionArgs) {
 *   const formData = await request.formData()
 *   const email = formData.get("email") as string
 *   const redirectTo = formData.get("redirectTo") as string | null
 *   const result = await sendMagicLink(auth, email, getBaseUrl(request), { redirectTo })
 *   return result.success
 *     ? { success: "Check your email!", error: null }
 *     : { error: result.error, success: null }
 * }
 * ```
 */
export async function sendMagicLink(
  auth: Auth,
  email: string,
  baseUrl: string,
  options?: SendMagicLinkOptions,
): Promise<SendMagicLinkResult> {
  const provider = auth.getProvider("email")

  if (!provider) {
    return {
      success: false,
      error: "Email authentication is not configured.",
    }
  }

  // Build request body with email and optional redirectTo
  const body: Record<string, string> = { email }
  if (options?.redirectTo) {
    body.redirectTo = options.redirectTo
  }

  // Create a request that the provider can handle
  const request = new Request(`${baseUrl}/auth/email/initiate`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body),
  })

  const context = auth.createContext(request)

  try {
    const result = await provider.initiate(request, context)

    // If provider returns a Response, it handled everything (unlikely for email)
    if (result instanceof Response) {
      return {
        success: true,
        message: "Check your email for a magic link to sign in.",
      }
    }

    if (result.success) {
      return {
        success: true,
        message:
          result.message || "Check your email for a magic link to sign in.",
      }
    }

    return {
      success: false,
      error:
        result.error.message || "Failed to send magic link. Please try again.",
    }
  } catch (error) {
    return {
      success: false,
      error:
        error instanceof Error
          ? error.message
          : "An unexpected error occurred.",
    }
  }
}

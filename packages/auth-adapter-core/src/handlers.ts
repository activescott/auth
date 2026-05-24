import type { Auth, AuthUser, Identity, AuthError } from '@activescott/auth';

/**
 * Options for creating auth handlers
 * @typeParam TUser - Your application's user type (defaults to AuthUser)
 */
export interface CreateAuthHandlersOptions<TUser = AuthUser> {
  /** URL to redirect to after successful authentication */
  successRedirect?: string | ((user: AuthUser, identity: Identity) => string);
  /** URL to redirect to on authentication error */
  errorRedirect?: string | ((error: AuthError) => string);
  /** URL to redirect unauthenticated users to */
  loginUrl?: string;
  /**
   * Map AuthUser to your application's user type.
   * If provided, requireAuth and optionalAuth will return TUser instead of AuthUser.
   */
  mapUser?: (user: AuthUser, identity: Identity) => TUser;
}

/**
 * Result of getSession - includes both user and identity
 * @typeParam TUser - Your application's user type (defaults to AuthUser)
 */
export interface AuthSession<TUser = AuthUser> {
  user: TUser;
  identity: Identity;
}

/**
 * Auth handlers returned by createAuthHandlers
 * @typeParam TUser - Your application's user type (defaults to AuthUser)
 */
export interface AuthHandlers<TUser = AuthUser> {
  handleAuth: (context: { request: Request }) => Promise<Response>;
  getSession: (request: Request) => Promise<AuthSession<TUser> | null>;
  requireAuth: (request: Request, redirectTo?: string) => Promise<TUser>;
  optionalAuth: (request: Request) => Promise<TUser | null>;
  refreshSessionCookie: (request: Request, updatedUser: AuthUser) => Promise<string>;
  logout: (redirectTo?: string) => Response;
  getAuth: () => Auth;
}

function redirect(url: string, init?: ResponseInit): Response {
  return new Response(null, {
    ...init,
    status: 302,
    headers: {
      ...Object.fromEntries(new Headers(init?.headers).entries()),
      Location: url
    }
  });
}

/**
 * Create framework-agnostic auth handlers around an Auth instance.
 * Each framework adapter re-exports this and adds its own middleware on top.
 * @typeParam TUser - Your application's user type (defaults to AuthUser)
 */
export function createAuthHandlers<TUser = AuthUser>(
  auth: Auth,
  options: CreateAuthHandlersOptions<TUser> = {}
): AuthHandlers<TUser> {
  const { successRedirect = '/', errorRedirect = '/login', loginUrl = '/login', mapUser } = options;

  const userMapper = mapUser ?? ((user: AuthUser) => user as unknown as TUser);

  return {
    async handleAuth({ request }: { request: Request }): Promise<Response> {
      const url = new URL(request.url);
      const path = url.pathname;

      const isVerify = path.includes('/verify') || path.includes('/callback');

      if (!isVerify) {
        return auth.handleRequest(request);
      }

      const match = path.match(/\/auth\/([^/]+)\//);
      if (!match) {
        return new Response('Not Found', { status: 404 });
      }

      const providerId = match[1];
      if (!providerId) {
        return new Response('Not Found', { status: 404 });
      }

      const provider = auth.getProvider(providerId);

      if (!provider || provider.enabled === false) {
        return new Response('Not Found', { status: 404 });
      }

      const context = auth.createContext(request);
      const result = await provider.verify(request, context);

      if (!result.success) {
        const errorUrl =
          typeof errorRedirect === 'function'
            ? errorRedirect(result.error)
            : `${errorRedirect}?error=${encodeURIComponent(result.error.code)}`;
        return redirect(errorUrl);
      }

      const sessionCookie = await auth.createSessionCookie(result.user, result.identity);

      const redirectToParameter = url.searchParams.get('redirectTo');

      let redirectUrl: string;
      if (redirectToParameter) {
        redirectUrl = redirectToParameter;
      } else if (typeof successRedirect === 'function') {
        redirectUrl = successRedirect(result.user, result.identity);
      } else {
        redirectUrl = successRedirect;
      }

      return redirect(redirectUrl, {
        headers: {
          'Set-Cookie': sessionCookie
        }
      });
    },

    async getSession(request: Request): Promise<AuthSession<TUser> | null> {
      const session = await auth.verifySession(request);
      if (!session) return null;
      return {
        user: userMapper(session.user, session.identity),
        identity: session.identity
      };
    },

    async requireAuth(request: Request, redirectTo?: string): Promise<TUser> {
      const session = await auth.verifySession(request);

      if (!session) {
        const url = new URL(request.url);
        const returnTo = url.pathname + url.search;
        const loginRedirect = `${redirectTo ?? loginUrl}?redirectTo=${encodeURIComponent(returnTo)}`;
        throw redirect(loginRedirect);
      }

      return userMapper(session.user, session.identity);
    },

    async optionalAuth(request: Request): Promise<TUser | null> {
      const session = await auth.verifySession(request);
      if (!session) return null;
      return userMapper(session.user, session.identity);
    },

    /**
     * Refresh the session cookie with updated user data.
     * Use when profile fields change without requiring re-authentication.
     * @throws Error if no active session exists
     */
    async refreshSessionCookie(request: Request, updatedUser: AuthUser): Promise<string> {
      const session = await auth.verifySession(request);
      if (!session) {
        throw new Error('Cannot refresh session: no active session found');
      }
      return auth.createSessionCookie(updatedUser, session.identity);
    },

    logout(redirectTo = '/'): Response {
      const cookie = auth.destroySessionCookie();
      return redirect(redirectTo, {
        headers: {
          'Set-Cookie': cookie
        }
      });
    },

    getAuth(): Auth {
      return auth;
    }
  };
}

/**
 * Result of sendMagicLink operation
 */
export interface SendMagicLinkResult {
  success: boolean;
  message?: string;
  error?: string;
}

/**
 * Options for sending a magic link
 */
export interface SendMagicLinkOptions {
  /** URL to redirect to after successful authentication */
  redirectTo?: string;
}

/**
 * Send a magic link email to the user.
 * Returns a plain result object so login pages can show success/error messages
 * without a redirect.
 *
 * @example
 * ```typescript
 * const result = await sendMagicLink(auth, email, getBaseUrl(request), { redirectTo })
 * return result.success
 *   ? { success: "Check your email!", error: null }
 *   : { error: result.error, success: null }
 * ```
 */
export async function sendMagicLink(
  auth: Auth,
  email: string,
  baseUrl: string,
  options?: SendMagicLinkOptions
): Promise<SendMagicLinkResult> {
  const provider = auth.getProvider('email');

  if (!provider) {
    return {
      success: false,
      error: 'Email authentication is not configured.'
    };
  }

  const body: Record<string, string> = { email };
  if (options?.redirectTo) {
    body.redirectTo = options.redirectTo;
  }

  const request = new Request(`${baseUrl}/auth/email/initiate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body)
  });

  const context = auth.createContext(request);

  try {
    const result = await provider.initiate(request, context);

    if (result instanceof Response) {
      return {
        success: true,
        message: 'Check your email for a magic link to sign in.'
      };
    }

    if (result.success) {
      return {
        success: true,
        message: result.message || 'Check your email for a magic link to sign in.'
      };
    }

    return {
      success: false,
      error: result.error.message || 'Failed to send magic link. Please try again.'
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'An unexpected error occurred.'
    };
  }
}

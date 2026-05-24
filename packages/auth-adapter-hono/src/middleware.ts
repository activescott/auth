import type { Context, MiddlewareHandler, Next } from 'hono';
import type { AuthUser } from '@activescott/auth';
import type { AuthHandlers } from './handlers.js';

/**
 * Hono middleware that requires an authenticated session.
 * Sets `c.set('user', user)` on success; returns a 302 redirect on failure.
 *
 * @example
 * ```ts
 * app.use('/dashboard/*', requireAuthMiddleware(handlers))
 * app.get('/dashboard', (c) => {
 *   const user = c.get('user') as AppUser
 *   return c.json({ user })
 * })
 * ```
 */
export function requireAuthMiddleware<TUser = AuthUser>(
  handlers: AuthHandlers<TUser>,
  redirectTo?: string
): MiddlewareHandler {
  return async (c: Context, next: Next): Promise<Response | void> => {
    try {
      const user = await handlers.requireAuth(c.req.raw, redirectTo);
      c.set('user', user);
      await next();
    } catch (e) {
      // requireAuth throws a redirect Response when unauthenticated
      if (e instanceof Response) return e;
      throw e;
    }
  };
}

/**
 * Hono middleware that optionally reads an authenticated session.
 * Sets `c.set('user', user)` when authenticated, `c.set('user', null)` otherwise.
 * Never redirects — use this for routes that serve both signed-in and signed-out users.
 */
export function optionalAuthMiddleware<TUser = AuthUser>(
  handlers: AuthHandlers<TUser>
): MiddlewareHandler {
  return async (c: Context, next: Next): Promise<void> => {
    const user = await handlers.optionalAuth(c.req.raw);
    c.set('user', user);
    await next();
  };
}

/**
 * Returns a Hono route handler that delegates to handleAuth.
 * Mount it on a wildcard route to handle all auth endpoints:
 *
 * @example
 * ```ts
 * app.all('/auth/:provider/:action', createAuthHandler(handlers))
 * // handles /auth/email/initiate, /auth/email/verify,
 * //         /auth/google/callback, /auth/github/callback, etc.
 * ```
 */
export function createAuthHandler<TUser = AuthUser>(
  handlers: AuthHandlers<TUser>
): (c: Context) => Promise<Response> {
  return (c: Context): Promise<Response> => handlers.handleAuth({ request: c.req.raw });
}

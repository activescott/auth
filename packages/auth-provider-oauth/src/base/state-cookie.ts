import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

const STATE_COOKIE_NAME = '__oauth_state';
const STATE_COOKIE_MAX_AGE_SECONDS = 600; // 10 minutes

/**
 * Payload stored in the short-lived OAuth state cookie.
 * Survives the browser round-trip between initiate and callback.
 */
export interface OAuthStateCookiePayload {
  /** Random nonce — verified against the ?state= param in the callback */
  state: string;
  /** PKCE code_verifier — used in the token exchange */
  codeVerifier: string;
  /** Provider id — prevents cross-provider state replay */
  provider: string;
  /** Optional post-login destination */
  redirectTo?: string;
}

export interface StateCookieOptions {
  secure?: boolean;
}

/**
 * Generate a cryptographically random state string for CSRF protection.
 */
export function generateState(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Generate a PKCE code_verifier and S256 code_challenge pair.
 * The challenge is BASE64URL(SHA256(verifier)) per RFC 7636.
 */
export function generatePKCE(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
}

/**
 * Sign the OAuth state payload into a short-lived JWT and return a Set-Cookie header value.
 * Cookie is HttpOnly, SameSite=Lax, Path=/auth, Max-Age=600.
 */
export function createStateCookie(
  payload: OAuthStateCookiePayload,
  secret: string,
  options: StateCookieOptions = {}
): string {
  const token = jwt.sign(payload, secret, {
    expiresIn: STATE_COOKIE_MAX_AGE_SECONDS,
    issuer: 'auth-oauth-state',
    audience: 'auth'
  });

  const parts = [
    `${STATE_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/auth',
    `Max-Age=${STATE_COOKIE_MAX_AGE_SECONDS}`,
    'HttpOnly',
    'SameSite=Lax'
  ];

  if (options.secure) {
    parts.push('Secure');
  }

  return parts.join('; ');
}

/**
 * Read and verify the OAuth state cookie from a request.
 * Returns null if the cookie is missing, expired, tampered, or signed with a different secret.
 */
export function readStateCookie(request: Request, secret: string): OAuthStateCookiePayload | null {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(';').map((c) => c.trim());
  const target = cookies.find((c) => c.startsWith(`${STATE_COOKIE_NAME}=`));
  if (!target) return null;

  const token = decodeURIComponent(target.split('=')[1] ?? '');
  if (!token) return null;

  try {
    const payload = jwt.verify(token, secret, {
      issuer: 'auth-oauth-state',
      audience: 'auth'
    }) as OAuthStateCookiePayload;

    if (!payload.state || !payload.provider || payload.codeVerifier == null) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

/**
 * Return a Set-Cookie header value that immediately clears the OAuth state cookie.
 * Call this after consuming the state in the callback to prevent replay.
 */
export function clearStateCookie(): string {
  return `${STATE_COOKIE_NAME}=; Path=/auth; Max-Age=0; HttpOnly; SameSite=Lax`;
}

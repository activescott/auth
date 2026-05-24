import jwt from 'jsonwebtoken';
import { type Page, test } from '@playwright/test';

/**
 * E2E auth helper — mints a magic-link token signed with the
 * `E2E_MAGIC_LINK_SECRET`, then visits the verify URL to log the user in.
 *
 * The server's EmailProvider is configured with this secret in its
 * `additionalSecrets` list (see `app/lib/auth.server.ts`), so tokens minted
 * here verify against the same code path real magic links use — no SMTP
 * server, no inbox polling, no flaky test waits.
 */
const E2E_MAGIC_LINK_SECRET = process.env.E2E_MAGIC_LINK_SECRET ?? 'e2e_test_magic_link_secret';

export function mintMagicLinkToken(email: string): string {
  return jwt.sign({ email }, E2E_MAGIC_LINK_SECRET, {
    expiresIn: '5m',
    issuer: 'auth-magic-link',
    audience: 'auth'
  });
}

export async function loginAs(page: Page, email: string): Promise<void> {
  const baseURL = test.info().project.use.baseURL;
  if (!baseURL) {
    throw new Error('baseURL is required in playwright.config.ts');
  }
  const token = mintMagicLinkToken(email);
  await page.goto(`${baseURL}/auth/email/verify?token=${token}`, {
    waitUntil: 'networkidle'
  });
  if (page.url().includes('/login')) {
    throw new Error(`Login failed for ${email}: redirected back to /login`);
  }
}

/**
 * E2E helper for OAuth providers — hits the test-only `/auth/test-login`
 * endpoint, which creates a real user + identity in the server's in-memory
 * store and issues a session cookie without going through a real OAuth flow.
 *
 * Only works when `NODE_ENV !== "production"` on the server side.
 * See `app/routes/auth.test-login.ts` and `app/lib/auth.server.ts`.
 */
export async function loginAsOAuth(
  page: Page,
  { provider, identifier, email }: { provider: string; identifier: string; email?: string }
): Promise<void> {
  const params = new URLSearchParams({ provider, identifier });
  if (email) params.set('email', email);
  await page.goto(`/auth/test-login?${params.toString()}`, {
    waitUntil: 'networkidle'
  });
  if (page.url().includes('/login')) {
    throw new Error(
      `OAuth test login failed for ${provider}/${identifier}: redirected back to /login`
    );
  }
}

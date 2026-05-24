/**
 * Test-only route: simulate a completed OAuth login without a real provider.
 *
 * GET /auth/test-login?provider=github&identifier=12345&email=test@example.com
 *
 * Creates a real user + identity in the in-memory store, mints a session
 * cookie, and redirects to /dashboard.  Only available outside production.
 * Used exclusively by the Playwright e2e suite.
 */
import { createTestSession } from '~/lib/auth.server';

export async function loader({ request }: { request: Request }) {
  if (process.env.NODE_ENV === 'production') {
    return new Response('Not Found', { status: 404 });
  }

  const url = new URL(request.url);
  const provider = url.searchParams.get('provider') ?? 'github';
  const identifier = url.searchParams.get('identifier') ?? 'test-user';
  const email = url.searchParams.get('email') ?? undefined;

  const sessionCookie = await createTestSession({ provider, identifier, email });

  return new Response(null, {
    status: 302,
    headers: { Location: '/dashboard', 'Set-Cookie': sessionCookie }
  });
}

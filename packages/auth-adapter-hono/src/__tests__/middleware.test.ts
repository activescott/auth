import { describe, it, expect, vi } from 'vitest';
import { Hono } from 'hono';
import { createAuthHandlers } from '../handlers.js';
import { requireAuthMiddleware, optionalAuthMiddleware, createAuthHandler } from '../middleware.js';
import type { Auth, AuthUser, Identity } from '@activescott/auth';

const TEST_BASE_URL = 'https://example.com';

function createMockIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: 'identity-1',
    userId: 'user-1',
    provider: 'email',
    identifier: 'user@example.com',
    createdAt: new Date(),
    ...overrides
  };
}

function createMockAuth(overrides: Partial<Auth> = {}): Auth {
  return {
    handleRequest: vi.fn().mockResolvedValue(new Response('OK')),
    verifySession: vi.fn().mockResolvedValue(null),
    createSessionCookie: vi.fn().mockResolvedValue('auth_session=token; Path=/; HttpOnly'),
    destroySessionCookie: vi.fn().mockReturnValue('auth_session=; Max-Age=0; Path=/; HttpOnly'),
    getProvider: vi.fn().mockReturnValue(null),
    getProviders: vi.fn().mockReturnValue([]),
    findProvider: vi.fn().mockReturnValue(null),
    createContext: vi.fn().mockReturnValue({
      identityStore: {},
      userStore: {},
      baseUrl: TEST_BASE_URL,
      createSession: vi.fn()
    }),
    getSessionManager: vi.fn(),
    getSessionConfig: vi.fn(),
    destroy: vi.fn(),
    ...overrides
  } as unknown as Auth;
}

// ---------------------------------------------------------------------------
describe('requireAuthMiddleware', () => {
  it('calls next and sets user when authenticated', async () => {
    const mockAuth = createMockAuth({
      verifySession: vi.fn().mockResolvedValue({
        user: { id: 'user-1' },
        identity: createMockIdentity()
      })
    });
    const handlers = createAuthHandlers(mockAuth);
    const app = new Hono();
    app.use('/protected', requireAuthMiddleware(handlers));
    app.get('/protected', (c) => {
      const user = c.get('user') as AuthUser;
      return c.json({ userId: user.id });
    });

    const res = await app.request(`${TEST_BASE_URL}/protected`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { userId: string };
    expect(body.userId).toBe('user-1');
  });

  it('returns 302 redirect to /login when not authenticated', async () => {
    const handlers = createAuthHandlers(createMockAuth());
    const app = new Hono();
    app.use('/protected', requireAuthMiddleware(handlers));
    app.get('/protected', (c) => c.text('should not reach'));

    const res = await app.request(`${TEST_BASE_URL}/protected`);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toContain('/login');
  });

  it('includes redirectTo in login redirect', async () => {
    const handlers = createAuthHandlers(createMockAuth());
    const app = new Hono();
    app.use('/dashboard', requireAuthMiddleware(handlers));
    app.get('/dashboard', (c) => c.text('ok'));

    const res = await app.request(`${TEST_BASE_URL}/dashboard`);
    const location = res.headers.get('Location') ?? '';
    expect(location).toContain('redirectTo=');
    expect(location).toContain('%2Fdashboard');
  });

  it('redirects to custom login URL when redirectTo is provided', async () => {
    const handlers = createAuthHandlers(createMockAuth());
    const app = new Hono();
    app.use('/admin', requireAuthMiddleware(handlers, '/admin-login'));
    app.get('/admin', (c) => c.text('ok'));

    const res = await app.request(`${TEST_BASE_URL}/admin`);
    expect(res.headers.get('Location')).toContain('/admin-login');
  });
});

// ---------------------------------------------------------------------------
describe('optionalAuthMiddleware', () => {
  it('sets user in context when authenticated', async () => {
    const mockAuth = createMockAuth({
      verifySession: vi.fn().mockResolvedValue({
        user: { id: 'user-1' },
        identity: createMockIdentity()
      })
    });
    const handlers = createAuthHandlers(mockAuth);
    const app = new Hono();
    app.use('/', optionalAuthMiddleware(handlers));
    app.get('/', (c) => {
      const user = c.get('user') as AuthUser | null;
      return c.json({ userId: user?.id ?? null });
    });

    const res = await app.request(`${TEST_BASE_URL}/`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { userId: string | null };
    expect(body.userId).toBe('user-1');
  });

  it('sets user to null and still calls next when not authenticated', async () => {
    const handlers = createAuthHandlers(createMockAuth());
    const app = new Hono();
    app.use('/', optionalAuthMiddleware(handlers));
    app.get('/', (c) => {
      const user = c.get('user') as AuthUser | null;
      return c.json({ userId: user?.id ?? null });
    });

    const res = await app.request(`${TEST_BASE_URL}/`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { userId: string | null };
    expect(body.userId).toBeNull();
  });
});

// ---------------------------------------------------------------------------
describe('createAuthHandler', () => {
  it('delegates to handleAuth and returns the response', async () => {
    const mockAuth = createMockAuth({
      handleRequest: vi.fn().mockResolvedValue(new Response('OK', { status: 200 }))
    });
    const handlers = createAuthHandlers(mockAuth);
    const app = new Hono();
    app.all('/auth/:provider/:action', createAuthHandler(handlers));

    const res = await app.request(`${TEST_BASE_URL}/auth/email/initiate`, { method: 'POST' });
    expect(res.status).toBe(200);
    expect(mockAuth.handleRequest).toHaveBeenCalledTimes(1);
  });

  it('passes the raw Request to handleAuth', async () => {
    const mockAuth = createMockAuth();
    const handlers = createAuthHandlers(mockAuth);
    const app = new Hono();
    app.all('/auth/:provider/:action', createAuthHandler(handlers));

    await app.request(`${TEST_BASE_URL}/auth/email/initiate`, { method: 'POST' });

    const passedRequest = vi.mocked(mockAuth.handleRequest).mock.calls[0]?.[0];
    expect(passedRequest).toBeInstanceOf(Request);
    expect(passedRequest?.url).toContain('/auth/email/initiate');
  });

  it('handles verify callbacks and sets session cookie', async () => {
    const provider = {
      id: 'email',
      name: 'Email',
      verify: vi.fn().mockResolvedValue({
        success: true,
        user: { id: 'user-1' },
        identity: createMockIdentity()
      }),
      initiate: vi.fn(),
      canHandle: vi.fn(),
      getRoutes: vi.fn()
    };
    const mockAuth = createMockAuth({
      getProvider: vi.fn().mockReturnValue(provider),
      createContext: vi.fn().mockReturnValue({
        identityStore: {},
        userStore: {},
        baseUrl: TEST_BASE_URL,
        createSession: vi.fn()
      })
    });
    const handlers = createAuthHandlers(mockAuth, { successRedirect: '/dashboard' });
    const app = new Hono();
    app.all('/auth/:provider/:action', createAuthHandler(handlers));

    const res = await app.request(`${TEST_BASE_URL}/auth/email/verify?token=abc`);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe('/dashboard');
    expect(res.headers.get('Set-Cookie')).toContain('auth_session=');
  });
});

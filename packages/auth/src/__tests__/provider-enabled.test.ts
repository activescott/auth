import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { Auth } from '../auth.js';
import { isProviderEnabled } from '../config.js';
import type { AuthConfig, AuthProvider, IdentityStore, UserStore } from '../types.js';

const SECRET = 'test-session-secret-for-enabled-tests';

function makeProvider(id: string, enabled?: boolean): AuthProvider {
  return {
    id,
    name: id.charAt(0).toUpperCase() + id.slice(1),
    enabled,
    initiate: vi.fn().mockResolvedValue({ success: true, message: 'ok' }),
    verify: vi.fn().mockResolvedValue({ success: true, user: { id: 'u1' }, identity: {} }),
    canHandle: vi.fn((r: Request) => new URL(r.url).pathname.startsWith(`/auth/${id}/`)),
    getRoutes: vi.fn().mockReturnValue([])
  };
}

function makeConfig(providers: AuthProvider[]): AuthConfig {
  const identityStore: IdentityStore = {
    findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
    findByUserId: vi.fn().mockResolvedValue([]),
    create: vi
      .fn()
      .mockResolvedValue({
        id: 'i1',
        userId: 'u1',
        provider: 'x',
        identifier: 'x',
        createdAt: new Date()
      })
  };
  const userStore: UserStore = {
    findById: vi.fn().mockResolvedValue(null),
    create: vi.fn().mockResolvedValue({ id: 'u1' })
  };
  return {
    session: {
      secret: SECRET,
      maxAge: '7d',
      cookieName: 'sess',
      cookie: { secure: false, sameSite: 'lax' }
    },
    identityStore,
    userStore,
    providers
  };
}

// ---------------------------------------------------------------------------
describe('Auth.getEnabledProviders', () => {
  let auth: Auth;
  afterEach(() => auth?.destroy());

  it('returns all providers when none have enabled set', () => {
    auth = new Auth(makeConfig([makeProvider('email'), makeProvider('google')]));
    const ids = auth.getEnabledProviders().map((p) => p.id);
    expect(ids).toContain('email');
    expect(ids).toContain('google');
  });

  it('excludes providers with enabled === false', () => {
    auth = new Auth(makeConfig([makeProvider('email', true), makeProvider('google', false)]));
    const ids = auth.getEnabledProviders().map((p) => p.id);
    expect(ids).toContain('email');
    expect(ids).not.toContain('google');
  });

  it('includes providers with enabled === true', () => {
    auth = new Auth(makeConfig([makeProvider('github', true)]));
    const ids = auth.getEnabledProviders().map((p) => p.id);
    expect(ids).toContain('github');
  });

  it('returns id and name only (not the full provider)', () => {
    auth = new Auth(makeConfig([makeProvider('email')]));
    const result = auth.getEnabledProviders();
    expect(result[0]).toEqual({ id: 'email', name: 'Email' });
    expect(Object.keys(result[0] ?? {})).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
describe('Auth.handleRequest — disabled provider', () => {
  let auth: Auth;
  afterEach(() => auth?.destroy());

  it('returns 404 for a disabled provider path', async () => {
    auth = new Auth(makeConfig([makeProvider('email', false)]));
    const request = new Request('https://app.test/auth/email/initiate');
    const response = await auth.handleRequest(request);
    expect(response.status).toBe(404);
  });

  it('dispatches normally for an enabled provider', async () => {
    const provider = makeProvider('email', true);
    auth = new Auth(makeConfig([provider]));
    const request = new Request('https://app.test/auth/email/initiate', { method: 'POST' });
    await auth.handleRequest(request);
    expect(provider.initiate).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
describe('Auth.findProvider — disabled provider', () => {
  let auth: Auth;
  afterEach(() => auth?.destroy());

  it('returns undefined for a disabled provider', () => {
    auth = new Auth(makeConfig([makeProvider('email', false)]));
    const request = new Request('https://app.test/auth/email/initiate');
    expect(auth.findProvider(request)).toBeUndefined();
  });

  it('returns the provider when enabled', () => {
    auth = new Auth(makeConfig([makeProvider('email', true)]));
    const request = new Request('https://app.test/auth/email/initiate');
    expect(auth.findProvider(request)).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
describe('isProviderEnabled', () => {
  const OLD_ENV = process.env;

  beforeEach(() => {
    process.env = { ...OLD_ENV };
  });

  afterEach(() => {
    process.env = OLD_ENV;
  });

  it('returns true by default when env var is not set', () => {
    delete process.env['AUTH_GOOGLE_ENABLED'];
    expect(isProviderEnabled('google')).toBe(true);
  });

  it('respects a custom defaultValue', () => {
    delete process.env['AUTH_GITHUB_ENABLED'];
    expect(isProviderEnabled('github', false)).toBe(false);
  });

  it('returns true for "true"', () => {
    process.env['AUTH_EMAIL_ENABLED'] = 'true';
    expect(isProviderEnabled('email')).toBe(true);
  });

  it('returns true for "1"', () => {
    process.env['AUTH_EMAIL_ENABLED'] = '1';
    expect(isProviderEnabled('email')).toBe(true);
  });

  it('returns false for "false"', () => {
    process.env['AUTH_GOOGLE_ENABLED'] = 'false';
    expect(isProviderEnabled('google')).toBe(false);
  });

  it('returns false for "0"', () => {
    process.env['AUTH_GOOGLE_ENABLED'] = '0';
    expect(isProviderEnabled('google')).toBe(false);
  });

  it('returns false for empty string', () => {
    process.env['AUTH_GOOGLE_ENABLED'] = '';
    expect(isProviderEnabled('google')).toBe(false);
  });

  it('normalises provider id to upper-case with underscores', () => {
    process.env['AUTH_MY_PROVIDER_ENABLED'] = 'true';
    expect(isProviderEnabled('my-provider')).toBe(true);
  });
});

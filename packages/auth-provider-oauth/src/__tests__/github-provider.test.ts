import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AuthContext, AuthUser, Identity, IdentityStore, UserStore } from '@activescott/auth';
import { GitHubProvider } from '../providers/github.js';
import { createStateCookie } from '../base/state-cookie.js';

// jose is not used by GitHubProvider but the module is imported transitively;
// mock it to avoid network calls.
vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(),
  jwtVerify: vi.fn()
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
const SECRET = 'github-test-state-secret-at-least-32-chars!!';
const BASE_URL = 'https://app.example.com';

const GITHUB_USER = {
  id: 98765,
  login: 'octocat',
  name: 'The Octocat',
  email: 'octocat@github.com',
  avatar_url: 'https://github.com/images/octocat.png'
};

const GITHUB_USER_PRIVATE_EMAIL = { ...GITHUB_USER, email: null };

const GITHUB_EMAILS = [
  { email: 'other@example.com', primary: false, verified: true },
  { email: 'octocat@private.example', primary: true, verified: true }
];

const TOKEN_RESPONSE = {
  access_token: 'gho_github_access_token',
  token_type: 'Bearer'
  // no id_token — GitHub is not OIDC
};

const PROVIDER_CONFIG = {
  clientId: 'github-client-id',
  clientSecret: 'github-client-secret',
  oauthStateSecret: SECRET
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function makeContext(): AuthContext {
  const identityStore: IdentityStore = {
    findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
    findByUserId: vi.fn().mockResolvedValue([]),
    create: vi.fn().mockImplementation(async (data) => ({
      id: 'ident-1',
      userId: data.userId,
      provider: data.provider,
      identifier: data.identifier,
      createdAt: new Date()
    })),
    update: vi.fn().mockResolvedValue(undefined)
  };
  const userStore: UserStore = {
    findById: vi.fn().mockResolvedValue(null),
    create: vi.fn().mockImplementation(
      async (data): Promise<AuthUser> => ({
        id: `user-${data.identifier}`
      })
    )
  };
  return {
    identityStore,
    userStore,
    baseUrl: BASE_URL,
    createSession: vi.fn().mockResolvedValue('session-cookie')
  };
}

function makeCallbackRequest(state: string): Request {
  const cookie = createStateCookie({ state, codeVerifier: '', provider: 'github' }, SECRET);
  const cookieVal = cookie.split(';')[0]?.split('=').slice(1).join('=') ?? '';
  return new Request(
    `${BASE_URL}/auth/github/callback?code=github-auth-code&state=${encodeURIComponent(state)}`,
    { headers: { Cookie: `__oauth_state=${cookieVal}` } }
  );
}

/**
 * Stub fetch to respond to GitHub's token + API endpoints.
 * `userOverride` replaces the default user fixture.
 * `emailsBody` is returned for /user/emails (pass null to simulate API error).
 */
function stubFetch(
  userOverride: Record<string, unknown> = GITHUB_USER as unknown as Record<string, unknown>,
  emailsBody: unknown[] | null = GITHUB_EMAILS
): void {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockImplementation(async (url: string) => {
      if (url === 'https://github.com/login/oauth/access_token') {
        return new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 });
      }
      if (url === 'https://api.github.com/user') {
        return new Response(JSON.stringify(userOverride), { status: 200 });
      }
      if (url === 'https://api.github.com/user/emails') {
        if (emailsBody === null) return new Response('Forbidden', { status: 403 });
        return new Response(JSON.stringify(emailsBody), { status: 200 });
      }
      return new Response('Not Found', { status: 404 });
    })
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('GitHubProvider — identity', () => {
  const provider = new GitHubProvider(PROVIDER_CONFIG);

  it('has id "github"', () => {
    expect(provider.id).toBe('github');
  });

  it('has name "GitHub"', () => {
    expect(provider.name).toBe('GitHub');
  });

  it('canHandle returns true for /auth/github/ paths', () => {
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/github/initiate`))).toBe(true);
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/github/callback`))).toBe(true);
  });

  it('canHandle returns false for other providers', () => {
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/google/callback`))).toBe(false);
  });

  it('getRoutes declares initiate and callback under /github/', () => {
    const routes = provider.getRoutes();
    expect(routes.some((r) => r.path === '/github/initiate' && r.handler === 'initiate')).toBe(
      true
    );
    expect(routes.some((r) => r.path === '/github/callback' && r.handler === 'verify')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
describe('GitHubProvider — initiate', () => {
  beforeEach(() => vi.clearAllMocks());

  it('redirects to the GitHub authorization endpoint', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch();
    const response = await provider.initiate(
      new Request(`${BASE_URL}/auth/github/initiate`),
      makeContext()
    );
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toContain('https://github.com/login/oauth/authorize');
  });

  it('includes read:user and user:email scopes by default', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch();
    const response = await provider.initiate(
      new Request(`${BASE_URL}/auth/github/initiate`),
      makeContext()
    );
    const location = new URL(response.headers.get('Location') ?? '');
    const scope = location.searchParams.get('scope') ?? '';
    expect(scope).toContain('read:user');
    expect(scope).toContain('user:email');
  });

  it('does not include PKCE params (GitHub does not support PKCE)', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch();
    const response = await provider.initiate(
      new Request(`${BASE_URL}/auth/github/initiate`),
      makeContext()
    );
    const location = new URL(response.headers.get('Location') ?? '');
    expect(location.searchParams.get('code_challenge')).toBeNull();
    expect(location.searchParams.get('code_challenge_method')).toBeNull();
  });

  it('sets an HttpOnly state cookie for CSRF protection', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch();
    const response = await provider.initiate(
      new Request(`${BASE_URL}/auth/github/initiate`),
      makeContext()
    );
    const cookie = response.headers.get('Set-Cookie') ?? '';
    expect(cookie).toContain('__oauth_state=');
    expect(cookie).toContain('HttpOnly');
  });
});

// ---------------------------------------------------------------------------
describe('GitHubProvider — verify', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns success with the GitHub numeric ID as identifier', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch();
    const result = await provider.verify(makeCallbackRequest('state-1'), makeContext());
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.identity.provider).toBe('github');
      expect(result.identity.identifier).toBe('98765');
    }
  });

  it('uses public email directly when available', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch();
    const context = makeContext();
    const result = await provider.verify(makeCallbackRequest('s'), context);
    expect(result.success).toBe(true);
    expect(context.userStore.create).toHaveBeenCalledWith(
      expect.objectContaining({
        metadata: expect.objectContaining({ email: 'octocat@github.com' })
      })
    );
    // /user/emails should not be called when public email is available
    expect(fetch).not.toHaveBeenCalledWith('https://api.github.com/user/emails', expect.anything());
  });

  it('falls back to /user/emails when public email is null (private email)', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch(GITHUB_USER_PRIVATE_EMAIL as unknown as Record<string, unknown>);
    const context = makeContext();
    const result = await provider.verify(makeCallbackRequest('s'), context);
    expect(result.success).toBe(true);
    expect(fetch).toHaveBeenCalledWith('https://api.github.com/user/emails', expect.anything());
    if (result.success) {
      // identifier is still the numeric ID, not the email
      expect(result.identity.identifier).toBe('98765');
    }
  });

  it('does not call /user/emails when public email is available', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch();
    const result = await provider.verify(makeCallbackRequest('s'), makeContext());
    expect(result.success).toBe(true);
    expect(fetch).not.toHaveBeenCalledWith('https://api.github.com/user/emails', expect.anything());
  });

  it('proceeds without email when /user/emails returns no primary verified email', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch(GITHUB_USER_PRIVATE_EMAIL as unknown as Record<string, unknown>, [
      { email: 'unverified@example.com', primary: true, verified: false }
    ]);
    const result = await provider.verify(makeCallbackRequest('s'), makeContext());
    expect(result.success).toBe(true);
  });

  it('proceeds without email when /user/emails API errors', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch(GITHUB_USER_PRIVATE_EMAIL as unknown as Record<string, unknown>, null);
    const result = await provider.verify(makeCallbackRequest('s'), makeContext());
    expect(result.success).toBe(true);
  });

  it('uses numeric GitHub ID not login as the identity identifier', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch({ ...GITHUB_USER, id: 12345, login: 'new-login' } as unknown as Record<
      string,
      unknown
    >);
    const context = makeContext();
    await provider.verify(makeCallbackRequest('s'), context);
    expect(context.identityStore.findByProviderAndIdentifier).toHaveBeenCalledWith(
      'github',
      '12345'
    );
  });

  it('returns PROVIDER_ERROR when GitHub /user API fails', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockImplementation(async (url: string) =>
          url === 'https://github.com/login/oauth/access_token'
            ? new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 })
            : new Response('Unauthorized', { status: 401 })
        )
    );
    const result = await provider.verify(makeCallbackRequest('s'), makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('PROVIDER_ERROR');
  });

  it('returns INVALID_TOKEN when state cookie is missing', async () => {
    const provider = new GitHubProvider(PROVIDER_CONFIG);
    stubFetch();
    const request = new Request(`${BASE_URL}/auth/github/callback?code=abc&state=xyz`);
    const result = await provider.verify(request, makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('INVALID_TOKEN');
  });
});

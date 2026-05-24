import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AuthContext, AuthUser, Identity, IdentityStore, UserStore } from '@activescott/auth';
import { GoogleProvider } from '../providers/google.js';
import { createStateCookie } from '../base/state-cookie.js';

// ---------------------------------------------------------------------------
// jose mock
// ---------------------------------------------------------------------------
const { mockJwtVerify, mockCreateRemoteJWKSet } = vi.hoisted(() => ({
  mockJwtVerify: vi.fn(),
  mockCreateRemoteJWKSet: vi.fn().mockReturnValue('mock-jwks')
}));

vi.mock('jose', () => ({
  createRemoteJWKSet: mockCreateRemoteJWKSet,
  jwtVerify: mockJwtVerify
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
const SECRET = 'google-test-state-secret-at-least-32-chars!!';
const BASE_URL = 'https://app.example.com';

const GOOGLE_DISCOVERY = {
  issuer: 'https://accounts.google.com',
  authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  token_endpoint: 'https://oauth2.googleapis.com/token',
  jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
  userinfo_endpoint: 'https://openidconnect.googleapis.com/v1/userinfo'
};

const GOOGLE_CLAIMS = {
  sub: 'google-user-456',
  email: 'bob@gmail.com',
  email_verified: true,
  name: 'Bob Smith',
  given_name: 'Bob',
  family_name: 'Smith',
  picture: 'https://lh3.googleusercontent.com/photo.jpg',
  iss: 'https://accounts.google.com',
  aud: 'google-client-id'
};

const TOKEN_RESPONSE = {
  access_token: 'ya29.access-token',
  token_type: 'Bearer',
  id_token: 'google.id.token'
};

const PROVIDER_CONFIG = {
  clientId: 'google-client-id',
  clientSecret: 'google-client-secret',
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

function stubFetch(discoveryBody = GOOGLE_DISCOVERY, tokenBody = TOKEN_RESPONSE): void {
  vi.stubGlobal(
    'fetch',
    vi
      .fn()
      .mockImplementation(async (url: string) =>
        url.includes('openid-configuration')
          ? new Response(JSON.stringify(discoveryBody), { status: 200 })
          : new Response(JSON.stringify(tokenBody), { status: 200 })
      )
  );
}

function makeCallbackRequest(state: string, codeVerifier: string): Request {
  const cookie = createStateCookie({ state, codeVerifier, provider: 'google' }, SECRET);
  const cookieVal = cookie.split(';')[0]?.split('=').slice(1).join('=') ?? '';
  return new Request(
    `${BASE_URL}/auth/google/callback?code=google-auth-code&state=${encodeURIComponent(state)}`,
    { headers: { Cookie: `__oauth_state=${cookieVal}` } }
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('GoogleProvider — identity', () => {
  const provider = new GoogleProvider(PROVIDER_CONFIG);

  it('has id "google"', () => {
    expect(provider.id).toBe('google');
  });

  it('has name "Google"', () => {
    expect(provider.name).toBe('Google');
  });

  it('uses the standard Google OIDC discovery URL', () => {
    expect(provider.discoveryUrl).toBe(
      'https://accounts.google.com/.well-known/openid-configuration'
    );
  });

  it('canHandle returns true for /auth/google/ paths', () => {
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/google/initiate`))).toBe(true);
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/google/callback`))).toBe(true);
  });

  it('canHandle returns false for other providers', () => {
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/github/callback`))).toBe(false);
  });

  it('getRoutes declares initiate and callback under /google/', () => {
    const routes = provider.getRoutes();
    expect(routes.some((r) => r.path === '/google/initiate' && r.handler === 'initiate')).toBe(
      true
    );
    expect(routes.some((r) => r.path === '/google/callback' && r.handler === 'verify')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
describe('GoogleProvider — initiate', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('redirects to the Google authorization endpoint', async () => {
    const provider = new GoogleProvider(PROVIDER_CONFIG);
    stubFetch();
    const response = await provider.initiate(
      new Request(`${BASE_URL}/auth/google/initiate`),
      makeContext()
    );
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toContain(
      'https://accounts.google.com/o/oauth2/v2/auth'
    );
  });

  it('includes openid email profile scopes by default', async () => {
    const provider = new GoogleProvider(PROVIDER_CONFIG);
    stubFetch();
    const response = await provider.initiate(
      new Request(`${BASE_URL}/auth/google/initiate`),
      makeContext()
    );
    const location = new URL(response.headers.get('Location') ?? '');
    expect(location.searchParams.get('scope')).toContain('openid');
    expect(location.searchParams.get('scope')).toContain('email');
    expect(location.searchParams.get('scope')).toContain('profile');
  });

  it('includes PKCE code_challenge (Google supports PKCE)', async () => {
    const provider = new GoogleProvider(PROVIDER_CONFIG);
    stubFetch();
    const response = await provider.initiate(
      new Request(`${BASE_URL}/auth/google/initiate`),
      makeContext()
    );
    const location = new URL(response.headers.get('Location') ?? '');
    expect(location.searchParams.get('code_challenge')).toBeTruthy();
    expect(location.searchParams.get('code_challenge_method')).toBe('S256');
  });
});

// ---------------------------------------------------------------------------
describe('GoogleProvider — verify', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockJwtVerify.mockResolvedValue({ payload: GOOGLE_CLAIMS });
  });

  it('returns success with Google user identity', async () => {
    const provider = new GoogleProvider(PROVIDER_CONFIG);
    stubFetch();
    const result = await provider.verify(
      makeCallbackRequest('state-abc', 'verifier-xyz'),
      makeContext()
    );
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.identity.provider).toBe('google');
      expect(result.identity.identifier).toBe('google-user-456');
    }
  });

  it('validates id_token with Google JWKS URI and issuer', async () => {
    const provider = new GoogleProvider(PROVIDER_CONFIG);
    stubFetch();
    await provider.verify(makeCallbackRequest('s', 'v'), makeContext());
    expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(
      new URL('https://www.googleapis.com/oauth2/v3/certs')
    );
    expect(mockJwtVerify).toHaveBeenCalledWith('google.id.token', 'mock-jwks', {
      issuer: 'https://accounts.google.com',
      audience: 'google-client-id'
    });
  });

  it('normalizes Google claims into OAuthProfile', async () => {
    const provider = new GoogleProvider(PROVIDER_CONFIG);
    stubFetch();
    const context = makeContext();
    await provider.verify(makeCallbackRequest('s', 'v'), context);
    expect(context.userStore.create).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: 'google',
        identifier: 'google-user-456',
        metadata: expect.objectContaining({ email: 'bob@gmail.com' })
      })
    );
  });

  it('clears email when email_verified is false', async () => {
    const provider = new GoogleProvider(PROVIDER_CONFIG);
    stubFetch();
    mockJwtVerify.mockResolvedValue({
      payload: { ...GOOGLE_CLAIMS, email_verified: false }
    });
    const context = makeContext();
    const result = await provider.verify(makeCallbackRequest('s', 'v'), context);
    expect(result.success).toBe(true);
    // email should not appear in the identity metadata
    if (result.success) {
      const meta = result.identity.metadata as Record<string, unknown> | undefined;
      expect(meta?.['email']).toBeUndefined();
    }
  });

  it('returns PROVIDER_ERROR when id_token is missing', async () => {
    const provider = new GoogleProvider(PROVIDER_CONFIG);
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async (url: string) =>
        url.includes('openid-configuration')
          ? new Response(JSON.stringify(GOOGLE_DISCOVERY), { status: 200 })
          : new Response(JSON.stringify({ access_token: 'tok', token_type: 'Bearer' }), {
              status: 200
            })
      )
    );
    const result = await provider.verify(makeCallbackRequest('s', 'v'), makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('PROVIDER_ERROR');
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AuthContext, AuthUser, Identity, IdentityStore, UserStore } from '@activescott/auth';
import type { OAuthProfile, TokenResponse } from '../types.js';
import type { OIDCDiscoveryDocument } from '../base/oauth-provider.js';
import { OAuthProvider } from '../base/oauth-provider.js';
import { createStateCookie } from '../base/state-cookie.js';

// ---------------------------------------------------------------------------
// jose mock — vi.hoisted() so variables are available in the hoisted vi.mock factory
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
const SECRET = 'test-oauth-state-secret-at-least-32-chars!!';

const DISCOVERY: OIDCDiscoveryDocument = {
  issuer: 'https://accounts.test.example',
  authorization_endpoint: 'https://accounts.test.example/oauth/authorize',
  token_endpoint: 'https://accounts.test.example/oauth/token',
  jwks_uri: 'https://accounts.test.example/.well-known/jwks.json',
  userinfo_endpoint: 'https://accounts.test.example/userinfo'
};

const CLAIMS: Record<string, unknown> = {
  sub: 'user-123',
  email: 'alice@example.com',
  email_verified: true,
  name: 'Alice Example',
  given_name: 'Alice',
  family_name: 'Example',
  picture: 'https://example.com/alice.jpg',
  iss: DISCOVERY.issuer,
  aud: 'test-client-id'
};

const TOKEN_RESPONSE = {
  access_token: 'access-tok',
  token_type: 'Bearer',
  id_token: 'id.tok.en'
};

// ---------------------------------------------------------------------------
// Concrete provider for testing
// ---------------------------------------------------------------------------
class TestProvider extends OAuthProvider {
  public readonly id = 'test';
  public readonly name = 'Test';
  public readonly discoveryUrl = 'https://accounts.test.example/.well-known/openid-configuration';

  protected async getUserProfile(
    tokens: TokenResponse,
    discovery: OIDCDiscoveryDocument
  ): Promise<OAuthProfile> {
    const claims = await this.validateIdToken(tokens.idToken!, discovery);
    return this.normalizeOIDCClaims(claims);
  }
}

class NoPKCEProvider extends OAuthProvider {
  public readonly id = 'nopkce';
  public readonly name = 'NoPKCE';
  public readonly discoveryUrl = 'https://accounts.test.example/.well-known/openid-configuration';
  protected readonly supportsPKCE = false;

  protected async getUserProfile(
    _tokens: TokenResponse,
    _discovery: OIDCDiscoveryDocument
  ): Promise<OAuthProfile> {
    return { id: 'user-1', rawClaims: {} };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const BASE_CONFIG = {
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  oauthStateSecret: SECRET
};

function makeDiscoveryFetch(): Response {
  return new Response(JSON.stringify(DISCOVERY), { status: 200 });
}

function makeTokenFetch(): Response {
  return new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 });
}

function makeMockFetch(...responses: Response[]): ReturnType<typeof vi.fn> {
  const fn = vi.fn();
  for (const r of responses) {
    fn.mockResolvedValueOnce(r);
  }
  return fn;
}

const BASE_URL = 'https://app.example.com';

function makeUser(id: string): AuthUser {
  return { id };
}

function makeIdentity(id: string, userId: string, provider: string, identifier: string): Identity {
  return { id, userId, provider, identifier, createdAt: new Date() };
}

function makeContext(overrides: Partial<AuthContext> = {}): AuthContext {
  const identityStore: IdentityStore = {
    findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
    findByUserId: vi.fn().mockResolvedValue([]),
    create: vi
      .fn()
      .mockImplementation(async (data) =>
        makeIdentity('id-1', data.userId, data.provider, data.identifier)
      ),
    update: vi.fn().mockResolvedValue(undefined)
  };

  const userStore: UserStore = {
    findById: vi.fn().mockResolvedValue(null),
    create: vi.fn().mockImplementation(async (data) => makeUser(`user-${data.identifier}`))
  };

  return {
    identityStore,
    userStore,
    baseUrl: BASE_URL,
    createSession: vi.fn().mockResolvedValue('session-cookie'),
    ...overrides
  };
}

function makeCallbackRequest(
  stateCookieValue: string,
  code: string,
  state: string,
  providerId: string = 'test'
): Request {
  return new Request(
    `${BASE_URL}/auth/${providerId}/callback?code=${code}&state=${encodeURIComponent(state)}`,
    { headers: { Cookie: `__oauth_state=${stateCookieValue}` } }
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('OAuthProvider — initiate', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('redirects to the authorization endpoint', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch()));
    const request = new Request(`${BASE_URL}/auth/test/initiate`);
    const response = await provider.initiate(request, makeContext());
    expect(response.status).toBe(302);
    const location = response.headers.get('Location') ?? '';
    expect(location).toContain('https://accounts.test.example/oauth/authorize');
  });

  it('includes required OAuth params in the redirect', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch()));
    const request = new Request(`${BASE_URL}/auth/test/initiate`);
    const response = await provider.initiate(request, makeContext());
    const location = new URL(response.headers.get('Location') ?? '');
    expect(location.searchParams.get('response_type')).toBe('code');
    expect(location.searchParams.get('client_id')).toBe('test-client-id');
    expect(location.searchParams.get('redirect_uri')).toBe(`${BASE_URL}/auth/test/callback`);
    expect(location.searchParams.get('state')).toBeTruthy();
  });

  it('includes PKCE params when supportsPKCE is true', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch()));
    const request = new Request(`${BASE_URL}/auth/test/initiate`);
    const response = await provider.initiate(request, makeContext());
    const location = new URL(response.headers.get('Location') ?? '');
    expect(location.searchParams.get('code_challenge')).toBeTruthy();
    expect(location.searchParams.get('code_challenge_method')).toBe('S256');
  });

  it('omits PKCE params when supportsPKCE is false', async () => {
    const provider = new NoPKCEProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch()));
    const request = new Request(`${BASE_URL}/auth/nopkce/initiate`);
    const response = await provider.initiate(request, makeContext());
    const location = new URL(response.headers.get('Location') ?? '');
    expect(location.searchParams.get('code_challenge')).toBeNull();
    expect(location.searchParams.get('code_challenge_method')).toBeNull();
  });

  it('sets an HttpOnly state cookie', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch()));
    const request = new Request(`${BASE_URL}/auth/test/initiate`);
    const response = await provider.initiate(request, makeContext());
    const cookie = response.headers.get('Set-Cookie') ?? '';
    expect(cookie).toContain('__oauth_state=');
    expect(cookie).toContain('HttpOnly');
  });

  it('uses cached discovery on second call', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    const mockFetch = makeMockFetch(makeDiscoveryFetch());
    vi.stubGlobal('fetch', mockFetch);
    const request = new Request(`${BASE_URL}/auth/test/initiate`);
    await provider.initiate(request, makeContext());
    await provider.initiate(new Request(`${BASE_URL}/auth/test/initiate`), makeContext());
    // Discovery fetched once; token endpoint not called during initiate
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('adds Secure flag on https requests', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch()));
    const request = new Request(`https://app.example.com/auth/test/initiate`);
    const response = await provider.initiate(request, makeContext());
    const cookie = response.headers.get('Set-Cookie') ?? '';
    expect(cookie).toContain('Secure');
  });

  it('preserves redirectTo in the state cookie payload', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch()));
    const request = new Request(`${BASE_URL}/auth/test/initiate?redirectTo=%2Fdashboard`);
    const response = await provider.initiate(request, makeContext());
    // We can only verify indirectly — state cookie is signed; if verify returns
    // the right user it confirms the cookie round-trip works. The redirectTo
    // field test is in the state-cookie unit tests.
    expect(response.headers.get('Set-Cookie')).toContain('__oauth_state=');
  });
});

// ---------------------------------------------------------------------------
describe('OAuthProvider — verify', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockJwtVerify.mockResolvedValue({ payload: CLAIMS });
  });

  function buildCallbackRequest(state: string, codeVerifier: string): Request {
    const cookie = createStateCookie({ state, codeVerifier, provider: 'test' }, SECRET);
    const cookieVal = cookie.split(';')[0]?.split('=').slice(1).join('=') ?? '';
    return makeCallbackRequest(cookieVal, 'auth-code-xyz', state);
  }

  it('returns success with user and identity for a valid callback', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    const context = makeContext();
    const result = await provider.verify(buildCallbackRequest('csrf-state', 'verifier'), context);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.user).toBeTruthy();
      expect(result.identity.provider).toBe('test');
      expect(result.identity.identifier).toBe('user-123');
    }
  });

  it('validates the id_token via JWKS', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    await provider.verify(buildCallbackRequest('s', 'v'), makeContext());
    expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(
      new URL('https://accounts.test.example/.well-known/jwks.json')
    );
    expect(mockJwtVerify).toHaveBeenCalledWith('id.tok.en', 'mock-jwks', {
      issuer: DISCOVERY.issuer,
      audience: 'test-client-id'
    });
  });

  it('creates a new user when identity does not exist', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    const context = makeContext();
    const result = await provider.verify(buildCallbackRequest('s', 'v'), context);
    expect(result.success).toBe(true);
    expect(context.userStore.create).toHaveBeenCalledWith(
      expect.objectContaining({ provider: 'test', identifier: 'user-123' })
    );
  });

  it('returns existing user when identity already exists', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    const existingUser = makeUser('existing-user');
    const existingIdentity = makeIdentity('ident-1', 'existing-user', 'test', 'user-123');
    const context = makeContext();
    vi.mocked(context.identityStore.findByProviderAndIdentifier).mockResolvedValue(
      existingIdentity
    );
    vi.mocked(context.userStore.findById).mockResolvedValue(existingUser);
    const result = await provider.verify(buildCallbackRequest('s', 'v'), context);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.user.id).toBe('existing-user');
    }
    expect(context.userStore.create).not.toHaveBeenCalled();
  });

  it('links to an existing email identity when linkByVerifiedEmail is set', async () => {
    const config = { ...BASE_CONFIG, linkByVerifiedEmail: true };
    const provider = new TestProvider(config);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    const emailUser = makeUser('email-user');
    const emailIdentity = makeIdentity('ident-email', 'email-user', 'email', 'alice@example.com');
    const context = makeContext();
    vi.mocked(context.identityStore.findByProviderAndIdentifier)
      .mockResolvedValueOnce(null) // no existing test identity
      .mockResolvedValueOnce(emailIdentity); // email identity found
    vi.mocked(context.userStore.findById).mockResolvedValue(emailUser);
    const result = await provider.verify(buildCallbackRequest('s', 'v'), context);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.user.id).toBe('email-user');
    }
  });

  it('returns INVALID_TOKEN when state cookie is missing', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', vi.fn());
    const request = new Request(`${BASE_URL}/auth/test/callback?code=abc&state=xyz`);
    const result = await provider.verify(request, makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('INVALID_TOKEN');
  });

  it('returns INVALID_TOKEN on state mismatch (CSRF)', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch()));
    const cookie = createStateCookie(
      { state: 'real-state', codeVerifier: 'v', provider: 'test' },
      SECRET
    );
    const cookieVal = cookie.split(';')[0]?.split('=').slice(1).join('=') ?? '';
    const request = new Request(`${BASE_URL}/auth/test/callback?code=abc&state=tampered-state`, {
      headers: { Cookie: `__oauth_state=${cookieVal}` }
    });
    const result = await provider.verify(request, makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('INVALID_TOKEN');
  });

  it('returns INVALID_TOKEN on provider mismatch', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', vi.fn());
    const cookie = createStateCookie({ state: 's', codeVerifier: 'v', provider: 'other' }, SECRET);
    const cookieVal = cookie.split(';')[0]?.split('=').slice(1).join('=') ?? '';
    const request = new Request(`${BASE_URL}/auth/test/callback?code=abc&state=s`, {
      headers: { Cookie: `__oauth_state=${cookieVal}` }
    });
    const result = await provider.verify(request, makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('INVALID_TOKEN');
  });

  it('returns PROVIDER_ERROR when OAuth returns an error param', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', vi.fn());
    const cookie = createStateCookie({ state: 's', codeVerifier: 'v', provider: 'test' }, SECRET);
    const cookieVal = cookie.split(';')[0]?.split('=').slice(1).join('=') ?? '';
    const request = new Request(`${BASE_URL}/auth/test/callback?error=access_denied&state=s`, {
      headers: { Cookie: `__oauth_state=${cookieVal}` }
    });
    const result = await provider.verify(request, makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('PROVIDER_ERROR');
  });

  it('returns INVALID_TOKEN when authorization code is missing', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch()));
    const cookie = createStateCookie({ state: 's', codeVerifier: 'v', provider: 'test' }, SECRET);
    const cookieVal = cookie.split(';')[0]?.split('=').slice(1).join('=') ?? '';
    const request = new Request(`${BASE_URL}/auth/test/callback?state=s`, {
      headers: { Cookie: `__oauth_state=${cookieVal}` }
    });
    const result = await provider.verify(request, makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('INVALID_TOKEN');
  });

  it('returns PROVIDER_ERROR when token exchange fails', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    const failedTokenResponse = new Response('Bad Request', { status: 400 });
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), failedTokenResponse));
    const result = await provider.verify(buildCallbackRequest('s', 'v'), makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('PROVIDER_ERROR');
  });

  it('returns PROVIDER_ERROR when id_token validation fails', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    mockJwtVerify.mockRejectedValue(new Error('JWTExpired'));
    const result = await provider.verify(buildCallbackRequest('s', 'v'), makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('PROVIDER_ERROR');
  });

  it('sends code_verifier in the token request when PKCE is enabled', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    await provider.verify(buildCallbackRequest('s', 'my-verifier'), makeContext());
    expect(fetch).toHaveBeenCalledWith(
      DISCOVERY.token_endpoint,
      expect.objectContaining({ body: expect.stringContaining('code_verifier=my-verifier') })
    );
  });

  it('does not send code_verifier when PKCE is disabled', async () => {
    const provider = new NoPKCEProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    const cookie = createStateCookie({ state: 's', codeVerifier: '', provider: 'nopkce' }, SECRET);
    const cookieVal = cookie.split(';')[0]?.split('=').slice(1).join('=') ?? '';
    const request = new Request(`${BASE_URL}/auth/nopkce/callback?code=abc&state=s`, {
      headers: { Cookie: `__oauth_state=${cookieVal}` }
    });
    const result = await provider.verify(request, makeContext());
    expect(result.success).toBe(true);
    expect(fetch).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ body: expect.stringContaining('code_verifier') })
    );
  });

  it('calls identityStore.update with verifiedAt after success', async () => {
    const provider = new TestProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    const context = makeContext();
    await provider.verify(buildCallbackRequest('s', 'v'), context);
    expect(context.identityStore.update).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ verifiedAt: expect.any(Date) })
    );
  });
});

// ---------------------------------------------------------------------------
describe('OAuthProvider — normalizeOIDCClaims', () => {
  class NormalizeProvider extends OAuthProvider {
    public readonly id = 'normalize';
    public readonly name = 'Normalize';
    public readonly discoveryUrl = 'https://example.com/.well-known/openid-configuration';
    protected async getUserProfile(): Promise<OAuthProfile> {
      return this.normalizeOIDCClaims(CLAIMS);
    }
    public exposeNormalize(claims: Record<string, unknown>): OAuthProfile {
      return this.normalizeOIDCClaims(claims);
    }
  }

  const provider = new NormalizeProvider(BASE_CONFIG);

  it('maps sub → id', () => {
    expect(provider.exposeNormalize({ sub: 'abc' }).id).toBe('abc');
  });

  it('maps email, email_verified, name, given_name, family_name, picture', () => {
    const profile = provider.exposeNormalize(CLAIMS);
    expect(profile.email).toBe('alice@example.com');
    expect(profile.emailVerified).toBe(true);
    expect(profile.name).toBe('Alice Example');
    expect(profile.givenName).toBe('Alice');
    expect(profile.familyName).toBe('Example');
    expect(profile.avatarUrl).toBe('https://example.com/alice.jpg');
  });

  it('preserves rawClaims', () => {
    const profile = provider.exposeNormalize(CLAIMS);
    expect(profile.rawClaims).toStrictEqual(CLAIMS);
  });

  it('handles missing optional fields gracefully', () => {
    const profile = provider.exposeNormalize({ sub: 'x' });
    expect(profile.email).toBeUndefined();
    expect(profile.emailVerified).toBeUndefined();
    expect(profile.name).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
describe('OAuthProvider — canHandle / getRoutes', () => {
  const provider = new TestProvider(BASE_CONFIG);

  it('canHandle returns true for /auth/test/ paths', () => {
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/test/initiate`))).toBe(true);
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/test/callback`))).toBe(true);
  });

  it('canHandle returns false for other paths', () => {
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/google/callback`))).toBe(false);
    expect(provider.canHandle(new Request(`${BASE_URL}/dashboard`))).toBe(false);
  });

  it('getRoutes declares initiate and callback routes', () => {
    const routes = provider.getRoutes();
    expect(routes.some((r) => r.path.includes('initiate') && r.handler === 'initiate')).toBe(true);
    expect(routes.some((r) => r.path.includes('callback') && r.handler === 'verify')).toBe(true);
  });
});

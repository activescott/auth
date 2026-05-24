import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AuthContext, AuthUser, Identity, IdentityStore, UserStore } from '@activescott/auth';
import type { OAuthProfile, TokenResponse } from '../types.js';
import type { OIDCDiscoveryDocument } from '../base/oauth-provider.js';
import { MicrosoftProvider } from '../providers/microsoft.js';
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
const SECRET = 'test-oauth-state-secret-at-least-32-chars!!';
const BASE_URL = 'https://app.example.com';
const TENANT_ID = 'abc123-tenant-guid';

const DISCOVERY: OIDCDiscoveryDocument = {
  issuer: `https://login.microsoftonline.com/{tenantid}/v2.0`,
  authorization_endpoint: `https://login.microsoftonline.com/common/oauth2/v2.0/authorize`,
  token_endpoint: `https://login.microsoftonline.com/common/oauth2/v2.0/token`,
  jwks_uri: `https://login.microsoftonline.com/common/discovery/v2.0/keys`
};

const SPECIFIC_TENANT_DISCOVERY: OIDCDiscoveryDocument = {
  issuer: `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
  authorization_endpoint: `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize`,
  token_endpoint: `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`,
  jwks_uri: `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`
};

const CLAIMS: Record<string, unknown> = {
  sub: 'S-1-12345',
  email: 'alice@example.com',
  name: 'Alice Example',
  given_name: 'Alice',
  family_name: 'Example',
  iss: `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
  aud: 'test-client-id',
  tid: TENANT_ID
};

const TOKEN_RESPONSE = {
  access_token: 'ms-access-token',
  token_type: 'Bearer',
  id_token: 'ms.id.token'
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const BASE_CONFIG = {
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  oauthStateSecret: SECRET
};

function makeDiscoveryFetch(doc = DISCOVERY): Response {
  return new Response(JSON.stringify(doc), { status: 200 });
}

function makeTokenFetch(): Response {
  return new Response(JSON.stringify(TOKEN_RESPONSE), { status: 200 });
}

function makeMockFetch(...responses: Response[]): ReturnType<typeof vi.fn> {
  const fn = vi.fn();
  for (const r of responses) fn.mockResolvedValueOnce(r);
  return fn;
}

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
    findByEmail: vi.fn().mockResolvedValue(null),
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

function buildCallbackRequest(
  state: string,
  codeVerifier: string,
  providerId = 'microsoft'
): Request {
  const cookie = createStateCookie({ state, codeVerifier, provider: providerId }, SECRET);
  const cookieVal = cookie.split(';')[0]?.split('=').slice(1).join('=') ?? '';
  return new Request(
    `${BASE_URL}/auth/${providerId}/callback?code=auth-code&state=${encodeURIComponent(state)}`,
    { headers: { Cookie: `__oauth_state=${cookieVal}` } }
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('MicrosoftProvider — constructor', () => {
  it('has id "microsoft" and name "Microsoft"', () => {
    const p = new MicrosoftProvider(BASE_CONFIG);
    expect(p.id).toBe('microsoft');
    expect(p.name).toBe('Microsoft');
  });

  it('uses the common tenant discovery URL by default', () => {
    const p = new MicrosoftProvider(BASE_CONFIG);
    expect(p.discoveryUrl).toBe(
      'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration'
    );
  });

  it('uses a custom tenant when specified', () => {
    const p = new MicrosoftProvider({ ...BASE_CONFIG, tenant: TENANT_ID });
    expect(p.discoveryUrl).toBe(
      `https://login.microsoftonline.com/${TENANT_ID}/v2.0/.well-known/openid-configuration`
    );
  });

  it('uses "organizations" tenant when specified', () => {
    const p = new MicrosoftProvider({ ...BASE_CONFIG, tenant: 'organizations' });
    expect(p.discoveryUrl).toContain('/organizations/');
  });

  it('respects enabled flag', () => {
    expect(new MicrosoftProvider({ ...BASE_CONFIG, enabled: false }).enabled).toBe(false);
    expect(new MicrosoftProvider({ ...BASE_CONFIG, enabled: true }).enabled).toBe(true);
    expect(new MicrosoftProvider(BASE_CONFIG).enabled).toBe(true);
  });
});

// ---------------------------------------------------------------------------
describe('MicrosoftProvider — getUserProfile', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockJwtVerify.mockResolvedValue({ payload: CLAIMS });
  });

  it('returns a profile with id, email, and name from id_token claims', async () => {
    const provider = new MicrosoftProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    const context = makeContext();
    const result = await provider.verify(buildCallbackRequest('s', 'v'), context);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.identity.identifier).toBe('S-1-12345');
    }
  });

  it('treats email as verified when Microsoft omits email_verified, enabling account linking', async () => {
    // Microsoft v2.0 tokens don't include email_verified.
    // Our code defaults emailVerified=true so linkByVerifiedEmail can work.
    const claimsWithoutVerified = { ...CLAIMS };
    delete claimsWithoutVerified['email_verified'];
    mockJwtVerify.mockResolvedValue({ payload: claimsWithoutVerified });

    const provider = new MicrosoftProvider({ ...BASE_CONFIG, linkByVerifiedEmail: true });
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    const context = makeContext();
    await provider.verify(buildCallbackRequest('s', 'v'), context);
    // findByEmail must have been called — proves we treated the email as verified
    expect(context.identityStore.findByEmail).toHaveBeenCalledWith('alice@example.com');
  });

  it('returns PROVIDER_ERROR when id_token is absent', async () => {
    const noIdToken = { access_token: 'tok', token_type: 'Bearer' };
    vi.stubGlobal(
      'fetch',
      makeMockFetch(makeDiscoveryFetch(), new Response(JSON.stringify(noIdToken), { status: 200 }))
    );
    const provider = new MicrosoftProvider(BASE_CONFIG);
    const result = await provider.verify(buildCallbackRequest('s', 'v'), makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('PROVIDER_ERROR');
  });
});

// ---------------------------------------------------------------------------
describe('MicrosoftProvider — multi-tenant issuer validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('accepts a valid Microsoft tenant issuer for the common endpoint', async () => {
    mockJwtVerify.mockResolvedValue({ payload: CLAIMS });
    const provider = new MicrosoftProvider(BASE_CONFIG); // tenant = 'common'
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    const result = await provider.verify(buildCallbackRequest('s', 'v'), makeContext());
    expect(result.success).toBe(true);
    // jose was called WITHOUT an issuer option (we skip the template issuer)
    expect(mockJwtVerify).toHaveBeenCalledWith(
      'ms.id.token',
      'mock-jwks',
      expect.not.objectContaining({ issuer: expect.anything() })
    );
  });

  it('rejects a token with a non-Microsoft issuer on the common endpoint', async () => {
    const badClaims = { ...CLAIMS, iss: 'https://evil.example.com/v2.0' };
    mockJwtVerify.mockResolvedValue({ payload: badClaims });
    const provider = new MicrosoftProvider(BASE_CONFIG);
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    const result = await provider.verify(buildCallbackRequest('s', 'v'), makeContext());
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.code).toBe('PROVIDER_ERROR');
  });

  it('does multi-tenant validation for the "organizations" tenant', async () => {
    mockJwtVerify.mockResolvedValue({ payload: CLAIMS });
    const provider = new MicrosoftProvider({ ...BASE_CONFIG, tenant: 'organizations' });
    const orgDiscovery = {
      ...DISCOVERY,
      issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0'
    };
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(orgDiscovery), makeTokenFetch()));
    const result = await provider.verify(buildCallbackRequest('s', 'v'), makeContext());
    expect(result.success).toBe(true);
  });

  it('uses strict issuer validation for a specific tenant', async () => {
    const specificClaims = { ...CLAIMS, iss: SPECIFIC_TENANT_DISCOVERY.issuer };
    mockJwtVerify.mockResolvedValue({ payload: specificClaims });
    const provider = new MicrosoftProvider({ ...BASE_CONFIG, tenant: TENANT_ID });
    vi.stubGlobal(
      'fetch',
      makeMockFetch(makeDiscoveryFetch(SPECIFIC_TENANT_DISCOVERY), makeTokenFetch())
    );
    const result = await provider.verify(buildCallbackRequest('s', 'v'), makeContext());
    expect(result.success).toBe(true);
    // For a specific tenant, jose is called WITH the exact issuer
    expect(mockJwtVerify).toHaveBeenCalledWith(
      'ms.id.token',
      'mock-jwks',
      expect.objectContaining({ issuer: SPECIFIC_TENANT_DISCOVERY.issuer })
    );
  });
});

// ---------------------------------------------------------------------------
describe('MicrosoftProvider — account linking', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockJwtVerify.mockResolvedValue({ payload: CLAIMS });
  });

  it('links to an existing identity via findByEmail when linkByVerifiedEmail is true', async () => {
    const provider = new MicrosoftProvider({ ...BASE_CONFIG, linkByVerifiedEmail: true });
    vi.stubGlobal('fetch', makeMockFetch(makeDiscoveryFetch(), makeTokenFetch()));
    const emailUser = makeUser('email-user');
    const emailIdentity = makeIdentity('ident-email', 'email-user', 'email', 'alice@example.com');
    const context = makeContext();
    vi.mocked(context.identityStore.findByEmail!).mockResolvedValue(emailIdentity);
    vi.mocked(context.userStore.findById).mockResolvedValue(emailUser);
    const result = await provider.verify(buildCallbackRequest('s', 'v'), context);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.user.id).toBe('email-user');
    }
    expect(context.userStore.create).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
describe('MicrosoftProvider — canHandle / getRoutes', () => {
  const provider = new MicrosoftProvider(BASE_CONFIG);

  it('canHandle returns true for /auth/microsoft/ paths', () => {
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/microsoft/initiate`))).toBe(true);
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/microsoft/callback`))).toBe(true);
  });

  it('canHandle returns false for other providers', () => {
    expect(provider.canHandle(new Request(`${BASE_URL}/auth/google/callback`))).toBe(false);
  });

  it('getRoutes declares initiate and callback routes', () => {
    const routes = provider.getRoutes();
    expect(routes.some((r) => r.path.includes('initiate') && r.handler === 'initiate')).toBe(true);
    expect(routes.some((r) => r.path.includes('callback') && r.handler === 'verify')).toBe(true);
  });
});

import { createRemoteJWKSet, jwtVerify } from 'jose';
import type {
  AuthContext,
  AuthProvider,
  AuthResult,
  AuthUser,
  Identity,
  ProviderRoute
} from '@activescott/auth';
import { AuthErrors, AuthenticationError } from '@activescott/auth';
import type { OAuthProviderConfig, OAuthProfile, TokenResponse } from '../types.js';
import { createStateCookie, generatePKCE, generateState, readStateCookie } from './state-cookie.js';

const DISCOVERY_CACHE_TTL_MS = 60 * 60 * 1000;

export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
}

interface DiscoveryCacheEntry {
  doc: OIDCDiscoveryDocument;
  fetchedAt: number;
}

/**
 * Abstract base class for OAuth 2.0 / OIDC providers.
 * Subclasses supply a discoveryUrl and implement getUserProfile().
 */
export abstract class OAuthProvider implements AuthProvider {
  public abstract readonly id: string;
  public abstract readonly name: string;
  public abstract readonly discoveryUrl: string;
  public readonly enabled: boolean;

  /** Set to false for providers that don't support PKCE (e.g., GitHub). */
  protected readonly supportsPKCE: boolean = true;

  private discoveryCache: DiscoveryCacheEntry | null = null;

  public constructor(protected readonly config: OAuthProviderConfig) {
    this.enabled = config.enabled ?? true;
  }

  /**
   * Build a normalized OAuthProfile from the tokens returned by the provider.
   * Subclasses call validateIdToken() and/or normalizeOIDCClaims() as needed.
   */
  protected abstract getUserProfile(
    tokens: TokenResponse,
    discovery: OIDCDiscoveryDocument
  ): Promise<OAuthProfile>;

  public async initiate(request: Request, context: AuthContext): Promise<Response> {
    const discovery = await this.getDiscovery();

    const state = generateState();
    let codeVerifier = '';
    let codeChallenge: string | undefined;

    if (this.supportsPKCE) {
      const pkce = generatePKCE();
      codeVerifier = pkce.codeVerifier;
      codeChallenge = pkce.codeChallenge;
    }

    const url = new URL(request.url);
    const redirectTo = url.searchParams.get('redirectTo') ?? undefined;
    const redirectUri = `${context.baseUrl}/auth/${this.id}/callback`;
    const scopes = this.config.scopes ?? ['openid', 'email', 'profile'];

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(' '),
      state
    });

    if (codeChallenge) {
      params.set('code_challenge', codeChallenge);
      params.set('code_challenge_method', 'S256');
    }

    const stateCookiePayload = {
      state,
      codeVerifier,
      provider: this.id,
      ...(redirectTo !== undefined ? { redirectTo } : {})
    };

    const secure = url.protocol === 'https:';
    const stateCookie = createStateCookie(stateCookiePayload, this.config.oauthStateSecret, {
      secure
    });

    return new Response(null, {
      status: 302,
      headers: {
        Location: `${discovery.authorization_endpoint}?${params.toString()}`,
        'Set-Cookie': stateCookie
      }
    });
  }

  public async verify(request: Request, context: AuthContext): Promise<AuthResult> {
    try {
      const cookiePayload = readStateCookie(request, this.config.oauthStateSecret);
      if (!cookiePayload) {
        return {
          success: false,
          error: AuthErrors.invalidToken({ reason: 'Missing or invalid state cookie' })
        };
      }

      if (cookiePayload.provider !== this.id) {
        return {
          success: false,
          error: AuthErrors.invalidToken({ reason: 'Provider mismatch in state cookie' })
        };
      }

      const url = new URL(request.url);
      const oauthError = url.searchParams.get('error');
      if (oauthError) {
        const description = url.searchParams.get('error_description') ?? oauthError;
        return {
          success: false,
          error: AuthErrors.providerError(`OAuth error: ${description}`)
        };
      }

      const code = url.searchParams.get('code');
      const returnedState = url.searchParams.get('state');

      if (!code) {
        return {
          success: false,
          error: AuthErrors.invalidToken({ reason: 'Missing authorization code' })
        };
      }

      if (returnedState !== cookiePayload.state) {
        return {
          success: false,
          error: AuthErrors.invalidToken({ reason: 'State mismatch — possible CSRF' })
        };
      }

      const discovery = await this.getDiscovery();
      const redirectUri = `${context.baseUrl}/auth/${this.id}/callback`;
      const tokens = await this.exchangeCode(
        code,
        redirectUri,
        cookiePayload.codeVerifier,
        discovery
      );

      const profile = await this.getUserProfile(tokens, discovery);
      const { user, identity } = await this.findOrCreateUser(profile, context);

      if (context.identityStore.update) {
        await context.identityStore.update(identity.id, { verifiedAt: new Date() });
      }

      return { success: true, user, identity };
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error(`Error in ${this.id} provider verify:`, error);
      if (error instanceof AuthenticationError) {
        return { success: false, error: error.toAuthError() };
      }
      return {
        success: false,
        error: AuthErrors.providerError(error instanceof Error ? error.message : 'Unknown error')
      };
    }
  }

  public canHandle(request: Request): boolean {
    const url = new URL(request.url);
    return url.pathname.startsWith(`/auth/${this.id}/`);
  }

  public getRoutes(): ProviderRoute[] {
    return [
      { method: 'GET', path: `/${this.id}/initiate`, handler: 'initiate' },
      { method: 'GET', path: `/${this.id}/callback`, handler: 'verify' }
    ];
  }

  /**
   * Validate an id_token's signature, issuer, audience, and expiry via JWKS.
   */
  protected async validateIdToken(
    idToken: string,
    discovery: OIDCDiscoveryDocument
  ): Promise<Record<string, unknown>> {
    const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
    const { payload } = await jwtVerify(idToken, jwks, {
      issuer: discovery.issuer,
      audience: this.config.clientId
    });
    return payload as Record<string, unknown>;
  }

  /**
   * Map standard OIDC JWT claims to a normalized OAuthProfile.
   */
  protected normalizeOIDCClaims(claims: Record<string, unknown>): OAuthProfile {
    return {
      id: String(claims['sub'] ?? ''),
      email: typeof claims['email'] === 'string' ? claims['email'] : undefined,
      emailVerified:
        typeof claims['email_verified'] === 'boolean' ? claims['email_verified'] : undefined,
      name: typeof claims['name'] === 'string' ? claims['name'] : undefined,
      givenName: typeof claims['given_name'] === 'string' ? claims['given_name'] : undefined,
      familyName: typeof claims['family_name'] === 'string' ? claims['family_name'] : undefined,
      avatarUrl: typeof claims['picture'] === 'string' ? claims['picture'] : undefined,
      rawClaims: claims
    };
  }

  protected async getDiscovery(): Promise<OIDCDiscoveryDocument> {
    const now = Date.now();
    if (this.discoveryCache && now - this.discoveryCache.fetchedAt < DISCOVERY_CACHE_TTL_MS) {
      return this.discoveryCache.doc;
    }

    const response = await fetch(this.discoveryUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch OIDC discovery document: ${response.status}`);
    }

    const doc = (await response.json()) as OIDCDiscoveryDocument;
    this.discoveryCache = { doc, fetchedAt: now };
    return doc;
  }

  private async exchangeCode(
    code: string,
    redirectUri: string,
    codeVerifier: string,
    discovery: OIDCDiscoveryDocument
  ): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret
    });

    if (this.supportsPKCE && codeVerifier) {
      body.set('code_verifier', codeVerifier);
    }

    const response = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json'
      },
      body: body.toString()
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`Token exchange failed: ${response.status} ${text}`);
    }

    const data = (await response.json()) as Record<string, unknown>;
    return {
      accessToken: String(data['access_token'] ?? ''),
      tokenType: String(data['token_type'] ?? 'Bearer'),
      idToken: typeof data['id_token'] === 'string' ? data['id_token'] : undefined,
      refreshToken: typeof data['refresh_token'] === 'string' ? data['refresh_token'] : undefined,
      expiresIn: typeof data['expires_in'] === 'number' ? data['expires_in'] : undefined,
      scope: typeof data['scope'] === 'string' ? data['scope'] : undefined
    };
  }

  private async findOrCreateUser(
    profile: OAuthProfile,
    context: AuthContext
  ): Promise<{ user: AuthUser; identity: Identity }> {
    const existing = await context.identityStore.findByProviderAndIdentifier(this.id, profile.id);
    if (existing) {
      const user = await context.userStore.findById(existing.userId);
      if (!user) {
        throw new Error(`User ${existing.userId} not found for existing identity`);
      }
      return { user, identity: existing };
    }

    if (this.config.linkByVerifiedEmail && profile.email && profile.emailVerified) {
      if (!context.identityStore.findByEmail) {
        throw new AuthenticationError(
          'CONFIGURATION_ERROR',
          'linkByVerifiedEmail requires IdentityStore to implement findByEmail()'
        );
      }
      const emailIdentity = await context.identityStore.findByEmail(profile.email);
      if (emailIdentity) {
        const user = await context.userStore.findById(emailIdentity.userId);
        if (user) {
          const identity = await context.identityStore.create({
            userId: user.id,
            provider: this.id,
            identifier: profile.id,
            metadata: profile.rawClaims
          });
          return { user, identity };
        }
      }
    }

    const metadata: Record<string, unknown> = { ...profile.rawClaims };
    const user = await context.userStore.create({
      provider: this.id,
      identifier: profile.id,
      metadata
    });
    const identity = await context.identityStore.create({
      userId: user.id,
      provider: this.id,
      identifier: profile.id,
      metadata
    });

    return { user, identity };
  }
}

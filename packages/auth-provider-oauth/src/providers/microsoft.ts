import { jwtVerify } from 'jose';
import type { OAuthProviderConfig, OAuthProfile, TokenResponse } from '../types.js';
import type { OIDCDiscoveryDocument } from '../base/oauth-provider.js';
import { OAuthProvider } from '../base/oauth-provider.js';

/**
 * Microsoft-specific provider config — adds an optional tenant.
 */
export interface MicrosoftProviderConfig extends OAuthProviderConfig {
  /**
   * Azure AD / Entra ID tenant identifier.
   * Use a specific tenant ID (GUID or domain) for single-tenant apps.
   * Use 'common' (default) to accept both personal (MSA) and work/school (AAD) accounts.
   * Use 'organizations' to accept only work/school accounts.
   * Use 'consumers' to accept only personal Microsoft accounts.
   */
  tenant?: string;
}

// Multi-tenant endpoint identifiers that return a template issuer.
const MULTI_TENANT_IDS = new Set(['common', 'organizations', 'consumers']);

// Expected issuer pattern for Microsoft v2.0 tokens.
const MICROSOFT_ISSUER_RE = /^https:\/\/login\.microsoftonline\.com\/[^/]+\/v2\.0$/;

/**
 * Microsoft / Azure AD (Entra ID) OIDC provider.
 *
 * Register at https://portal.azure.com → App registrations.
 * Add `<baseUrl>/auth/microsoft/callback` as a redirect URI (Web platform).
 * Grant the `openid`, `email`, and `profile` delegated permissions (added by default).
 */
export class MicrosoftProvider extends OAuthProvider {
  public readonly id = 'microsoft';
  public readonly name = 'Microsoft';
  public readonly discoveryUrl: string;
  private readonly tenant: string;

  public constructor(config: MicrosoftProviderConfig) {
    super({ scopes: ['openid', 'email', 'profile'], ...config });
    this.tenant = config.tenant ?? 'common';
    this.discoveryUrl = `https://login.microsoftonline.com/${this.tenant}/v2.0/.well-known/openid-configuration`;
  }

  protected async getUserProfile(
    tokens: TokenResponse,
    discovery: OIDCDiscoveryDocument
  ): Promise<OAuthProfile> {
    if (!tokens.idToken) {
      throw new Error('Microsoft did not return an id_token');
    }
    const claims = await this.validateIdToken(tokens.idToken, discovery);
    const profile = this.normalizeOIDCClaims(claims);
    // Microsoft does not include email_verified in v2.0 tokens; email addresses
    // in AAD/MSA tokens are directory-verified, so treat them as verified.
    if (profile.email && profile.emailVerified === undefined) {
      return { ...profile, emailVerified: true };
    }
    return profile;
  }

  protected override async validateIdToken(
    idToken: string,
    discovery: OIDCDiscoveryDocument
  ): Promise<Record<string, unknown>> {
    if (!MULTI_TENANT_IDS.has(this.tenant)) {
      // Specific tenant — the discovery issuer is an exact URL; use base validation.
      return super.validateIdToken(idToken, discovery);
    }

    // Multi-tenant endpoints return a template issuer like
    // https://login.microsoftonline.com/{tenantid}/v2.0 which won't match any
    // real token's iss claim. Skip jose's issuer check and validate the pattern manually.
    const jwks = this.getJwks(discovery.jwks_uri);
    const { payload } = await jwtVerify(idToken, jwks, {
      audience: this.config.clientId
    });
    const iss = typeof payload.iss === 'string' ? payload.iss : '';
    if (!MICROSOFT_ISSUER_RE.test(iss)) {
      throw new Error(`Unexpected Microsoft token issuer: ${iss}`);
    }
    return payload as Record<string, unknown>;
  }
}

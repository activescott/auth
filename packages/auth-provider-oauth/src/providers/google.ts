import type { OAuthProfile, TokenResponse } from '../types.js';
import type { OIDCDiscoveryDocument } from '../base/oauth-provider.js';
import { OAuthProvider } from '../base/oauth-provider.js';
import type { OAuthProviderConfig } from '../types.js';

/**
 * Google Sign-In provider (OIDC).
 *
 * Register in Google Cloud Console → APIs & Services → Credentials.
 * Add `<baseUrl>/auth/google/callback` as an authorized redirect URI.
 */
export class GoogleProvider extends OAuthProvider {
  public readonly id = 'google';
  public readonly name = 'Google';
  public readonly discoveryUrl = 'https://accounts.google.com/.well-known/openid-configuration';

  public constructor(config: OAuthProviderConfig) {
    super({ scopes: ['openid', 'email', 'profile'], ...config });
  }

  protected async getUserProfile(
    tokens: TokenResponse,
    discovery: OIDCDiscoveryDocument
  ): Promise<OAuthProfile> {
    if (!tokens.idToken) {
      throw new Error('Google did not return an id_token');
    }
    const claims = await this.validateIdToken(tokens.idToken, discovery);
    const profile = this.normalizeOIDCClaims(claims);
    // Treat unverified email as absent — do not use for account linking or display.
    if (!profile.emailVerified) {
      return { ...profile, email: undefined };
    }
    return profile;
  }
}

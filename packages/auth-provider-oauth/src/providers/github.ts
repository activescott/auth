import type { OAuthProviderConfig, OAuthProfile, TokenResponse } from '../types.js';
import type { OIDCDiscoveryDocument } from '../base/oauth-provider.js';
import { OAuthProvider } from '../base/oauth-provider.js';

const GITHUB_API = 'https://api.github.com';
const GITHUB_ACCEPT = 'application/vnd.github.v3+json';

interface GitHubUser {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string | null;
  [key: string]: unknown;
}

interface GitHubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
}

/**
 * GitHub OAuth 2.0 provider (non-OIDC).
 *
 * Register at https://github.com/settings/developers → OAuth Apps.
 * Set the callback URL to `<baseUrl>/auth/github/callback`.
 */
export class GitHubProvider extends OAuthProvider {
  public readonly id = 'github';
  public readonly name = 'GitHub';
  // GitHub has no OIDC discovery document; getDiscovery() is overridden to return static endpoints.
  public readonly discoveryUrl = '';
  protected readonly supportsPKCE = false;

  public constructor(config: OAuthProviderConfig) {
    super({ scopes: ['read:user', 'user:email'], ...config });
  }

  protected getDiscovery(): Promise<OIDCDiscoveryDocument> {
    return Promise.resolve({
      issuer: 'https://github.com',
      authorization_endpoint: 'https://github.com/login/oauth/authorize',
      token_endpoint: 'https://github.com/login/oauth/access_token',
      jwks_uri: '' // Not used — GitHub has no JWKS
    });
  }

  protected async getUserProfile(tokens: TokenResponse): Promise<OAuthProfile> {
    const user = await this.fetchUser(tokens.accessToken);
    const email = user.email ?? (await this.fetchPrimaryEmail(tokens.accessToken));
    return {
      id: String(user.id),
      email: email ?? undefined,
      emailVerified: email != null,
      name: user.name ?? user.login,
      avatarUrl: user.avatar_url ?? undefined,
      rawClaims: user as Record<string, unknown>
    };
  }

  private async fetchUser(accessToken: string): Promise<GitHubUser> {
    const response = await fetch(`${GITHUB_API}/user`, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: GITHUB_ACCEPT }
    });
    if (!response.ok) {
      throw new Error(`GitHub /user API error: ${response.status}`);
    }
    return response.json() as Promise<GitHubUser>;
  }

  private async fetchPrimaryEmail(accessToken: string): Promise<string | null> {
    const response = await fetch(`${GITHUB_API}/user/emails`, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: GITHUB_ACCEPT }
    });
    if (!response.ok) return null;
    const emails = (await response.json()) as GitHubEmail[];
    return emails.find((e) => e.primary && e.verified)?.email ?? null;
  }
}

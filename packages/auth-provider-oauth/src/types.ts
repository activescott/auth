/**
 * Shared types for @activescott/auth-provider-oauth
 */

/**
 * Base configuration shared by all OAuth/OIDC providers.
 */
export interface OAuthProviderConfig {
  /** OAuth application client ID */
  clientId: string;
  /** OAuth application client secret */
  clientSecret: string;
  /**
   * Secret used to sign the short-lived state cookie (PKCE + CSRF).
   * Must be different from the session secret.
   */
  oauthStateSecret: string;
  /** Override the default scopes for this provider */
  scopes?: string[];
  /**
   * When true, automatically link an OAuth identity to an existing user
   * if the provider returns a verified email that matches an existing identity.
   * Requires IdentityStore to implement findByEmail().
   * Defaults to false.
   */
  linkByVerifiedEmail?: boolean;
}

/**
 * Normalized user profile returned by all OAuth/OIDC providers.
 * Stored in Identity.metadata after authentication.
 */
export interface OAuthProfile {
  /** Provider's stable user ID (e.g. Google sub claim, GitHub numeric id) */
  id: string;
  email?: string;
  /** Whether the provider has verified ownership of the email address */
  emailVerified?: boolean;
  name?: string;
  givenName?: string;
  familyName?: string;
  avatarUrl?: string;
  /** Full raw claims from id_token or userinfo endpoint */
  rawClaims: Record<string, unknown>;
}

/**
 * Token response from an OAuth token endpoint.
 */
export interface TokenResponse {
  accessToken: string;
  tokenType: string;
  /** Present for OIDC providers */
  idToken?: string;
  refreshToken?: string;
  expiresIn?: number;
  scope?: string;
}

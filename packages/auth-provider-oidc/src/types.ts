import type { JWTPayload } from "jose"

/**
 * Claims of an ID token that passed validation. `iss`, `sub`, `aud`, `exp`
 * and `iat` are always present; anything else is whatever the identity
 * provider put in the token.
 */
export interface IdTokenClaims extends JWTPayload {
  iss: string
  sub: string
  aud: string | string[]
  exp: number
  iat: number
  nonce?: string
  azp?: string
}

/**
 * The fields of an OpenID Provider's discovery document this package reads
 * (OpenID Connect Discovery 1.0, section 3).
 */
export interface OidcDiscoveryDocument {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  id_token_signing_alg_values_supported?: string[]
  token_endpoint_auth_methods_supported?: string[]
  code_challenge_methods_supported?: string[]
}

/**
 * How to reach one OpenID Provider as one registered client.
 */
export interface OidcClientConfig {
  /**
   * The issuer identifier, exactly as the provider's discovery document and
   * ID tokens state it (e.g. "https://slack.com"). ID tokens with any other
   * `iss` are rejected.
   */
  issuer: string
  /** Client ID from the app registration at the provider */
  clientId: string
  /** Client secret from the app registration. Never logged or described. */
  clientSecret: string
  /**
   * Where to fetch the discovery document. Defaults to
   * `{issuer}/.well-known/openid-configuration`.
   */
  discoveryUrl?: string
  /** Scopes to request. Defaults to `["openid"]`; "openid" is added if missing. */
  scopes?: string[]
  /**
   * How far the ID token's `exp` and `iat` may be off from this server's
   * clock, in seconds. Defaults to 60.
   */
  clockToleranceSeconds?: number
  /**
   * Reject ID tokens whose `iat` is older than this many seconds. The token
   * comes straight back from the token endpoint, so anything older is stale.
   * Defaults to 600.
   */
  maxIdTokenAgeSeconds?: number
  /** Fetch implementation for discovery, JWKS and the token endpoint. Defaults to the global `fetch`. */
  fetch?: typeof fetch
}

/**
 * What an identity row records about a verified ID token: the identifier the
 * identity is keyed on, and the provider state stored with it.
 */
export interface OidcIdentity {
  identifier: string
  providerState: Record<string, unknown>
}

/**
 * Configuration for {@link OidcProvider}.
 */
export interface OidcProviderConfig extends OidcClientConfig {
  /** Provider id, the `{provider}` segment of `/auth/{provider}/...` (e.g. "slack", "okta") */
  id: string
  /** Human-readable name */
  name: string
  /**
   * The redirect URI registered with the provider. Defaults to
   * `{baseUrl}/auth/{id}/callback`, where baseUrl comes from the request.
   */
  redirectUri?: string
  /** How long a started sign-in may take before the callback is refused. Defaults to "10m". */
  expiry?: string
  /** Name of the cookie binding a started sign-in to the browser. Defaults to `auth_{id}_oidc`. */
  cookieName?: string
  /**
   * Where a finished link redirects when the start request named no
   * `redirectTo`. Defaults to "/".
   */
  linkRedirect?: string
  /**
   * Map validated claims to the identity row. Defaults to keying on issuer
   * plus subject (`{iss}|{sub}`) and storing both as provider state. Throw an
   * `OidcError` with reason "claims" to refuse a token that lacks something
   * the adapter needs.
   */
  identify?: (claims: IdTokenClaims) => OidcIdentity
}

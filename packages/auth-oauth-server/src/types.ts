import type { RateLimitRule, RateLimitStore } from "@activescott/auth"

/**
 * How a client came to be known: a Client ID Metadata Document fetched from
 * its HTTPS `client_id`, a Dynamic Client Registration (RFC 7591), or a row
 * the app inserted itself.
 */
export type OAuthClientKind = "cimd" | "dynamic" | "preregistered"

/**
 * `native` clients may only redirect to loopback `http` URIs; `web` clients
 * only to `https`.
 */
export type OAuthApplicationType = "native" | "web"

/** Token endpoint client authentication methods this server accepts. */
export type TokenEndpointAuthMethod =
  "none" | "client_secret_basic" | "client_secret_post"

/**
 * A registered client. Stored by the app; one row per `client_id`.
 */
export interface OAuthClient {
  /** The CIMD URL, a generated dynamic id, or the app's own id. */
  clientId: string
  kind: OAuthClientKind
  applicationType: OAuthApplicationType
  /** Self-asserted, already stripped of control and bidi characters and capped. */
  name: string | null
  redirectUris: string[]
  tokenEndpointAuthMethod: TokenEndpointAuthMethod
  /** SHA-256 hex of the secret for confidential clients, else null. */
  clientSecretHash: string | null
  createdAt: Date
  /** When the metadata document was last fetched (CIMD only). */
  metadataFetchedAt: Date | null
  /** When the cached metadata document must be fetched again (CIMD only). */
  metadataExpiresAt: Date | null
}

/**
 * A pending authorization request, stored between rendering the consent page
 * and the user's answer. Keyed by `(userId, id)`, single use.
 */
export interface OAuthAuthorizationRequest {
  id: string
  userId: string
  /** SHA-256 hex of the CSRF token embedded in the consent form. */
  csrfTokenHash: string
  clientId: string
  redirectUri: string
  scopes: string[]
  state: string | null
  codeChallenge: string
  resource: string
  createdAt: Date
  expiresAt: Date
}

/**
 * An authorization code. Only its SHA-256 hash is stored.
 */
export interface OAuthCode {
  codeHash: string
  clientId: string
  userId: string
  redirectUri: string
  scopes: string[]
  resource: string
  /** S256 code challenge (base64url). */
  codeChallenge: string
  createdAt: Date
  expiresAt: Date
  /** Set once by a conditional update when the code is redeemed. */
  usedAt: Date | null
}

/**
 * A user's connection to one client: what Connected apps lists and what
 * Disconnect revokes. One row per user and client.
 */
export interface OAuthGrant {
  id: string
  userId: string
  clientId: string
  scopes: string[]
  resource: string
  createdAt: Date
  lastUsedAt: Date | null
  revokedAt: Date | null
}

/**
 * Why a token row was revoked. A refresh token revoked by the lost-response
 * grace path (`grace`) is the only one whose later use counts as reuse.
 */
export type OAuthTokenRevocationReason =
  "grant" | "grace" | "code_reuse" | "client"

/**
 * An access token and the refresh token issued with it. Both are stored as
 * SHA-256 hashes.
 */
export interface OAuthToken {
  id: string
  grantId: string
  clientId: string
  userId: string
  accessTokenHash: string
  refreshTokenHash: string
  scopes: string[]
  /** The resource (audience) the token is bound to. */
  resource: string
  accessTokenExpiresAt: Date
  /** Absolute from consent: rotation never extends it. */
  refreshTokenExpiresAt: Date
  /** Hash of the code this chain started from, for revoking on code reuse. */
  codeHash: string
  /** The row whose refresh token was rotated into this one. */
  rotatedFromId: string | null
  /** When this row's refresh token was exchanged. */
  rotatedAt: Date | null
  revokedAt: Date | null
  revokedReason: OAuthTokenRevocationReason | null
  createdAt: Date
}

/**
 * Storage the app implements, typically one table per record type. Methods
 * documented as conditional must be a single atomic update (SQL:
 * `UPDATE ... WHERE used_at IS NULL`), because they are what stops two
 * concurrent requests from both redeeming the same code or refresh token.
 */
export interface OAuthStore {
  getClient(clientId: string): Promise<OAuthClient | null>
  /** Insert, or replace the row with the same `clientId`. */
  saveClient(client: OAuthClient): Promise<void>
  /**
   * Delete `dynamic` clients created before `createdBefore` that have no
   * grant. Returns how many were deleted.
   */
  deleteUnusedDynamicClients(createdBefore: Date): Promise<number>

  createAuthorizationRequest(request: OAuthAuthorizationRequest): Promise<void>
  /**
   * Delete and return the request with this id stored for this user, or
   * null. Atomic: a request is returned at most once.
   */
  consumeAuthorizationRequest(
    userId: string,
    id: string,
  ): Promise<OAuthAuthorizationRequest | null>

  createCode(code: OAuthCode): Promise<void>
  findCode(codeHash: string): Promise<OAuthCode | null>
  /** Conditional: set `usedAt` only where it is null. True if this call set it. */
  markCodeUsed(codeHash: string, usedAt: Date): Promise<boolean>

  /**
   * Create the grant for `(userId, clientId)` or update the existing one with
   * these scopes and resource, clearing `revokedAt`.
   */
  upsertGrant(
    input: Pick<OAuthGrant, "userId" | "clientId" | "scopes" | "resource">,
    at: Date,
  ): Promise<OAuthGrant>
  getGrant(grantId: string): Promise<OAuthGrant | null>
  listGrants(userId: string): Promise<OAuthGrant[]>
  touchGrant(grantId: string, at: Date): Promise<void>
  /** Set the grant's `revokedAt` and revoke every token row under it. */
  revokeGrant(grantId: string, at: Date): Promise<void>

  createToken(token: OAuthToken): Promise<void>
  findTokenByAccessHash(accessTokenHash: string): Promise<OAuthToken | null>
  findTokenByRefreshHash(refreshTokenHash: string): Promise<OAuthToken | null>
  findTokensRotatedFrom(tokenId: string): Promise<OAuthToken[]>
  /**
   * Conditional: set `rotatedAt` only where both `rotatedAt` and `revokedAt`
   * are null. True if this call set it.
   */
  markTokenRotated(tokenId: string, at: Date): Promise<boolean>
  /**
   * Conditional: revoke with reason `grace` only where both `rotatedAt` and
   * `revokedAt` are null. True if this call revoked it.
   */
  revokeUnrotatedToken(tokenId: string, at: Date): Promise<boolean>
  /** Revoke the row unless it is already revoked. */
  revokeToken(
    tokenId: string,
    at: Date,
    reason: OAuthTokenRevocationReason,
  ): Promise<void>
  /** Revoke every row whose `codeHash` matches, unless already revoked. */
  revokeTokensForCode(
    codeHash: string,
    at: Date,
    reason: OAuthTokenRevocationReason,
  ): Promise<void>
}

/**
 * The protected resource the tokens are for, such as an MCP endpoint.
 */
export interface OAuthResource {
  /** Canonical resource URI; `resource` must equal it exactly. */
  uri: string
  /** Every scope a client may ask for. */
  scopes: string[]
  /** Granted when the client asks for none, and named in the 401 challenge. */
  defaultScopes: string[]
  /**
   * Scopes the consent page shows as a checkbox that starts unticked. They
   * are granted only when the consent POST carries them in `scope`. Every
   * other requested scope is granted on approval.
   */
  optionalScopes?: string[]
  /** Human-readable name for the protected resource metadata. */
  name?: string
}

/**
 * What the consent page needs to show. Every field here comes from the
 * stored request, not from the query string the browser sent.
 */
export interface ConsentPrompt {
  userId: string
  /** POST target: the authorization endpoint. */
  action: string
  /** Hidden form fields the consent POST must echo. */
  fields: { request_id: string; csrf_token: string }
  client: {
    clientId: string
    kind: OAuthClientKind
    /** Self-asserted; show it secondary to a host for dynamic clients. */
    name: string | null
    /** Host of a CIMD `client_id`; null for dynamic and preregistered clients. */
    clientIdHost: string | null
    redirectUri: string
    redirectHost: string
  }
  warnings: {
    /** Every registered redirect is loopback: any local program can claim it. */
    loopbackRedirects: boolean
    /** A CIMD client whose redirect host differs from its `client_id` host. */
    redirectHostDiffers: boolean
    /** A dynamic client: nothing vouches for its name. */
    unregisteredClient: boolean
  }
  /** Requested scopes; `optional` ones render as unticked checkboxes. */
  scopes: Array<{ scope: string; optional: boolean }>
  resource: string
}

/**
 * Why the authorization endpoint shows an error page instead of redirecting:
 * the client or redirect URI could not be trusted, or the consent POST was
 * stale or forged.
 */
export interface AuthorizeErrorPage {
  error:
    | "invalid_client"
    | "invalid_redirect_uri"
    | "invalid_request"
    | "request_expired"
    | "temporarily_unavailable"
  description: string
}

/**
 * Fetches a Client ID Metadata Document. Throw on any failure. The Node
 * implementation with the SSRF guard is `createClientMetadataFetcher` from
 * the `/node` subpath.
 */
export type ClientMetadataFetcher = (
  url: URL,
) => Promise<{ document: unknown; maxAgeSeconds: number | null }>

/** Rate limits the server applies itself. Each is a list of fixed windows. */
export interface OAuthRateLimits {
  /** Dynamic registrations per client IP. */
  registrationPerIp: RateLimitRule[]
  /** Client metadata document fetches per signed-in user. */
  metadataFetchPerUser: RateLimitRule[]
  /** Client metadata document fetches across all users. */
  metadataFetchGlobal: RateLimitRule[]
  /** Stored authorization requests per signed-in user. */
  authorizationRequestsPerUser: RateLimitRule[]
}

/** Lifetimes in seconds. */
export interface OAuthLifetimes {
  accessToken: number
  /** Absolute from consent, not sliding. */
  refreshToken: number
  code: number
  authorizationRequest: number
  /** How long after a rotation the old refresh token may be retried. */
  refreshReuseGrace: number
}

/**
 * Configuration for {@link OAuthServer}.
 */
export interface OAuthServerConfig {
  /** Issuer URL, the app's origin (e.g. `https://example.com`). */
  issuer: string
  store: OAuthStore
  resource: OAuthResource
  /** Endpoint paths, relative to the issuer. */
  endpoints?: Partial<{
    authorization: string
    token: string
    registration: string
    revocation: string
  }>
  /**
   * Render the consent page. The server adds `frame-ancestors 'none'`,
   * `X-Frame-Options: DENY` and `Cache-Control: no-store` to the response.
   */
  renderConsent(
    prompt: ConsentPrompt,
    request: Request,
  ): Response | Promise<Response>
  /** Render an error page. Gets the same headers as the consent page. */
  renderError(
    error: AuthorizeErrorPage,
    request: Request,
  ): Response | Promise<Response>
  /**
   * Enables Client ID Metadata Documents. Without it an HTTPS `client_id` is
   * an unknown client.
   */
  fetchClientMetadata?: ClientMetadataFetcher
  /**
   * Hosts that route to this app besides the issuer's. A CIMD `client_id` on
   * any of them, or on the issuer host, is refused.
   */
  ownHosts?: string[]
  /** Accept Dynamic Client Registration (default true). */
  dynamicRegistration?: boolean
  /** Prefix for generated dynamic client ids (default `dyn_`). */
  dynamicClientIdPrefix?: string
  /**
   * Names a dynamic client may not use, matched case-insensitively as whole
   * words (e.g. `["Claude", "ChatGPT"]`).
   */
  reservedClientNames?: string[]
  /** Token prefixes so secret scanners can find a leaked one. */
  tokenPrefixes?: { access?: string; refresh?: string }
  /**
   * Whether this user may still use OAuth (e.g. not blocked). Checked on
   * code redemption, refresh, and every access token verification.
   */
  isUserActive?: (userId: string) => boolean | Promise<boolean>
  lifetimes?: Partial<OAuthLifetimes>
  rateLimits?: Partial<OAuthRateLimits>
  /** Counters for {@link rateLimits}. Defaults to an in-memory store. */
  rateLimitStore?: RateLimitStore
  /** Clock, for tests. */
  now?: () => Date
}

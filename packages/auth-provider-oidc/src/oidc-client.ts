import { createLocalJWKSet, errors } from "jose"
import type { JSONWebKeySet, JWTVerifyGetKey } from "jose"
import type {
  IdTokenClaims,
  OidcClientConfig,
  OidcDiscoveryDocument,
} from "./types.js"
import { OidcError } from "./oidc-error.js"
import { discoveryUrlFor, fetchDiscoveryDocument } from "./discovery.js"
import { validateIdToken } from "./id-token.js"

const DEFAULT_CLOCK_TOLERANCE_SECONDS = 60
const DEFAULT_MAX_ID_TOKEN_AGE_SECONDS = 600
/** OIDC Core 3.1.3.7 step 7: RS256 when the provider does not say */
const DEFAULT_SIGNING_ALGORITHMS = ["RS256"]

/**
 * Parameters of one authorization request. The caller generates and stores
 * `state`, `nonce` and the PKCE verifier; this client only builds the URL.
 */
export interface AuthorizationRequest {
  redirectUri: string
  state: string
  nonce: string
  /** S256 challenge of the PKCE code verifier */
  codeChallenge: string
}

/**
 * Parameters for redeeming an authorization code, from what was stored when
 * the authorization request was made.
 */
export interface CodeRedemption {
  code: string
  redirectUri: string
  codeVerifier: string
  nonce: string
}

/**
 * An OpenID Connect relying party for one provider and one client
 * registration: discovery, the authorization code flow with PKCE, and ID
 * token validation. Holds no per-request state, so one instance serves every
 * request; the discovery document and JWKS are cached in memory.
 *
 * Only the ID token is used. The access token the token endpoint returns is
 * dropped without being stored or returned.
 */
export class OidcClient {
  private discovery: Promise<OidcDiscoveryDocument> | undefined
  private jwks: Promise<JWTVerifyGetKey> | undefined
  private readonly fetchImpl: typeof fetch

  public constructor(private readonly config: OidcClientConfig) {
    this.fetchImpl = config.fetch ?? ((input, init) => fetch(input, init))
  }

  /** The configured issuer */
  public get issuer(): string {
    return this.config.issuer
  }

  /** The configured client ID */
  public get clientId(): string {
    return this.config.clientId
  }

  /** Scopes sent in the authorization request, always including "openid" */
  public get scopes(): string[] {
    const scopes = this.config.scopes ?? ["openid"]
    return scopes.includes("openid") ? scopes : ["openid", ...scopes]
  }

  /**
   * The provider's discovery document, fetched once and cached. A failed
   * fetch is not cached, so the next request tries again.
   *
   * @throws OidcError with reason "discovery"
   */
  public async discover(): Promise<OidcDiscoveryDocument> {
    this.discovery ??= fetchDiscoveryDocument(
      this.config.issuer,
      this.config.discoveryUrl ?? discoveryUrlFor(this.config.issuer),
      this.fetchImpl,
    ).catch((error: unknown) => {
      this.discovery = undefined
      throw error instanceof OidcError
        ? error
        : new OidcError("discovery", describeError(error))
    })
    return this.discovery
  }

  /**
   * The URL to send the browser to: the provider's authorization endpoint
   * with response_type=code, the PKCE S256 challenge, state and nonce.
   */
  public async authorizationUrl(
    request: AuthorizationRequest,
  ): Promise<string> {
    const { authorization_endpoint } = await this.discover()
    const url = new URL(authorization_endpoint)
    url.searchParams.set("response_type", "code")
    url.searchParams.set("client_id", this.config.clientId)
    url.searchParams.set("redirect_uri", request.redirectUri)
    url.searchParams.set("scope", this.scopes.join(" "))
    url.searchParams.set("state", request.state)
    url.searchParams.set("nonce", request.nonce)
    url.searchParams.set("code_challenge", request.codeChallenge)
    url.searchParams.set("code_challenge_method", "S256")
    return url.toString()
  }

  /**
   * Exchange an authorization code at the token endpoint and validate the
   * ID token that comes back. Returns the ID token's claims.
   *
   * @throws OidcError naming the step or ID token check that failed
   */
  public async redeemCode(redemption: CodeRedemption): Promise<IdTokenClaims> {
    const discovery = await this.discover()
    const idToken = await this.requestIdToken(discovery, redemption)
    return validateIdToken(
      idToken,
      (header, token) => this.key(header, token),
      {
        issuer: this.config.issuer,
        clientId: this.config.clientId,
        nonce: redemption.nonce,
        algorithms:
          discovery.id_token_signing_alg_values_supported ??
          DEFAULT_SIGNING_ALGORITHMS,
        clockToleranceSeconds:
          this.config.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE_SECONDS,
        maxAgeSeconds:
          this.config.maxIdTokenAgeSeconds ?? DEFAULT_MAX_ID_TOKEN_AGE_SECONDS,
      },
    )
  }

  private async requestIdToken(
    discovery: OidcDiscoveryDocument,
    redemption: CodeRedemption,
  ): Promise<string> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: redemption.code,
      redirect_uri: redemption.redirectUri,
      code_verifier: redemption.codeVerifier,
    })
    const headers = new Headers({
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    })

    // client_secret_basic is the default when the provider lists no methods
    // (OpenID Connect Discovery 1.0, section 3)
    const methods = discovery.token_endpoint_auth_methods_supported ?? [
      "client_secret_basic",
    ]
    if (methods.includes("client_secret_basic")) {
      const credentials = `${formEncode(this.config.clientId)}:${formEncode(this.config.clientSecret)}`
      headers.set("Authorization", `Basic ${btoa(credentials)}`)
    } else {
      body.set("client_id", this.config.clientId)
      body.set("client_secret", this.config.clientSecret)
    }

    const response = await this.fetchImpl(discovery.token_endpoint, {
      method: "POST",
      headers,
      body,
    })
    const result = (await response.json().catch(() => ({}))) as {
      ok?: boolean
      error?: string
      id_token?: unknown
    }
    // Slack answers errors with HTTP 200 and ok: false
    if (!response.ok || result.ok === false || result.error) {
      throw new OidcError(
        "token_request",
        `Token endpoint refused the code: ${result.error ?? `HTTP ${response.status}`}`,
      )
    }
    if (typeof result.id_token !== "string") {
      throw new OidcError("token_request", "Token response has no id_token")
    }
    return result.id_token
  }

  /**
   * Resolve the signing key for an ID token from the provider's JWKS. An
   * unknown `kid` refetches the JWKS once, so a key rotation at the provider
   * does not need a restart here.
   */
  private async key(
    ...args: Parameters<JWTVerifyGetKey>
  ): Promise<Awaited<ReturnType<JWTVerifyGetKey>>> {
    const keys = await this.loadJwks(false)
    try {
      return await keys(...args)
    } catch (error) {
      if (!(error instanceof errors.JWKSNoMatchingKey)) throw error
      const refreshed = await this.loadJwks(true)
      return refreshed(...args)
    }
  }

  private async loadJwks(refresh: boolean): Promise<JWTVerifyGetKey> {
    if (refresh || !this.jwks) {
      this.jwks = this.fetchJwks().catch((error: unknown) => {
        this.jwks = undefined
        throw error
      })
    }
    return this.jwks
  }

  private async fetchJwks(): Promise<JWTVerifyGetKey> {
    const { jwks_uri } = await this.discover()
    const response = await this.fetchImpl(jwks_uri, {
      headers: { Accept: "application/json" },
    })
    if (!response.ok) {
      throw new OidcError(
        "discovery",
        `JWKS request failed with HTTP ${response.status}`,
      )
    }
    const jwks = (await response.json()) as JSONWebKeySet
    return createLocalJWKSet(jwks)
  }
}

/**
 * client_secret_basic form-encodes the ID and secret before base64
 * (RFC 6749, section 2.3.1)
 */
function formEncode(value: string): string {
  return encodeURIComponent(value).replaceAll("%20", "+")
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

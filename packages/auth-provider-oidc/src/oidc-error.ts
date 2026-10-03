/**
 * Why an OIDC step failed:
 * - "discovery": the discovery document or JWKS could not be fetched or is invalid;
 * - "token_request": the token endpoint refused the code (bad code, wrong
 *   redirect URI, PKCE verifier mismatch) or answered without an ID token;
 * - "signature", "issuer", "audience", "azp", "expired", "iat", "nonce",
 *   "malformed": the ID token failed that check of OIDC Core 3.1.3.7;
 * - "claims": the ID token is valid but lacks a claim the adapter needs.
 */
export type OidcErrorReason =
  | "discovery"
  | "token_request"
  | "signature"
  | "issuer"
  | "audience"
  | "azp"
  | "expired"
  | "iat"
  | "nonce"
  | "malformed"
  | "claims"

/**
 * A failed discovery, code exchange, or ID token validation.
 */
export class OidcError extends Error {
  public constructor(
    public readonly reason: OidcErrorReason,
    message: string,
  ) {
    super(message)
    this.name = "OidcError"
  }
}

import { errors, jwtVerify } from "jose"
import type { JWTVerifyGetKey } from "jose"
import type { IdTokenClaims } from "./types.js"
import { OidcError } from "./oidc-error.js"

/**
 * What {@link validateIdToken} checks the token against.
 */
export interface IdTokenExpectations {
  /** The issuer from configuration, which discovery has confirmed */
  issuer: string
  /** This client's ID; must be the token's audience */
  clientId: string
  /** The nonce sent in the authorization request */
  nonce: string
  /** Signing algorithms to accept. Never includes "none". */
  algorithms: string[]
  clockToleranceSeconds: number
  maxAgeSeconds: number
}

/**
 * Validate an ID token from the token endpoint per OIDC Core 3.1.3.7:
 * signature against the provider's JWKS with an allowed algorithm, `iss`
 * equal to the configured issuer, `aud` naming this client and no other
 * audience, `azp` (when present) equal to this client, `exp` in the future,
 * `iat` neither in the future nor older than `maxAgeSeconds`, and `nonce`
 * equal to the one this client sent. Encrypted (JWE) ID tokens are not
 * supported and fail as malformed.
 *
 * @throws OidcError naming the check that failed
 */
export async function validateIdToken(
  idToken: string,
  keys: JWTVerifyGetKey,
  expected: IdTokenExpectations,
): Promise<IdTokenClaims> {
  let payload
  try {
    ;({ payload } = await jwtVerify(idToken, keys, {
      issuer: expected.issuer,
      audience: expected.clientId,
      algorithms: expected.algorithms.filter((alg) => alg !== "none"),
      clockTolerance: expected.clockToleranceSeconds,
      maxTokenAge: expected.maxAgeSeconds,
      requiredClaims: ["iss", "sub", "aud", "exp", "iat"],
    }))
  } catch (error) {
    throw toOidcError(error)
  }

  const claims = payload as IdTokenClaims

  // 3.1.3.7 step 3: reject additional audiences the client does not trust.
  // This client trusts none but itself.
  if (Array.isArray(claims.aud) && claims.aud.length > 1) {
    throw new OidcError("audience", "ID token names additional audiences")
  }
  if (claims.azp !== undefined && claims.azp !== expected.clientId) {
    throw new OidcError("azp", "ID token azp is not this client")
  }
  if (claims.nonce !== expected.nonce) {
    throw new OidcError("nonce", "ID token nonce does not match")
  }

  return claims
}

function toOidcError(error: unknown): OidcError {
  if (error instanceof errors.JWTExpired) {
    // maxTokenAge failures are reported as JWTExpired on the iat claim
    return error.claim === "iat"
      ? new OidcError("iat", "ID token was issued too long ago")
      : new OidcError("expired", "ID token has expired")
  }
  if (error instanceof errors.JWTClaimValidationFailed) {
    switch (error.claim) {
      case "iss": {
        return new OidcError("issuer", "ID token issuer does not match")
      }
      case "aud": {
        return new OidcError("audience", "ID token audience is not this client")
      }
      case "iat": {
        return new OidcError("iat", "ID token iat is not acceptable")
      }
      default: {
        return new OidcError(
          "malformed",
          `ID token claim check failed: ${error.claim}`,
        )
      }
    }
  }
  if (
    error instanceof errors.JWSSignatureVerificationFailed ||
    error instanceof errors.JWKSNoMatchingKey ||
    error instanceof errors.JOSEAlgNotAllowed
  ) {
    return new OidcError("signature", "ID token signature is not valid")
  }
  return new OidcError(
    "malformed",
    error instanceof Error ? error.message : "ID token is not a valid JWT",
  )
}

import { base64url } from "jose"

/** 32 random bytes: a 43-character base64url string, the RFC 7636 minimum length */
const RANDOM_TOKEN_BYTES = 32

/**
 * An unguessable base64url string, used for the PKCE code verifier, the
 * `state` parameter and the nonce.
 */
export function randomToken(): string {
  return base64url.encode(
    crypto.getRandomValues(new Uint8Array(RANDOM_TOKEN_BYTES)),
  )
}

/**
 * The S256 code challenge for a PKCE code verifier (RFC 7636, section 4.2).
 */
export async function codeChallengeFor(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier),
  )
  return base64url.encode(new Uint8Array(digest))
}

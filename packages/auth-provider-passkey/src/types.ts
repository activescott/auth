import type { ChallengeStore } from "@activescott/auth"
import type {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server"

/**
 * Configuration for PasskeyProvider.
 *
 * Passkeys need no storage interface of their own: each credential is
 * an identity row ({provider: "passkey", identifier: <credentialId>})
 * whose provider-owned Identity.metadata holds the verification state
 * (see passkeyCredentialMetadataSchema).
 */
export interface PasskeyProviderConfig {
  /** Relying party name shown by authenticator UIs (e.g., "My App") */
  rpName: string
  /** Relying party ID; defaults to the request hostname */
  rpID?: string
  /** Expected WebAuthn origin; defaults to the request origin */
  expectedOrigin?: string
  /** Secret for signing the short-lived challenge cookie */
  challengeSecret: string
  /** How long a challenge stays valid (default "5m") */
  challengeExpiry?: string
  /** Challenge cookie name (default "auth_passkey_challenge") */
  challengeCookieName?: string
  /** Optional store for strict single-use challenges. Without it,
   * challenges are stateless signed tokens that expire but could be
   * replayed within their lifetime; with it, each challenge is deleted
   * on first redemption attempt. */
  challengeStore?: ChallengeStore
}

/**
 * The @simplewebauthn/server functions the provider calls, injectable
 * for tests.
 */
export interface WebAuthnServer {
  generateRegistrationOptions: typeof generateRegistrationOptions
  verifyRegistrationResponse: typeof verifyRegistrationResponse
  generateAuthenticationOptions: typeof generateAuthenticationOptions
  verifyAuthenticationResponse: typeof verifyAuthenticationResponse
}

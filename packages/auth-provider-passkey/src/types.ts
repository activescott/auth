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
 * whose provider-owned Identity.providerState holds the verification state
 * (see passkeyCredentialMetadataSchema).
 */
export interface PasskeyProviderConfig {
  /** Relying party name shown by authenticator UIs (e.g., "My App") */
  rpName: string
  /**
   * The app's canonical URL (e.g. "https://myapp.example"). When set, rpID
   * defaults to its hostname and expectedOrigin to its origin, so passkeys
   * bind to the configured domain rather than to whatever host a request
   * (or a proxy rewriting it) presents. When unset, both derive from each
   * request, which suits localhost dev and e2e. An explicit rpID or
   * expectedOrigin still wins — e.g. an rpID of "example.com" for an app at
   * "https://app.example.com". Must be an http(s) URL; the constructor
   * throws otherwise, so a typo fails at boot instead of minting passkeys
   * for the wrong domain.
   */
  appUrl?: string
  /** Relying party ID; defaults to the appUrl hostname, else the request hostname */
  rpID?: string
  /** Expected WebAuthn origin; defaults to the appUrl origin, else the request origin */
  expectedOrigin?: string
  /** Secret for signing the short-lived challenge cookie */
  challengeSecret: string
  /** How long a challenge stays valid (default "5m") */
  challengeExpiry?: string
  /** Challenge cookie name (default "auth_passkey_challenge") */
  challengeCookieName?: string
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

import type { ChallengeStore } from "@activescott/auth"
import type {
  AuthenticatorTransportFuture,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server"

/**
 * A registered WebAuthn credential (one passkey on one authenticator or
 * one synced passkey).
 */
export interface StoredCredential {
  /** WebAuthn credential ID, base64url */
  credentialId: string
  /** COSE public key, base64url */
  publicKey: string
  /** Signature counter reported by the authenticator (0 for most synced passkeys) */
  counter: number
  /** Transport hints from registration (e.g., "internal", "hybrid", "usb") */
  transports?: AuthenticatorTransportFuture[]
  /** The user this credential belongs to */
  userId: string
  /** "singleDevice" (hardware-bound) or "multiDevice" (synced passkey) */
  deviceType: "singleDevice" | "multiDevice"
  /** Whether the credential is backed up (synced to a cloud keychain) */
  backedUp: boolean
  /** User-assigned label (e.g., "MacBook Touch ID") */
  nickname?: string
  /** When this credential was registered */
  createdAt: Date
  /** When this credential last completed an authentication */
  lastUsedAt?: Date
}

/**
 * Storage adapter for WebAuthn credentials. Applications implement this
 * to connect to their database, or use the shipped
 * InMemoryCredentialStore for single-instance deployments.
 */
export interface CredentialStore {
  /**
   * Find a credential by its WebAuthn credential ID
   */
  findById(credentialId: string): Promise<StoredCredential | null>

  /**
   * Find all credentials registered to a user
   */
  findByUserId(userId: string): Promise<StoredCredential[]>

  /**
   * Persist a new credential with createdAt=now
   */
  create(
    data: Omit<StoredCredential, "createdAt" | "lastUsedAt">,
  ): Promise<StoredCredential>

  /**
   * Store the counter from a successful authentication and set
   * lastUsedAt=now
   */
  updateCounterAndLastUsed(credentialId: string, counter: number): Promise<void>

  /**
   * Delete a credential (e.g., user removes a passkey)
   */
  delete?(credentialId: string): Promise<void>
}

/**
 * Configuration for PasskeyProvider
 */
export interface PasskeyProviderConfig {
  /** Relying party name shown by authenticator UIs (e.g., "My App") */
  rpName: string
  /** Relying party ID; defaults to the request hostname */
  rpID?: string
  /** Expected WebAuthn origin; defaults to the request origin */
  expectedOrigin?: string
  /** Storage for registered credentials */
  credentialStore: CredentialStore
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

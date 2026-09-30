import type { Identity, IdentityStore } from "@activescott/auth"
import type { PasskeyCredentialMetadata } from "./credential-metadata.js"
import { parsePasskeyCredentialMetadata } from "./credential-metadata.js"

/** Identity.provider of every passkey identity (PasskeyProvider.id) */
export const PASSKEY_PROVIDER_ID = "passkey"

/**
 * One passkey as a settings page shows it. Plain JSON (ISO date strings,
 * no Dates) so it can be returned from a loader as is.
 */
export interface PasskeySummary {
  /** WebAuthn credential ID (base64url); the passkey identity's identifier */
  credentialId: string
  /** User-assigned label, or null when none was given at registration */
  nickname: string | null
  /** True for passkeys synced to a cloud keychain or password manager ("multiDevice") */
  synced: boolean
  /** ISO timestamp of registration (the identity's createdAt) */
  createdAt: string
  /** ISO timestamp of the last successful sign-in, or null if never used */
  lastUsedAt: string | null
}

/**
 * A user's passkeys for an account/settings page, in the order the identity
 * store returns them. Identities whose provider state fails validation are
 * skipped, the same as the provider does when excluding existing credentials
 * from registration. Never exposes the stored public key or counter.
 */
export async function listPasskeys(
  identityStore: IdentityStore,
  userId: string,
): Promise<PasskeySummary[]> {
  const passkeys = await findPasskeyCredentials(identityStore, userId)
  return passkeys.map(({ identity, credential }) => ({
    credentialId: identity.identifier,
    nickname: credential.nickname ?? null,
    synced: credential.deviceType === "multiDevice",
    createdAt: identity.createdAt.toISOString(),
    lastUsedAt: credential.lastUsedAt ?? null,
  }))
}

/**
 * A user's passkey identities with their validated credential state;
 * identities whose provider state fails validation are skipped
 */
export async function findPasskeyCredentials(
  identityStore: IdentityStore,
  userId: string,
): Promise<{ identity: Identity; credential: PasskeyCredentialMetadata }[]> {
  const identities = await identityStore.findByUserId(userId)
  const result: {
    identity: Identity
    credential: PasskeyCredentialMetadata
  }[] = []
  for (const identity of identities) {
    if (identity.provider !== PASSKEY_PROVIDER_ID) continue
    const credential = parsePasskeyCredentialMetadata(identity.providerState)
    if (credential) result.push({ identity, credential })
  }
  return result
}

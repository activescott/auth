import { z } from "zod"

/**
 * Schema for the provider-owned Identity.providerState of a passkey identity.
 * The identity row's identifier is the WebAuthn credential ID; this
 * state holds the verification data for it. Applications persist it
 * opaquely (a JSON/JSONB column) and never construct it themselves.
 */
export const passkeyCredentialMetadataSchema = z.object({
  /** COSE public key, base64url */
  publicKey: z.string().min(1),
  /** Signature counter reported by the authenticator (0 for most synced passkeys) */
  counter: z.number().int().nonnegative(),
  /** Transport hints from registration (e.g., "internal", "hybrid", "usb") */
  transports: z
    .array(
      z.enum([
        "ble",
        "cable",
        "hybrid",
        "internal",
        "nfc",
        "smart-card",
        "usb",
      ]),
    )
    .optional(),
  /** "singleDevice" (hardware-bound) or "multiDevice" (synced passkey) */
  deviceType: z.enum(["singleDevice", "multiDevice"]),
  /** Whether the credential is backed up (synced to a cloud keychain) */
  backedUp: z.boolean(),
  /** User-assigned label (e.g., "MacBook Touch ID") */
  nickname: z.string().optional(),
  /** ISO timestamp of the last successful authentication (strings survive JSON columns; Dates do not) */
  lastUsedAt: z.string().optional(),
})

export type PasskeyCredentialMetadata = z.infer<
  typeof passkeyCredentialMetadataSchema
>

/**
 * Validate an identity's provider state as passkey credential state. Returns
 * null when it does not match the schema (e.g., the store
 * corrupted or dropped it).
 */
export function parsePasskeyCredentialMetadata(
  metadata: Record<string, unknown>,
): PasskeyCredentialMetadata | null {
  const result = passkeyCredentialMetadataSchema.safeParse(metadata)
  return result.success ? result.data : null
}

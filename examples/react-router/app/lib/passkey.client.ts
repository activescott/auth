import {
  createPasskeyClient,
  isConditionalUIAvailable,
} from "@activescott/auth-provider-passkey/browser"

export { isConditionalUIAvailable }

/**
 * The passkey client: each method fetches options from the provider, runs
 * the WebAuthn ceremony, and posts the result back. The `.client` suffix
 * keeps this browser-only module out of the server bundle; pages load it
 * with a dynamic import when the user acts. The default basePath ("/auth")
 * matches where app/routes/auth.$provider.$action.tsx mounts the endpoints.
 *
 * Rejections from the server surface as an Error whose message is the
 * specific reason — e.g. "Unknown credential" for a passkey saved in a
 * password manager that the server no longer knows, common here because
 * the example's stores reset on restart.
 */
export const passkeys = createPasskeyClient()

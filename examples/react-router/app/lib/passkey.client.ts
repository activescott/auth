import { createPasskeyClient } from "@activescott/auth-provider-passkey/browser"

/**
 * The passkey client: each method fetches options from the provider, runs
 * the WebAuthn ceremony, and posts the result back. The default basePath
 * ("/auth") matches where app/routes/auth.$provider.$action.tsx mounts the
 * endpoints. Pages hand it to the adapter's usePasskeySignIn and
 * useRegisterPasskey hooks, which take the client as a parameter so the
 * adapter does not depend on the passkey package.
 *
 * The `.client` suffix keeps this browser-only module out of the server
 * bundle. Pages still import it directly: on the server the export is
 * undefined, and the hooks only call it from click handlers and effects,
 * which never run there.
 *
 * Rejections from the server surface as an Error whose message is the
 * specific reason — e.g. "Unknown credential" for a passkey saved in a
 * password manager that the server no longer knows, common here because
 * the example's stores reset on restart.
 */
export const passkeys = createPasskeyClient()

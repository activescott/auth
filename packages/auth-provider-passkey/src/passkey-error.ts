/**
 * Why a passkey sign-in or registration failed:
 *
 * - `"no-credential-or-cancelled"`: the browser's passkey prompt ended
 *   without a credential. The user dismissed it, it timed out (often
 *   because the site has no passkey saved on this device), or another
 *   ceremony aborted it. Browsers report all of these as the same few
 *   DOMExceptions and won't say which, on purpose, so a site can't probe
 *   for passkeys.
 * - `"error"`: anything else, such as the server rejecting the request
 *   (e.g. "Unknown credential"). `message` is fit to show the user.
 */
export type PasskeyErrorReason = "no-credential-or-cancelled" | "error"

/** A failed passkey ceremony, as returned by describePasskeyError */
export interface PasskeyError {
  ok: false
  reason: PasskeyErrorReason
  /**
   * The error's own message. For `"no-credential-or-cancelled"` it is the
   * browser's text, such as "The operation either timed out or was not
   * allowed", which reads like a fault; show your own text for that reason.
   */
  message: string
  /** The value that was thrown */
  error: unknown
}

// The names the WebAuthn spec and browsers give a ceremony that ends
// without a credential
const NO_CREDENTIAL_ERROR_NAMES = new Set([
  "NotAllowedError",
  "AbortError",
  "TimeoutError",
])

/**
 * Describe an error thrown by PasskeyClient.signInWithPasskey or
 * registerPasskey, so an app can tell "no passkey, or the user cancelled"
 * from a real failure and show a clear message for each:
 *
 * ```ts
 * try {
 *   await passkeys.signInWithPasskey()
 * } catch (caught) {
 *   const failure = describePasskeyError(caught)
 *   showError(
 *     failure.reason === "no-credential-or-cancelled"
 *       ? "No passkey for this site yet. Sign in with email, then add one."
 *       : failure.message,
 *   )
 * }
 * ```
 */
export function describePasskeyError(error: unknown): PasskeyError {
  const reason: PasskeyErrorReason =
    error instanceof DOMException && NO_CREDENTIAL_ERROR_NAMES.has(error.name)
      ? "no-credential-or-cancelled"
      : "error"
  return { ok: false, reason, message: messageOf(error), error }
}

function messageOf(error: unknown): string {
  if (error instanceof Error && error.message) return error.message
  return typeof error === "string" && error ? error : "Passkey request failed"
}

import { useEffect, useRef, useState } from "react"

/**
 * The part of the passkey browser client this hook calls.
 * `createPasskeyClient()` from `@activescott/auth-provider-passkey/browser`
 * satisfies it; the adapter takes it as a parameter rather than importing it,
 * so apps without passkeys never install the WebAuthn library.
 */
export interface PasskeySignInClient {
  signInWithPasskey(options?: { conditional?: boolean }): Promise<void>
}

/** Options for {@link usePasskeySignIn} */
export interface UsePasskeySignInOptions {
  /** Create it once, at module scope, rather than on every render */
  client: PasskeySignInClient
  /** Where the browser goes after signing in */
  redirectTo: string
  /**
   * Also offer passkeys in the browser's autofill (conditional UI), on a
   * field with `autoComplete="... webauthn"`. Off by default: the spec
   * intends it to be silent, but password manager extensions commonly answer
   * the pending request with their own dialog as soon as the page loads,
   * which reads as an unprompted request to sign in.
   */
  autofill?: boolean
}

/** What {@link usePasskeySignIn} returns */
export interface PasskeySignInState {
  /** Run the modal passkey ceremony; wire it to a button's onClick */
  signIn: () => Promise<void>
  /** True from the click until the ceremony fails (success navigates away) */
  pending: boolean
  /**
   * Why the last attempt failed: the server's specific reason when it
   * rejected the passkey (e.g. "Unknown credential"), else the browser's
   */
  error: string | null
}

/**
 * Sign in with a passkey. On success the browser does a full page load of
 * `redirectTo`, so the next page is rendered on the server with the new
 * session cookie.
 *
 * @example
 * ```tsx
 * // app/lib/passkey.client.ts
 * export const passkeys = createPasskeyClient()
 *
 * // app/routes/login.tsx
 * const passkey = usePasskeySignIn({ client: passkeys, redirectTo: "/dashboard" })
 * <button onClick={passkey.signIn} disabled={passkey.pending}>Sign in with a passkey</button>
 * {passkey.error && <p>{passkey.error}</p>}
 * ```
 */
export function usePasskeySignIn(
  options: UsePasskeySignInOptions,
): PasskeySignInState {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // The autofill effect must not restart when the caller passes a new object
  // or string on each render, so it reads these through a ref
  const latest = useRef(options)
  latest.current = options

  useEffect(() => {
    if (!options.autofill) return

    async function offerPasskeyAutofill(): Promise<void> {
      if (!(await isConditionalUIAvailable())) return
      try {
        await latest.current.client.signInWithPasskey({ conditional: true })
        window.location.assign(latest.current.redirectTo)
      } catch (caught) {
        // DOMExceptions are ceremony noise the user never started: aborted
        // by the button's modal flow, dismissed, or unsupported. A plain
        // Error is the server rejecting an assertion the user did choose,
        // so show that one.
        if (caught instanceof Error && !(caught instanceof DOMException)) {
          setError(caught.message)
        }
      }
    }
    // The timeout makes React StrictMode's dev-only mount, unmount, remount
    // start exactly one ceremony: the first mount's timer is cleared before
    // it fires. Start-abort-start cycles let the user pick a passkey on an
    // aborted ceremony whose completion never navigates, and some password
    // managers ignore the abort and later report an error of their own.
    const timer = setTimeout(() => void offerPasskeyAutofill(), 0)
    return () => clearTimeout(timer)
  }, [options.autofill])

  async function signIn(): Promise<void> {
    setError(null)
    setPending(true)
    try {
      // Starting the modal ceremony aborts a pending autofill one, as
      // WebAuthn requires
      await latest.current.client.signInWithPasskey()
      window.location.assign(latest.current.redirectTo)
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : "Passkey sign-in failed",
      )
      setPending(false)
    }
  }

  return { signIn, pending, error }
}

async function isConditionalUIAvailable(): Promise<boolean> {
  return (
    typeof PublicKeyCredential !== "undefined" &&
    typeof PublicKeyCredential.isConditionalMediationAvailable === "function" &&
    (await PublicKeyCredential.isConditionalMediationAvailable())
  )
}

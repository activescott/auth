import { useRef, useState } from "react"

/**
 * The part of the passkey browser client this hook calls.
 * `createPasskeyClient()` from `@activescott/auth-provider-passkey/browser`
 * satisfies it.
 */
export interface PasskeyRegistrationClient {
  registerPasskey(): Promise<void>
}

/** Options for {@link useRegisterPasskey} */
export interface UseRegisterPasskeyOptions {
  /** Create it once, at module scope, rather than on every render */
  client: PasskeyRegistrationClient
  /**
   * Called once the passkey is saved, to reload the page's data so the new
   * passkey shows in the list. In React Router that is
   * `useRevalidator().revalidate`; the adapter does not import it so one
   * build serves both v7 and v8.
   */
  onRegistered?: () => unknown
}

/** Where the last registration attempt stands */
export type RegisterPasskeyStatus = "idle" | "pending" | "added" | "error"

/** What {@link useRegisterPasskey} returns */
export interface RegisterPasskeyState {
  /** Run the registration ceremony; wire it to a button's onClick */
  register: () => Promise<void>
  status: RegisterPasskeyStatus
  /** Why the last attempt failed, when `status` is "error" */
  error: string | null
}

/**
 * Add a passkey to the signed-in user.
 *
 * @example
 * ```tsx
 * const revalidator = useRevalidator()
 * const passkey = useRegisterPasskey({
 *   client: passkeys,
 *   onRegistered: revalidator.revalidate,
 * })
 * <button onClick={passkey.register}>Add a passkey</button>
 * {passkey.status === "added" && <p>Passkey added.</p>}
 * ```
 */
export function useRegisterPasskey(
  options: UseRegisterPasskeyOptions,
): RegisterPasskeyState {
  const [status, setStatus] = useState<RegisterPasskeyStatus>("idle")
  const [error, setError] = useState<string | null>(null)
  const latest = useRef(options)
  latest.current = options

  async function register(): Promise<void> {
    setStatus("pending")
    setError(null)
    try {
      await latest.current.client.registerPasskey()
      setStatus("added")
      await latest.current.onRegistered?.()
    } catch (caught) {
      setStatus("error")
      setError(
        caught instanceof Error ? caught.message : "Adding a passkey failed",
      )
    }
  }

  return { register, status, error }
}

import { useEffect, useState } from "react"

/**
 * Keep a form value across the full-page round trip through the auth routes.
 * A sign-in form posts straight to `/auth/{provider}/initiate`, which
 * redirects back with `?sent=1` or `?error=`, reloading the page and losing
 * what was typed. Call `save` from the form's onSubmit and the value comes
 * back on the next load, so the user can resend or retry without retyping.
 *
 * The value lives in sessionStorage rather than the redirect URL, which keeps
 * the address or number out of URLs, history, and server logs. Where storage
 * is unavailable the hook still works; it just forgets.
 *
 * @param storageKey - sessionStorage key; one per field
 * @returns The value, its setter, and `save`
 *
 * @example
 * ```tsx
 * const [email, setEmail, saveEmail] = usePreservedInput("login.email")
 * <form method="post" action="/auth/email/initiate" onSubmit={saveEmail}>
 *   <input name="email" value={email} onChange={(e) => setEmail(e.target.value)} />
 * ```
 */
export function usePreservedInput(
  storageKey: string,
): [value: string, setValue: (value: string) => void, save: () => void] {
  const [value, setValue] = useState("")

  // Read after mounting, not during render: the server has no sessionStorage,
  // and a different first render would not hydrate
  useEffect(() => {
    try {
      const saved = sessionStorage.getItem(storageKey)
      if (saved) setValue(saved)
    } catch {
      // Storage disabled (some private modes); start empty
    }
  }, [storageKey])

  function save(): void {
    try {
      sessionStorage.setItem(storageKey, value)
    } catch {
      // Storage disabled or full; the value is lost on reload, nothing worse
    }
  }

  return [value, setValue, save]
}

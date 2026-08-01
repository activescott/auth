import { useEffect, useState } from "react"

/**
 * Keeps a form value across a full-page round trip. The login forms post
 * directly to the auth routes, and the provider redirects back with
 * ?sent=1 or ?error=..., reloading the page and losing input state — so
 * the value is saved to sessionStorage (call `save` in the form's
 * onSubmit) and restored on the next load, letting the user resend or
 * retry after an error without retyping. sessionStorage rather than the
 * redirect URL keeps the address/number out of URLs, history, and server
 * logs.
 */
export function usePreservedInput(
  storageKey: string,
): [value: string, setValue: (value: string) => void, save: () => void] {
  const [value, setValue] = useState("")
  useEffect(() => {
    const saved = sessionStorage.getItem(storageKey)
    if (saved) setValue(saved)
  }, [storageKey])

  function save(): void {
    sessionStorage.setItem(storageKey, value)
  }

  return [value, setValue, save]
}

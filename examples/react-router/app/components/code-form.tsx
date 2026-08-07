import { useRef, useState } from "react"
import { Form } from "react-router"

/** Digits in a sign-in code. Both providers here are configured for six. */
const DEFAULT_CODE_LENGTH = 6

/**
 * One-time-code entry form, shared by every OTP-based provider — copy this
 * into your app as-is. It posts the code directly to the provider's verify
 * action (`/auth/email/verify`, `/auth/sms/verify`, ...); the challenge
 * cookie set at initiate identifies which sign-in attempt the code belongs
 * to. The input attributes are what make platform autofill work:
 * `autoComplete="one-time-code"` (iOS/macOS from Mail or Messages, Android
 * from SMS) plus `inputMode="numeric"` for the digit keyboard.
 *
 * Once `length` digits are entered the form submits itself, so autofill
 * finishes the sign-in without a button press. The button stays for the
 * cases autofill misses.
 *
 * `length` must match what the provider issues. Email codes use the SMS/email
 * provider's `otp.length` (6 by default). Twilio Verify uses the `code_length`
 * on the Verify service (4-10, 6 by default) — the start API does not return
 * it, so it cannot be discovered at runtime without a separate service lookup.
 */
export function CodeForm({
  action,
  length = DEFAULT_CODE_LENGTH,
  children,
}: {
  action: string
  length?: number
  children: string
}) {
  const formRef = useRef<HTMLFormElement>(null)
  // Autofill can fire more than one change event with a complete code, and
  // requestSubmit() during an in-flight navigation throws
  const [submitting, setSubmitting] = useState(false)

  function handleChange(event: React.ChangeEvent<HTMLInputElement>) {
    if (submitting) return
    if (event.target.value.length !== length) return
    setSubmitting(true)
    formRef.current?.requestSubmit()
  }

  return (
    <Form
      ref={formRef}
      method="post"
      action={action}
      reloadDocument
      className="flex flex-col gap-3 mt-6"
    >
      <label htmlFor="code">{children}</label>
      <input
        id="code"
        name="code"
        type="text"
        autoComplete="one-time-code"
        inputMode="numeric"
        pattern={`[0-9]{${length}}`}
        maxLength={length}
        required
        autoFocus
        onChange={handleChange}
        className="border p-2 rounded font-mono text-2xl tracking-[0.5em] text-center"
      />
      <button
        type="submit"
        disabled={submitting}
        className="bg-blue-600 text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50"
      >
        {submitting ? "Signing in…" : "Sign in with code"}
      </button>
    </Form>
  )
}

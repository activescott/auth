import { Form } from "react-router"
import { useOtpAutoSubmit } from "@activescott/auth-adapter-react-router/client"

/** Digits in a sign-in code. Both providers here are configured for six. */
const DEFAULT_CODE_LENGTH = 6

/**
 * One-time-code entry form, shared by every OTP-based provider — copy this
 * into your app as-is. It posts the code directly to the provider's verify
 * action (`/auth/email/verify`, `/auth/sms/verify`, ...); the challenge
 * cookie set at initiate identifies which sign-in attempt the code belongs
 * to.
 *
 * `useOtpAutoSubmit` supplies the input attributes platform autofill looks
 * for (`autoComplete="one-time-code"`, the numeric keyboard) and submits the
 * form once `length` digits are in, so autofill finishes the sign-in without
 * a button press. The button stays for the cases autofill misses.
 *
 * `length` must match what the provider issues. Email codes use the SMS/email
 * provider's `otp.length` (6 by default). Twilio Verify uses the `code_length`
 * on the Verify service (4-10, 6 by default) — the start API does not return
 * it, so it cannot be discovered at runtime without a separate service lookup.
 */
export function CodeForm({
  action,
  length = DEFAULT_CODE_LENGTH,
  submitLabel = "Sign in with code",
  children,
}: {
  action: string
  length?: number
  /** Button text; override for flows that are not a sign-in (e.g. linking) */
  submitLabel?: string
  children: string
}) {
  const { inputProps, submitting } = useOtpAutoSubmit(length)

  return (
    <Form
      method="post"
      action={action}
      reloadDocument
      className="flex flex-col gap-3 mt-6"
    >
      <label htmlFor="code">{children}</label>
      <input
        id="code"
        type="text"
        required
        autoFocus
        {...inputProps}
        className="border p-2 rounded font-mono text-2xl tracking-[0.5em] text-center"
      />
      <button
        type="submit"
        disabled={submitting}
        className="bg-blue-600 text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50"
      >
        {submitting ? "Submitting…" : submitLabel}
      </button>
    </Form>
  )
}

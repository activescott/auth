import { Form } from "react-router"

/**
 * One-time-code entry form, shared by every OTP-based provider — copy this
 * into your app as-is. It posts the code directly to the provider's verify
 * action (`/auth/email/verify`, `/auth/sms/verify`, ...); the challenge
 * cookie set at initiate identifies which sign-in attempt the code belongs
 * to. The input attributes are what make platform autofill work:
 * `autoComplete="one-time-code"` (iOS/macOS from Mail or Messages, Android
 * from SMS) plus `inputMode="numeric"` for the digit keyboard.
 */
export function CodeForm({
  action,
  children,
}: {
  action: string
  children: string
}) {
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
        name="code"
        type="text"
        autoComplete="one-time-code"
        inputMode="numeric"
        pattern="[0-9]{6}"
        maxLength={6}
        required
        className="border p-2 rounded font-mono text-2xl tracking-[0.5em] text-center"
      />
      <button
        type="submit"
        className="bg-blue-600 text-white py-2 rounded hover:bg-blue-700"
      >
        Sign in with code
      </button>
    </Form>
  )
}

import { useRef, useState } from "react"
import type { ChangeEvent } from "react"

/** Props for the code `<input>`; spread them, then add your own */
export interface OtpInputProps {
  /** The field the verify endpoints read */
  name: "code"
  /** Lets iOS/macOS offer the code from Mail or Messages, and Android from SMS */
  autoComplete: "one-time-code"
  /** The digit keyboard on phones */
  inputMode: "numeric"
  pattern: string
  maxLength: number
  onChange: (event: ChangeEvent<HTMLInputElement>) => void
}

/** What {@link useOtpAutoSubmit} returns */
export interface OtpAutoSubmitState {
  inputProps: OtpInputProps
  /** True once the code was submitted; disable the button on it */
  submitting: boolean
}

/**
 * Submit a one-time-code form as soon as the last digit lands, so platform
 * autofill finishes the sign-in without a button press. Keep a submit button
 * for the cases autofill misses.
 *
 * `length` has to match what the provider issues: `otp.length` on the email
 * and SMS providers (6 by default), or the `code_length` of a Twilio Verify
 * service (4 to 10, 6 by default), which its API does not report.
 *
 * @param length - Digits in the code
 *
 * @example
 * ```tsx
 * const { inputProps, submitting } = useOtpAutoSubmit(6)
 * <form method="post" action="/auth/email/verify">
 *   <input id="code" required {...inputProps} />
 *   <button disabled={submitting}>Sign in with code</button>
 * </form>
 * ```
 */
export function useOtpAutoSubmit(length: number): OtpAutoSubmitState {
  const [submitting, setSubmitting] = useState(false)
  // A second complete code can land before the page leaves (autofill
  // replacing what was typed), and requestSubmit() during an in-flight
  // navigation throws. A ref rather than state, so two change events in one
  // tick are caught too.
  const submitted = useRef(false)

  function onChange(event: ChangeEvent<HTMLInputElement>): void {
    const input = event.currentTarget
    if (input.value.length < length) {
      // Edited after a submit that did not leave the page: allow another
      if (submitted.current) {
        submitted.current = false
        setSubmitting(false)
      }
      return
    }
    if (submitted.current || input.value.length !== length) return
    if (!input.form || !input.checkValidity()) return
    submitted.current = true
    setSubmitting(true)
    input.form.requestSubmit()
  }

  return {
    inputProps: {
      name: "code",
      autoComplete: "one-time-code",
      inputMode: "numeric",
      pattern: `[0-9]{${length}}`,
      maxLength: length,
      onChange,
    },
    submitting,
  }
}

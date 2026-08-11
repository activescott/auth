/**
 * Sends SMS messages. Implementations live in vendor packages
 * (@activescott/auth-sms-twilio) or your own
 * code; the provider itself has no vendor dependencies.
 */
export interface SmsTransport {
  /**
   * Send a message to an E.164 phone number. Returns false when the send
   * failed and the user should be shown an error.
   */
  sendMessage(to: string, message: string): Promise<boolean>
}

/**
 * Outcome of asking a hosted verification service to send a code.
 * `reference` is whatever the vendor needs back at check time; vendors that
 * key the check on the phone number alone (Twilio Verify) return none.
 */
export type VerificationStart =
  { ok: true; reference?: string } | { ok: false; message?: string }

/**
 * Outcome of submitting a code to a hosted verification service. The statuses
 * mirror the failure reasons the local one-time-code path already produces, so
 * both paths return the same errors to the browser.
 */
export type VerificationCheck =
  | { status: "approved" }
  | { status: "invalid_code" }
  | { status: "expired" }
  | { status: "rate_limited" }
  | { status: "error"; message?: string }

/**
 * A hosted verification service that generates, delivers, and checks the code
 * itself (Twilio Verify, Vonage Verify, ...). Use this instead of SmsTransport
 * when you want to avoid registering your own US A2P 10DLC brand and campaign:
 * the vendor sends from senders it already owns and has registered. It costs
 * substantially more per sign-in than sending a raw SMS yourself.
 *
 * The plaintext code never reaches your server on this path.
 */
export interface VerificationTransport {
  /**
   * Ask the vendor to generate a code and deliver it to an E.164 number.
   */
  startVerification(to: string): Promise<VerificationStart>

  /**
   * Submit a code the user typed. `reference` is what startVerification
   * returned for this verification, if anything.
   */
  checkVerification(
    to: string,
    reference: string | undefined,
    code: string,
  ): Promise<VerificationCheck>
}

/**
 * True when a transport is a hosted verification service rather than a plain
 * message sender. Exported so application code can branch on the two without
 * a type cast.
 */
export function isVerificationTransport(
  transport: SmsTransport | VerificationTransport,
): transport is VerificationTransport {
  return "startVerification" in transport
}

export interface SmsOtpConfig {
  /** Number of digits in the code (default 6) */
  length?: number
  /** Attempts allowed before the challenge is invalidated (default 5) */
  maxAttempts?: number
  /** Name of the HttpOnly cookie binding the challenge to the browser (default "auth_sms_challenge") */
  cookieName?: string
}

/**
 * `appName`, `messageTemplate`, `webOtpDomain`, and `otp.length` describe a
 * message this package composes, so they do nothing when the provider is given
 * a VerificationTransport — the vendor owns the code and the message text
 * there. `expiry`, `otp.maxAttempts`, and `otp.cookieName` apply to both.
 */
export interface SmsProviderConfig {
  /** App name shown in the default message template (default "App") */
  appName?: string
  /**
   * How long a code stays valid, e.g. "10m", "300s" (default "10m"). With a
   * VerificationTransport this bounds our own challenge record; the vendor
   * enforces its own code lifetime and whichever expires first wins.
   */
  expiry?: string
  /**
   * Domain for the WebOTP autofill line appended to the message
   * (`@domain #code`). Set this to your app's origin domain (no scheme) to
   * enable one-tap autofill in Chrome/Android; omit to skip the line.
   * See https://developer.mozilla.org/docs/Web/API/WebOTP_API
   */
  webOtpDomain?: string
  /**
   * Override the message text. Receives the code and the configured app
   * name; the WebOTP line (when webOtpDomain is set) is appended after
   * this text on its own final line, as the spec requires.
   */
  messageTemplate?: (code: string, appName: string) => string
  /**
   * Override the message text for link-mode confirmations (a signed-in
   * user adding this phone number to their account). Falls back to
   * `messageTemplate`, then to a default worded as a confirmation rather
   * than a sign-in — the recipient of a link text did not ask to sign in.
   * Same WebOTP handling as `messageTemplate`.
   */
  linkMessageTemplate?: (code: string, appName: string) => string
  otp?: SmsOtpConfig
}

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

export interface SmsOtpConfig {
  /** Number of digits in the code (default 6) */
  length?: number
  /** Attempts allowed before the challenge is invalidated (default 5) */
  maxAttempts?: number
  /** Name of the HttpOnly cookie binding the challenge to the browser (default "auth_sms_challenge") */
  cookieName?: string
}

export interface SmsProviderConfig {
  /** App name shown in the default message template (default "App") */
  appName?: string
  /**
   * How long a code stays valid, e.g. "10m", "300s" (default "10m")
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
  otp?: SmsOtpConfig
}

/**
 * Email provider configuration
 */
export interface EmailProviderConfig {
  /** How long a sign-in email is valid — covers both the magic link and
   * the code, since they redeem the same challenge (e.g., "15m"; default
   * "15m") */
  expiry?: string
  /** SMTP configuration */
  smtp: SmtpConfig
  /** Sender email address */
  from: string
  /** Email template customization */
  template?: EmailTemplateConfig
  /** One-time code tuning */
  otp?: EmailOtpConfig
}

/**
 * One-time code (OTP) tuning for the email provider
 */
export interface EmailOtpConfig {
  /** Number of digits in the code (default: 6) */
  length?: number
  /** Maximum verification attempts before the code is rejected (default: 5) */
  maxAttempts?: number
  /** Name of the HttpOnly cookie that binds code entry to the initiating
   * browser (default: "auth_challenge") */
  cookieName?: string
}

/**
 * SMTP server configuration
 */
export interface SmtpConfig {
  host: string
  port: number
  user: string
  pass: string
  /** Whether to use TLS. Auto-detected from port if not specified */
  secure?: boolean
}

/**
 * Email template customization
 */
export interface EmailTemplateConfig {
  /** Email subject line for sign-in emails */
  subject?: string
  /**
   * Subject line for link-mode confirmations (a signed-in user adding this
   * address to their account; default "Confirm your email"). Kept separate
   * from `subject` because a link recipient did not ask to sign in — a
   * "Sign in" subject there reads like a request they never made.
   */
  linkSubject?: string
  /** Application name shown in email */
  appName?: string
  /** Primary brand color (hex) */
  primaryColor?: string
  /** Logo URL to include in email */
  logoUrl?: string
}

/**
 * Email transport interface for sending emails
 */
export interface EmailTransport {
  sendMagicLink(
    to: string,
    magicLink: string,
    config: EmailProviderConfig,
    options?: SendMagicLinkOptions,
  ): Promise<boolean>
}

/**
 * Additional content for a magic link email
 */
export interface SendMagicLinkOptions {
  /** One-time code to include in the email alongside the link */
  code?: string
  /**
   * Which flow this email confirms: an ordinary sign-in, or a signed-in
   * user linking this address to their account (`mode: "link"`).
   * Transports use it to word the message accordingly; absent means
   * "sign-in".
   */
  purpose?: "sign-in" | "link"
}

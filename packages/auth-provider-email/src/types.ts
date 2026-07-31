/**
 * Email provider configuration
 */
export interface EmailProviderConfig {
  /** Secret for signing magic link tokens */
  magicLinkSecret: string
  /** Additional secrets for verification (e.g., for E2E testing) */
  additionalSecrets?: string[]
  /** Magic link expiration (e.g., "5m", "15m") */
  magicLinkExpiry: string
  /** SMTP configuration */
  smtp: SmtpConfig
  /** Sender email address */
  from: string
  /** Email template customization */
  template?: EmailTemplateConfig
  /** One-time code tuning. Codes are included automatically whenever the
   * Auth config has a challengeStore; use enabled to override. */
  otp?: EmailOtpConfig
}

/**
 * One-time code (OTP) configuration for the email provider
 */
export interface EmailOtpConfig {
  /** Override the default (codes on when a challengeStore is configured):
   * false opts out; true requires a challengeStore and errors without one */
  enabled?: boolean
  /** Number of digits in the code (default: 6) */
  length?: number
  /** Code expiration (e.g., "10m"); default: "10m" */
  expiry?: string
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
  /** Email subject line */
  subject?: string
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
}

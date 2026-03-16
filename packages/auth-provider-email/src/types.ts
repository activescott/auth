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
  ): Promise<boolean>
}

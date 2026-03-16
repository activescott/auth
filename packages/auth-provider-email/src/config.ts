import type { EmailProviderConfig } from "./types.js"

/** Minimum length for magic link secrets (32 characters = 256 bits) */
const MIN_SECRET_LENGTH = 32
/** Default SMTP port for email submission */
const DEFAULT_SMTP_PORT = 587

/**
 * Validates email provider configuration and returns validated config
 * Throws with actionable error messages if configuration is invalid
 */
// eslint-disable-next-line complexity -- validation logic is inherently multi-conditional
export function validateEmailConfig(
  config: Partial<EmailProviderConfig>,
): EmailProviderConfig {
  const errors: string[] = []

  // Required fields
  if (
    !config.magicLinkSecret ||
    config.magicLinkSecret.length < MIN_SECRET_LENGTH
  ) {
    errors.push(
      `magicLinkSecret must be at least ${MIN_SECRET_LENGTH} characters. ` +
        `Generate one with: node -e "console.log(require('crypto').randomBytes(${MIN_SECRET_LENGTH}).toString('hex'))"`,
    )
  }

  if (!config.smtp?.host) {
    errors.push("smtp.host is required (SMTP server hostname)")
  }

  if (!config.smtp?.user) {
    errors.push("smtp.user is required (SMTP username)")
  }

  if (!config.smtp?.pass) {
    errors.push("smtp.pass is required (SMTP password)")
  }

  if (!config.from) {
    errors.push("from is required (sender email address)")
  }

  if (errors.length > 0) {
    throw new Error(
      `Email provider configuration error:\n  - ${errors.join("\n  - ")}`,
    )
  }

  // At this point, all required fields are validated
  // TypeScript doesn't know this, so we need to assert
  const smtp = config.smtp as NonNullable<typeof config.smtp>
  const magicLinkSecret = config.magicLinkSecret as string
  const from = config.from as string

  // Return validated config with defaults
  return {
    magicLinkSecret,
    additionalSecrets: config.additionalSecrets,
    magicLinkExpiry: config.magicLinkExpiry ?? "15m",
    smtp: {
      host: smtp.host,
      port: smtp.port ?? DEFAULT_SMTP_PORT,
      user: smtp.user,
      pass: smtp.pass,
      secure: smtp.secure,
    },
    from,
    template: {
      subject: config.template?.subject ?? "Sign in",
      appName: config.template?.appName ?? "App",
      primaryColor: config.template?.primaryColor ?? "#6366f1",
      logoUrl: config.template?.logoUrl,
    },
  }
}

/**
 * Create email provider config from environment variables
 *
 * Expected environment variables:
 * - MAGIC_LINK_SECRET or AUTH_MAGIC_LINK_SECRET (required)
 * - E2E_MAGIC_LINK_SECRET (optional, for testing)
 * - MAGIC_LINK_EXPIRY (optional, default: "15m")
 * - SMTP_HOST (required)
 * - SMTP_PORT (optional, default: 587)
 * - SMTP_USER (required)
 * - SMTP_PASS (required)
 * - FROM_EMAIL or SMTP_FROM (required)
 * - APP_NAME (optional)
 * - AUTH_PRIMARY_COLOR (optional)
 * - AUTH_LOGO_URL (optional)
 */
// eslint-disable-next-line complexity -- config assembly from env vars requires many conditionals
export function emailConfigFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): EmailProviderConfig {
  const additionalSecrets: string[] = []
  if (environment.E2E_MAGIC_LINK_SECRET) {
    additionalSecrets.push(environment.E2E_MAGIC_LINK_SECRET)
  }

  const config: Partial<EmailProviderConfig> = {
    magicLinkSecret:
      environment.MAGIC_LINK_SECRET ?? environment.AUTH_MAGIC_LINK_SECRET,
    additionalSecrets:
      additionalSecrets.length > 0 ? additionalSecrets : undefined,
    magicLinkExpiry: environment.MAGIC_LINK_EXPIRY ?? "15m",
    smtp: {
      host: environment.SMTP_HOST ?? "",
      port: environment.SMTP_PORT
        ? Number.parseInt(environment.SMTP_PORT, 10)
        : DEFAULT_SMTP_PORT,
      user: environment.SMTP_USER ?? "",
      pass: environment.SMTP_PASS ?? "",
    },
    from: environment.FROM_EMAIL ?? environment.SMTP_FROM ?? "",
    template: {
      appName: environment.APP_NAME,
      primaryColor: environment.AUTH_PRIMARY_COLOR,
      logoUrl: environment.AUTH_LOGO_URL,
    },
  }

  try {
    return validateEmailConfig(config)
  } catch (error) {
    if (error instanceof Error) {
      // Add environment variable hints
      const hints = `
Required environment variables:
  MAGIC_LINK_SECRET  - Secret for signing magic link tokens (32+ chars)
  SMTP_HOST          - SMTP server hostname
  SMTP_USER          - SMTP username
  SMTP_PASS          - SMTP password
  FROM_EMAIL         - Sender email address

Optional environment variables:
  E2E_MAGIC_LINK_SECRET - Additional secret for E2E testing
  MAGIC_LINK_EXPIRY     - Token expiry (default: "15m")
  SMTP_PORT             - SMTP port (default: 587)
  APP_NAME              - Application name in emails
  AUTH_PRIMARY_COLOR    - Brand color in emails
  AUTH_LOGO_URL         - Logo URL in emails`

      throw new Error(`${error.message}\n${hints}`)
    }
    throw error
  }
}

import type { EmailProviderConfig } from "./types.js"

/** Default SMTP port for email submission */
const DEFAULT_SMTP_PORT = 587
/** Default sign-in email expiry (magic link and code share it) */
const DEFAULT_EXPIRY = "15m"
/** Default number of digits in an OTP code */
const DEFAULT_OTP_LENGTH = 6
/** Default maximum OTP verification attempts */
const DEFAULT_OTP_MAX_ATTEMPTS = 5
/** Default challenge cookie name */
const DEFAULT_OTP_COOKIE_NAME = "auth_challenge"

/**
 * Validates email provider configuration and returns validated config
 * Throws with actionable error messages if configuration is invalid
 */
export function validateEmailConfig(
  config: Partial<EmailProviderConfig>,
): EmailProviderConfig {
  const errors: string[] = []

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
  const from = config.from as string

  return {
    expiry: config.expiry ?? DEFAULT_EXPIRY,
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
    otp: {
      length: config.otp?.length ?? DEFAULT_OTP_LENGTH,
      maxAttempts: config.otp?.maxAttempts ?? DEFAULT_OTP_MAX_ATTEMPTS,
      cookieName: config.otp?.cookieName ?? DEFAULT_OTP_COOKIE_NAME,
    },
  }
}

/**
 * Create email provider config from environment variables
 *
 * Expected environment variables:
 * - SMTP_HOST (required)
 * - SMTP_PORT (optional, default: 587)
 * - SMTP_USER (required)
 * - SMTP_PASS (required)
 * - FROM_EMAIL or SMTP_FROM (required)
 * - EMAIL_EXPIRY (optional, default: "15m")
 * - EMAIL_OTP_LENGTH (optional, default: 6)
 * - EMAIL_OTP_MAX_ATTEMPTS (optional, default: 5)
 * - APP_NAME (optional)
 * - AUTH_PRIMARY_COLOR (optional)
 * - AUTH_LOGO_URL (optional)
 */
export function emailConfigFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): EmailProviderConfig {
  const config: Partial<EmailProviderConfig> = {
    expiry: environment.EMAIL_EXPIRY,
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
    otp: {
      length: environment.EMAIL_OTP_LENGTH
        ? Number.parseInt(environment.EMAIL_OTP_LENGTH, 10)
        : undefined,
      maxAttempts: environment.EMAIL_OTP_MAX_ATTEMPTS
        ? Number.parseInt(environment.EMAIL_OTP_MAX_ATTEMPTS, 10)
        : undefined,
    },
  }

  try {
    return validateEmailConfig(config)
  } catch (error) {
    if (error instanceof Error) {
      // Add environment variable hints
      const hints = `
Required environment variables:
  SMTP_HOST          - SMTP server hostname
  SMTP_USER          - SMTP username
  SMTP_PASS          - SMTP password
  FROM_EMAIL         - Sender email address

Optional environment variables:
  EMAIL_EXPIRY           - Sign-in email expiry (default: "15m")
  EMAIL_OTP_LENGTH       - Code digits (default: 6)
  EMAIL_OTP_MAX_ATTEMPTS - Max verification attempts (default: 5)
  SMTP_PORT              - SMTP port (default: 587)
  APP_NAME               - Application name in emails
  AUTH_PRIMARY_COLOR     - Brand color in emails
  AUTH_LOGO_URL          - Logo URL in emails`

      throw new Error(`${error.message}\n${hints}`)
    }
    throw error
  }
}

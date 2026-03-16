// Email provider
export { EmailProvider } from "./email-provider.js"

// Configuration
export { validateEmailConfig, emailConfigFromEnvironment } from "./config.js"

// Types
export type {
  EmailProviderConfig,
  SmtpConfig,
  EmailTemplateConfig,
  EmailTransport,
} from "./types.js"

// Transports
export { NodemailerTransport } from "./transports/index.js"

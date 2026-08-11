import nodemailer from "nodemailer"
import type {
  EmailTransport,
  EmailProviderConfig,
  SendMagicLinkOptions,
} from "../types.js"

// Standard port for SMTPS (implicit TLS)
const SMTPS_PORT = 465

/**
 * Nodemailer-based email transport
 */
export class NodemailerTransport implements EmailTransport {
  private transporter: nodemailer.Transporter | null = null
  private isDevelopment: boolean

  public constructor(isDevelopment = false) {
    this.isDevelopment = isDevelopment
  }

  public async sendMagicLink(
    to: string,
    magicLink: string,
    config: EmailProviderConfig,
    options?: SendMagicLinkOptions,
  ): Promise<boolean> {
    try {
      const transporter = this.getTransporter(config)

      const { template, from } = config
      const appName = template?.appName ?? "App"
      const primaryColor = template?.primaryColor ?? "#6366f1"
      const code = options?.code
      const linking = options?.purpose === "link"

      // A link confirmation goes to an address whose owner did not ask to
      // sign in, so it must not read like a sign-in request
      const subject = linking
        ? `${template?.linkSubject ?? "Confirm your email"} for ${appName}`
        : `${template?.subject ?? "Sign in"} to ${appName}`

      const mailOptions = {
        from,
        to,
        subject,
        html: this.generateHtmlEmail(
          magicLink,
          appName,
          primaryColor,
          code,
          linking,
        ),
        text: this.generateTextEmail(magicLink, appName, code, linking),
      }

      await transporter.sendMail(mailOptions)

      if (this.isDevelopment) {
        // eslint-disable-next-line no-console
        console.info(`
📧 Magic link email (development mode):
To: ${to}
Magic Link: ${magicLink}${code ? `\nCode: ${code}` : ""}
---
`)
      }

      return true
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("Failed to send magic link email:", error)
      return false
    }
  }

  private getTransporter(config: EmailProviderConfig): nodemailer.Transporter {
    if (this.transporter) {
      return this.transporter
    }

    if (this.isDevelopment) {
      // Development mode: log to console instead of sending
      this.transporter = nodemailer.createTransport({
        streamTransport: true,
        newline: "unix",
        buffer: true,
      })
    } else {
      // Production mode: real SMTP
      const { smtp } = config
      this.transporter = nodemailer.createTransport({
        host: smtp.host,
        port: smtp.port,
        // Auto-detect TLS from port if not specified
        secure: smtp.secure ?? smtp.port === SMTPS_PORT,
        auth: {
          user: smtp.user,
          pass: smtp.pass,
        },
      })
    }

    return this.transporter
  }

  private generateHtmlEmail(
    magicLink: string,
    appName: string,
    primaryColor: string,
    code?: string,
    linking = false,
  ): string {
    const heading = linking
      ? `Confirm your email for ${appName}`
      : `Sign in to ${appName}`
    const lede = linking
      ? `Confirm to add this email address to your ${appName} account:`
      : `Click the link below to sign in to your ${appName} account:`
    const buttonLabel = linking ? "Confirm Email" : "Sign In"
    const codeNoun = linking ? "confirmation" : "sign-in"
    const codeHint = linking
      ? "Enter this code where you started adding the email, or click the button below."
      : "Enter this code on the sign-in page, or click the button below."

    // The code sentence stays literal ("Your ... code is: NNNNNN") so
    // Apple Mail and similar clients detect it and offer AutoFill
    const codeSection = code
      ? `
        <p>Your ${codeNoun} code is:</p>
        <p style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 32px; font-weight: 700; letter-spacing: 6px; margin: 16px 0;">${code}</p>
        <p style="color: #6b7280; font-size: 14px;">${codeHint}</p>
      `
      : ""

    return `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: ${primaryColor};">${heading}</h2>
        ${codeSection}
        <p>${lede}</p>

        <div style="margin: 30px 0;">
          <a href="${magicLink}"
             style="background: ${primaryColor}; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
            ${buttonLabel}
          </a>
        </div>

        <p style="color: #6b7280; font-size: 14px;">
          This link will expire in 5 minutes. If you didn't request this email, you can safely ignore it.
        </p>

        <p style="color: #6b7280; font-size: 12px; margin-top: 40px;">
          If the button doesn't work, copy and paste this link into your browser:<br>
          <a href="${magicLink}" style="color: ${primaryColor}; word-break: break-all;">${magicLink}</a>
        </p>
      </div>
    `
  }

  private generateTextEmail(
    magicLink: string,
    appName: string,
    code?: string,
    linking = false,
  ): string {
    const heading = linking
      ? `Confirm your email for ${appName}`
      : `Sign in to ${appName}`
    const codeNoun = linking ? "confirmation" : "sign-in"
    const linkVerb = linking
      ? "confirm adding this email to your account"
      : "sign in"
    const codeSection = code ? `Your ${codeNoun} code is: ${code}\n\n` : ""
    return `
${heading}

${codeSection}Click this link to ${linkVerb}: ${magicLink}

This link will expire in 5 minutes.

If you didn't request this email, you can safely ignore it.
    `.trim()
  }
}

import nodemailer from "nodemailer"
import type { EmailTransport, EmailProviderConfig } from "../types.js"

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
  ): Promise<boolean> {
    try {
      const transporter = this.getTransporter(config)

      const { template, from } = config
      const appName = template?.appName ?? "App"
      const subject = template?.subject ?? "Sign in"
      const primaryColor = template?.primaryColor ?? "#6366f1"

      const mailOptions = {
        from,
        to,
        subject: `${subject} to ${appName}`,
        html: this.generateHtmlEmail(magicLink, appName, primaryColor),
        text: this.generateTextEmail(magicLink, appName),
      }

      await transporter.sendMail(mailOptions)

      if (this.isDevelopment) {
        // eslint-disable-next-line no-console
        console.info(`
📧 Magic link email (development mode):
To: ${to}
Magic Link: ${magicLink}
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
  ): string {
    return `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: ${primaryColor};">Sign in to ${appName}</h2>

        <p>Click the link below to sign in to your ${appName} account:</p>

        <div style="margin: 30px 0;">
          <a href="${magicLink}"
             style="background: ${primaryColor}; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
            Sign In
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

  private generateTextEmail(magicLink: string, appName: string): string {
    return `
Sign in to ${appName}

Click this link to sign in: ${magicLink}

This link will expire in 5 minutes.

If you didn't request this email, you can safely ignore it.
    `.trim()
  }
}

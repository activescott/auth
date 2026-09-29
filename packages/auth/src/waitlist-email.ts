import type { WaitlistNotice } from "./waitlist.js"

/** Options for {@link waitlistNotificationEmail} */
export interface WaitlistEmailOptions {
  /** Shown in the subject and body, e.g. "Fernfiles" */
  appName: string
  /**
   * The app's domain, e.g. "fernfiles.com"; the review link points at
   * `https://<domain>`. An origin with a scheme ("http://localhost:5173") is
   * used as given.
   */
  domain: string
  /** Sender address */
  from: string
  /** Path of the admin users page (default "/admin/users") */
  adminPath?: string
}

/** A rendered email, shaped for nodemailer's `sendMail` once `to` is added */
export interface WaitlistEmail {
  from: string
  subject: string
  text: string
  html: string
}

/** Options for {@link waitlistApprovalEmail} */
export interface WaitlistApprovalEmailOptions {
  /** Shown in the subject and body, e.g. "Fernfiles" */
  appName: string
  /**
   * The app's domain, e.g. "fernfiles.com"; the sign-in link points at
   * `https://<domain>`. An origin with a scheme ("http://localhost:5173") is
   * used as given.
   */
  domain: string
  /** Sender address */
  from: string
  /** Path of the sign-in page (default "/login") */
  signInPath?: string
}

const DEFAULT_ADMIN_PATH = "/admin/users"
const DEFAULT_SIGN_IN_PATH = "/login"

/**
 * Render the email telling admins about a {@link WaitlistNotice}. Sending it
 * is up to the app, so the core stays free of mail dependencies:
 *
 * ```ts
 * notify: (notice) =>
 *   transporter.sendMail({
 *     ...waitlistNotificationEmail(notice, { appName, domain, from }),
 *     to: adminEmails,
 *   }),
 * ```
 */
export function waitlistNotificationEmail(
  notice: WaitlistNotice,
  options: WaitlistEmailOptions,
): WaitlistEmail {
  const { appName, from } = options
  const reviewUrl = `${originOf(options.domain)}${options.adminPath ?? DEFAULT_ADMIN_PATH}`
  const waitlisted = notice.reason === "waitlisted"

  const subject = waitlisted
    ? `New ${appName} user awaiting approval`
    : `New ${appName} user approved automatically`
  const lede = waitlisted
    ? `Someone wants to sign in to ${appName} and is on the waitlist until an admin approves or blocks them.`
    : `A new ${appName} user was approved automatically by one of the app's rules. Nothing needs doing unless you want to block them.`

  const text = [
    subject,
    "",
    lede,
    "",
    `${notice.provider}: ${notice.identifier}`,
    "",
    `Review: ${reviewUrl}`,
  ].join("\n")

  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #111827;">
      <h2 style="margin-top: 0;">${escapeHtml(subject)}</h2>
      <p>${escapeHtml(lede)}</p>
      <p style="background: #f3f4f6; padding: 12px 16px; border-radius: 6px;">
        ${escapeHtml(notice.provider)}: <strong>${escapeHtml(notice.identifier)}</strong>
      </p>
      <p style="margin: 24px 0;">
        <a href="${escapeHtml(reviewUrl)}" style="background: #111827; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Review users</a>
      </p>
      <p style="color: #6b7280; font-size: 12px;">Sent by ${escapeHtml(appName)} (${escapeHtml(options.domain)}).</p>
    </div>
  `

  return { from, subject, text, html }
}

/**
 * Render the email telling a user an admin approved them, for
 * `WaitlistConfig.onApproved`. Sending it is up to the app, which also picks
 * the address from the notice's identities:
 *
 * ```ts
 * onApproved: ({ identities }) => {
 *   const to = identities.find((i) => i.provider === "email")?.identifier
 *   if (to) return transporter.sendMail({ ...waitlistApprovalEmail(options), to })
 * },
 * ```
 */
export function waitlistApprovalEmail(
  options: WaitlistApprovalEmailOptions,
): WaitlistEmail {
  const { appName, from } = options
  const signInUrl = `${originOf(options.domain)}${options.signInPath ?? DEFAULT_SIGN_IN_PATH}`
  const subject = `Your ${appName} account is approved`
  const lede = `An admin approved your ${appName} account. You can sign in now.`

  const text = [subject, "", lede, "", `Sign in: ${signInUrl}`].join("\n")

  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #111827;">
      <h2 style="margin-top: 0;">${escapeHtml(subject)}</h2>
      <p>${escapeHtml(lede)}</p>
      <p style="margin: 24px 0;">
        <a href="${escapeHtml(signInUrl)}" style="background: #111827; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Sign in</a>
      </p>
      <p style="color: #6b7280; font-size: 12px;">Sent by ${escapeHtml(appName)} (${escapeHtml(options.domain)}).</p>
    </div>
  `

  return { from, subject, text, html }
}

/** `https://<domain>`, or the domain as given when it already has a scheme */
function originOf(domain: string): string {
  return domain.includes("://")
    ? domain.replace(/\/+$/, "")
    : `https://${domain}`
}

/** The identifier is user input and the rest is config; escape all of it */
function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
}

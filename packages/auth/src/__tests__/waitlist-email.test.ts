import { describe, it, expect } from "vitest"
import { waitlistNotificationEmail } from "../waitlist-email.js"
import type { WaitlistNotice } from "../waitlist.js"

const NOTICE: WaitlistNotice = {
  reason: "waitlisted",
  userId: "user-1",
  provider: "email",
  identifier: "new@example.com",
}

const OPTIONS = {
  appName: "Fernfiles",
  domain: "fernfiles.com",
  from: "noreply@fernfiles.com",
}

describe("waitlistNotificationEmail", () => {
  it("names the app, the identifier, and links to the admin users page", () => {
    const email = waitlistNotificationEmail(NOTICE, OPTIONS)

    expect(email.from).toBe("noreply@fernfiles.com")
    expect(email.subject).toBe("New Fernfiles user awaiting approval")
    expect(email.text).toContain("email: new@example.com")
    expect(email.text).toContain("https://fernfiles.com/admin/users")
    expect(email.html).toContain('href="https://fernfiles.com/admin/users"')
  })

  it("words an auto-approval as needing nothing", () => {
    const email = waitlistNotificationEmail(
      { ...NOTICE, reason: "auto-approved" },
      OPTIONS,
    )

    expect(email.subject).toBe("New Fernfiles user approved automatically")
  })

  it("uses an origin with a scheme as given, and a custom admin path", () => {
    const email = waitlistNotificationEmail(NOTICE, {
      ...OPTIONS,
      domain: "http://localhost:5173/",
      adminPath: "/staff/users",
    })

    expect(email.text).toContain("http://localhost:5173/staff/users")
  })

  it("escapes the identifier in the HTML", () => {
    const email = waitlistNotificationEmail(
      { ...NOTICE, identifier: '"<b>"@example.com' },
      OPTIONS,
    )

    expect(email.html).not.toContain("<b>")
    expect(email.html).toContain("&quot;&lt;b&gt;&quot;@example.com")
  })
})

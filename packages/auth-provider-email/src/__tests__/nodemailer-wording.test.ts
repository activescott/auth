import { describe, it, expect, vi, beforeEach } from "vitest"

const sendMail = vi.fn().mockResolvedValue({})
vi.mock("nodemailer", () => ({
  default: { createTransport: vi.fn(() => ({ sendMail })) },
}))

import { NodemailerTransport } from "../transports/nodemailer.js"
import type { EmailProviderConfig } from "../types.js"

const config: EmailProviderConfig = {
  smtp: { host: "smtp.test.com", port: 587, user: "u", pass: "p" },
  from: "login@example.com",
  template: { appName: "Test App" },
}

/** The mail nodemailer was asked to send in the last call */
function lastMail(): { subject: string; html: string; text: string } {
  const mail = sendMail.mock.calls.at(-1)?.[0]
  if (!mail) throw new Error("no mail sent")
  return mail
}

describe("NodemailerTransport wording", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("words a sign-in email as a sign-in", async () => {
    const transport = new NodemailerTransport()
    await transport.sendMagicLink("a@example.com", "https://x/verify", config, {
      code: "123456",
      purpose: "sign-in",
    })

    const mail = lastMail()
    expect(mail.subject).toBe("Sign in to Test App")
    expect(mail.html).toContain("Sign in to Test App")
    expect(mail.html).toContain("Your sign-in code is:")
    expect(mail.text).toContain("sign in")
  })

  it("defaults to sign-in wording when no purpose is given", async () => {
    const transport = new NodemailerTransport()
    await transport.sendMagicLink("a@example.com", "https://x/verify", config, {
      code: "123456",
    })

    expect(lastMail().subject).toBe("Sign in to Test App")
  })

  it("words a link email as a confirmation, not a sign-in request", async () => {
    const transport = new NodemailerTransport()
    await transport.sendMagicLink("a@example.com", "https://x/verify", config, {
      code: "123456",
      purpose: "link",
    })

    const mail = lastMail()
    expect(mail.subject).toBe("Confirm your email for Test App")
    expect(mail.html).toContain("Confirm your email for Test App")
    expect(mail.html).toContain("Confirm Email")
    // AutoFill heuristics still see a literal "code is:" sentence
    expect(mail.html).toContain("Your confirmation code is:")
    expect(mail.text).toContain("confirm adding this email to your account")
    expect(mail.subject).not.toContain("Sign in")
  })

  it("honors a configured linkSubject", async () => {
    const transport = new NodemailerTransport()
    await transport.sendMagicLink(
      "a@example.com",
      "https://x/verify",
      {
        ...config,
        template: { appName: "Test App", linkSubject: "Verify your address" },
      },
      { purpose: "link" },
    )

    expect(lastMail().subject).toBe("Verify your address for Test App")
  })
})

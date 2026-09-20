// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest"
import { act } from "react"
import { FORM_TOKEN_FIELD } from "@activescott/auth"
import type { LinkFlow, SignInMethod } from "../page-loaders.js"
import { SignInMethods } from "../profile/sign-in-methods.js"
import { render } from "./render.js"

const LINK_FLOW: LinkFlow = {
  add: null,
  sent: false,
  linked: false,
  merged: false,
  conflict: null,
  error: null,
  errorCode: null,
  formToken: "form-token",
  turnstileSiteKey: null,
}

function linkFlow(overrides: Partial<LinkFlow> = {}): LinkFlow {
  return { ...LINK_FLOW, ...overrides }
}

function identity(overrides: Partial<SignInMethod> = {}): SignInMethod {
  return {
    id: "identity-1",
    provider: "email",
    identifier: "user@example.com",
    createdAt: "2026-01-15T10:00:00.000Z",
    verifiedAt: "2026-01-15T10:00:00.000Z",
    ...overrides,
  }
}

/** Set a controlled input's value the way a user typing does */
function typeInto(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  )?.set
  act(() => {
    setter?.call(input, value)
    input.dispatchEvent(new Event("input", { bubbles: true }))
  })
}

function textOf(element: Element | null): string {
  return element?.textContent?.replace(/\s+/g, " ").trim() ?? ""
}

beforeEach(() => {
  sessionStorage.clear()
})

describe("SignInMethods", () => {
  it("lists the identifiers that sign in", () => {
    const { container } = render(
      <SignInMethods identities={[identity()]} linkFlow={linkFlow()} />,
    )

    const rows = container.querySelectorAll('[data-testid="sign-in-method"]')
    expect(rows).toHaveLength(1)
    expect([...rows[0].querySelectorAll("td")].map(textOf)).toEqual([
      "email",
      "user@example.com",
      "2026-01-15",
    ])
  })

  it("says so when nothing but a passkey signs in", () => {
    const { container } = render(
      <SignInMethods identities={[]} linkFlow={linkFlow()} />,
    )

    expect(container.querySelector("table")).toBeNull()
    expect(textOf(container)).toContain(
      "No email address or phone number signs in to this account yet",
    )
  })

  it("offers only the providers the account is missing", () => {
    const { container } = render(
      <SignInMethods
        identities={[identity()]}
        linkFlow={linkFlow()}
        addMethods={[{ provider: "email" }, { provider: "sms" }]}
      />,
    )

    const links = [...container.querySelectorAll("a")]
    expect(links.map((link) => link.textContent)).toEqual([
      "Add a phone number",
    ])
    expect(links[0].getAttribute("href")).toBe("/profile?add=sms")
  })

  it("offers a provider again when the account may have several", () => {
    const { container } = render(
      <SignInMethods
        identities={[identity()]}
        linkFlow={linkFlow()}
        addMethods={[{ provider: "email", allowMultiple: true }]}
      />,
    )

    expect(container.querySelector("a")?.textContent).toBe(
      "Add an email address",
    )
  })

  it("opens the add form the query asks for", () => {
    const { container } = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow({ add: "email" })}
        addMethods={[{ provider: "email" }]}
      />,
    )

    const form = container.querySelector("form")
    expect(form?.getAttribute("action")).toBe("/auth/email/initiate")
    expect(form?.getAttribute("method")).toBe("post")
    const values = Object.fromEntries(
      [...form!.querySelectorAll("input[type=hidden]")].map((input) => [
        input.getAttribute("name"),
        input.getAttribute("value"),
      ]),
    )
    expect(values).toMatchObject({
      mode: "link",
      redirectTo: "/profile?add=email&linked=1",
      [FORM_TOKEN_FIELD]: "form-token",
    })
  })

  it("composes the full number from the calling code", () => {
    const { container } = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow({ add: "sms" })}
        addMethods={[{ provider: "sms", callingCode: "+1" }]}
      />,
    )

    const visible = container.querySelector<HTMLInputElement>("input[type=tel]")
    expect(visible?.hasAttribute("name")).toBe(false)
    typeInto(visible!, "4155550100")

    expect(
      container.querySelector<HTMLInputElement>("input[name=phone]")?.value,
    ).toBe("+14155550100")
  })

  it("puts the saved identifier back after the round trip", () => {
    sessionStorage.setItem("profile.email", "second@example.com")
    const { container } = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow({ add: "email" })}
        addMethods={[{ provider: "email" }]}
      />,
    )

    expect(
      container.querySelector<HTMLInputElement>("input[name=email]")?.value,
    ).toBe("second@example.com")
  })

  it("redeems the code at the provider that sent it", () => {
    const { container } = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow({ add: "sms", sent: true })}
        addMethods={[{ provider: "sms" }]}
      />,
    )

    expect(textOf(container.querySelector('[data-testid="link-sent"]'))).toBe(
      "We texted you a code.",
    )
    const code = container.querySelector<HTMLInputElement>("input[name=code]")
    expect(code?.form?.getAttribute("action")).toBe(
      "/auth/sms/verify?redirectTo=%2Fprofile%3Fadd%3Dsms%26linked%3D1",
    )
    expect(textOf(code?.labels?.[0] ?? null)).toBe(
      "Enter the code from the text",
    )
  })

  it("keeps the code form but drops the notice when the verify failed", () => {
    const { container } = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow({
          add: "email",
          sent: true,
          error: "That code is wrong or expired.",
          errorCode: "INVALID_CREDENTIALS",
        })}
        addMethods={[{ provider: "email" }]}
      />,
    )

    expect(container.querySelector('[data-testid="link-sent"]')).toBeNull()
    const error = container.querySelector('[data-testid="link-error"]')
    expect(textOf(error)).toBe("Error: That code is wrong or expired.")
    // The code is what was rejected, so the address above it is not marked
    const code = container.querySelector<HTMLInputElement>("input[name=code]")
    expect(code?.getAttribute("aria-invalid")).toBe("true")
    expect(code?.getAttribute("aria-describedby")).toBe(error!.id)
    expect(
      container
        .querySelector("input[name=email]")
        ?.hasAttribute("aria-invalid"),
    ).toBe(false)
  })

  it("confirms the method that was just added", () => {
    const { container } = render(
      <SignInMethods
        identities={[identity()]}
        linkFlow={linkFlow({ linked: true })}
      />,
    )

    expect(
      textOf(container.querySelector('[data-testid="link-success"]')),
    ).toContain("Sign-in method added.")
  })

  it("reports a conflict as an error but leaves the form open for a retry", () => {
    const { container } = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow({
          add: "sms",
          errorCode: "IDENTITY_CONFLICT",
          conflict: { provider: "sms" },
        })}
        addMethods={[{ provider: "sms" }]}
      />,
    )

    const error = container.querySelector('[data-testid="link-error"]')
    expect(textOf(error)).toBe(
      "Error: That phone number already signs in to another account.",
    )
    expect(container.querySelector('[data-testid="merge-prompt"]')).toBeNull()
    // The number may simply have been mistyped, so there is a way to correct it
    const form = container.querySelector('[data-testid="add-sms"]')
    expect(form).not.toBeNull()
    const input = form!.querySelector<HTMLInputElement>("input[name=phone]")
    expect(input?.getAttribute("aria-invalid")).toBe("true")
    expect(input?.getAttribute("aria-describedby")).toBe(error!.id)
    expect(error!.id).not.toBe("")
  })

  it("closes the add form once the method is linked", () => {
    const { container } = render(
      <SignInMethods
        identities={[identity()]}
        linkFlow={linkFlow({ add: "email", linked: true })}
        // allowMultiple, so the form closing is the outcome and not the
        // already-have filter
        addMethods={[{ provider: "email", allowMultiple: true }]}
      />,
    )

    expect(container.querySelector('[data-testid="add-email"]')).toBeNull()
    expect(
      textOf(container.querySelector('[data-testid="link-success"]')),
    ).toContain("Sign-in method added.")
    expect(container.querySelector("a")?.getAttribute("href")).toBe(
      "/profile?add=email",
    )
  })

  it("offers the merge where the application merges accounts", () => {
    const { container } = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow({
          add: "email",
          errorCode: "IDENTITY_CONFLICT",
          conflict: { provider: "email" },
        })}
        addMethods={[{ provider: "email" }]}
        allowMerge
        mergeDescription="Its files move into a merged folder."
      />,
    )

    const prompt = container.querySelector('[data-testid="merge-prompt"]')
    expect(textOf(prompt)).toContain("Its files move into a merged folder.")
    expect(prompt?.querySelector("form")?.getAttribute("action")).toBe(
      "/auth/email/link-merge",
    )
  })

  it("replaces the add flow with the confirmation after a merge", () => {
    const { container } = render(
      <SignInMethods
        identities={[identity()]}
        linkFlow={linkFlow({ add: "email", merged: true })}
        addMethods={[{ provider: "email" }]}
      />,
    )

    expect(
      textOf(container.querySelector('[data-testid="merge-success"]')),
    ).toContain("Accounts merged.")
    expect(container.querySelector("form")).toBeNull()
  })

  it("follows the paths the application mounted things at", () => {
    const { container } = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow({ add: "email" })}
        addMethods={[{ provider: "email" }]}
        profilePath="/settings/account"
        authBasePath="/api/auth"
      />,
    )

    expect(container.querySelector("form")?.getAttribute("action")).toBe(
      "/api/auth/email/initiate",
    )
    expect(container.querySelector("a")?.getAttribute("href")).toBe(
      "/settings/account",
    )
  })

  it("navigates through the link component when it gets one", () => {
    function Link({ to, children }: { to: string; children: React.ReactNode }) {
      return <span data-testid="router-link" data-to={to} children={children} />
    }
    const { container } = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow()}
        addMethods={[{ provider: "email" }]}
        linkComponent={Link}
      />,
    )

    expect(container.querySelector("a")).toBeNull()
    expect(
      container
        .querySelector('[data-testid="router-link"]')
        ?.getAttribute("data-to"),
    ).toBe("/profile?add=email")
  })

  it("holds the submit button until the bot check has a token", async () => {
    const options: { callback: () => void }[] = []
    ;(globalThis as { turnstile?: unknown }).turnstile = {
      render: (_container: HTMLElement, rendered: { callback: () => void }) => {
        options.push(rendered)
        return "widget-1"
      },
      remove: vi.fn(),
    }

    const { container } = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow({ add: "email", turnstileSiteKey: "site-key" })}
        addMethods={[{ provider: "email" }]}
      />,
    )
    // The widget renders from an effect, after the script promise resolves
    await act(async () => {
      await Promise.resolve()
    })

    const submit = container.querySelector<HTMLButtonElement>(
      "button[type=submit]",
    )
    expect(submit?.disabled).toBe(true)
    expect(submit?.textContent).toBe("Verifying you're human…")

    act(() => options[0].callback())
    expect(submit?.disabled).toBe(false)
    expect(submit?.textContent).toBe("Send a confirmation email")
  })
})

describe("SignInMethods announcements", () => {
  it("interrupts with a failure and waits with a confirmation", () => {
    const failed = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow({ error: "Too many attempts. Try again later." })}
      />,
    )
    expect(
      failed.container
        .querySelector('[data-testid="link-error"]')
        ?.getAttribute("role"),
    ).toBe("alert")

    const done = render(
      <SignInMethods
        identities={[identity()]}
        linkFlow={linkFlow({ linked: true })}
      />,
    )
    expect(
      done.container
        .querySelector('[data-testid="link-success"]')
        ?.getAttribute("role"),
    ).toBe("status")
  })

  it("announces the merge offer without its buttons", () => {
    const { container } = render(
      <SignInMethods
        identities={[]}
        linkFlow={linkFlow({
          add: "email",
          errorCode: "IDENTITY_CONFLICT",
          conflict: { provider: "email" },
        })}
        addMethods={[{ provider: "email" }]}
        allowMerge
      />,
    )

    const prompt = container.querySelector('[data-testid="merge-prompt"]')
    expect(prompt?.hasAttribute("role")).toBe(false)
    const announced = prompt?.querySelector('[role="alert"]')
    expect(textOf(announced)).toContain("already opens a different account")
    expect(announced?.querySelector("button")).toBeNull()
  })
})

describe("SignInMethods styling", () => {
  it("replaces the built-in look on a slot the application dresses itself", () => {
    const { container } = render(
      <SignInMethods
        identities={[identity()]}
        linkFlow={linkFlow()}
        classNames={{ card: "card mb-4", table: "table" }}
      />,
    )

    const card = container.querySelector("section")
    expect(card?.getAttribute("class")).toBe("card mb-4")
    expect(card?.hasAttribute("style")).toBe(false)
    expect(container.querySelector("table")?.hasAttribute("style")).toBe(false)
    // A slot the application said nothing about keeps the built-in look
    expect(container.querySelector("h2")?.hasAttribute("style")).toBe(true)
  })

  it("renders structural markup only when asked", () => {
    const { container } = render(
      <SignInMethods
        identities={[identity()]}
        linkFlow={linkFlow()}
        includeDefaultStyles={false}
      />,
    )

    expect(container.querySelectorAll("[style]")).toHaveLength(0)
  })
})

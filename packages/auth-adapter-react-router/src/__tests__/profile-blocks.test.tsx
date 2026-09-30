// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest"
import { act } from "react"
import type { LinkFlow } from "../page-loaders.js"
import { AccountSummary } from "../profile/account-summary.js"
import { Passkeys } from "../profile/passkeys.js"
import { ProfilePage } from "../profile/profile-page.js"
import { SignInMethods } from "../profile/sign-in-methods.js"
import type { ProfilePasskey } from "../profile/passkeys.js"
import { BOOTSTRAP_PROFILE_CLASS_NAMES } from "../profile/bootstrap-classes.js"
import { PROFILE_STYLES } from "../profile/profile-styles.js"
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

function passkey(overrides: Partial<ProfilePasskey> = {}): ProfilePasskey {
  return {
    credentialId: "Y3JlZGVudGlhbA",
    nickname: null,
    synced: true,
    createdAt: "2026-02-01T08:00:00.000Z",
    lastUsedAt: null,
    ...overrides,
  }
}

function textOf(element: Element | null): string {
  return element?.textContent?.replace(/\s+/g, " ").trim() ?? ""
}

function rowsOf(container: HTMLElement): string[] {
  return [...container.querySelectorAll("dt")].map(
    (term) => `${term.textContent}: ${term.nextElementSibling?.textContent}`,
  )
}

describe("AccountSummary", () => {
  it("shows the email and the join date as a UTC calendar date", () => {
    const { container } = render(
      <AccountSummary
        email="user@example.com"
        memberSince="2026-01-15T23:30:00.000Z"
      />,
    )

    expect(rowsOf(container)).toEqual([
      "Email: user@example.com",
      "Member since: 2026-01-15",
    ])
  })

  it("appends the application's own rows", () => {
    const { container } = render(
      <AccountSummary
        email="user@example.com"
        entries={[{ label: "Handle", value: "tester" }]}
      />,
    )

    expect(rowsOf(container)).toEqual([
      "Email: user@example.com",
      "Handle: tester",
    ])
  })

  it("leaves the whole list to the application when that is all it gets", () => {
    const { container } = render(
      <AccountSummary
        entries={[
          { label: "Handle", value: "tester" },
          { label: "Status", value: "APPROVED" },
        ]}
      />,
    )

    expect(rowsOf(container)).toEqual(["Handle: tester", "Status: APPROVED"])
  })

  it("renders structural markup only when asked", () => {
    const { container } = render(
      <AccountSummary
        email="user@example.com"
        memberSince="2026-01-15T10:00:00.000Z"
        includeDefaultStyles={false}
      />,
    )

    expect(container.querySelectorAll("[style]")).toHaveLength(0)
  })

  it("puts each term and value straight into the list", () => {
    const { container } = render(
      <AccountSummary
        email="user@example.com"
        classNames={{ definitionList: "row mb-0", definitionTerm: "col-sm-4" }}
      />,
    )

    // Bootstrap's dl.row puts its columns on the terms and values themselves,
    // so nothing may come between them and the list
    const list = container.querySelector("dl")
    expect(list?.getAttribute("class")).toBe("row mb-0")
    expect([...(list?.children ?? [])].map((child) => child.tagName)).toEqual([
      "DT",
      "DD",
    ])
    expect(list?.querySelector("dt")?.getAttribute("class")).toBe("col-sm-4")
  })
})

describe("Passkeys", () => {
  const client = { registerPasskey: vi.fn() }

  it("abbreviates a passkey that was never named", () => {
    const { container } = render(
      <Passkeys passkeys={[passkey()]} client={client} />,
    )

    const item = container.querySelector('[data-testid="passkey-item"]')
    expect(textOf(item?.querySelector("span") ?? null)).toBe(
      "Passkey Y3JlZGVu…",
    )
    expect(textOf(item?.querySelector("small") ?? null)).toBe(
      "synced · added 2026-02-01",
    )
  })

  it("names the ones the user named, and says when they were last used", () => {
    const { container } = render(
      <Passkeys
        passkeys={[
          passkey({
            nickname: "MacBook",
            synced: false,
            lastUsedAt: "2026-03-04T15:30:00.000Z",
          }),
        ]}
        client={client}
      />,
    )

    const item = container.querySelector('[data-testid="passkey-item"]')
    expect(textOf(item?.querySelector("span") ?? null)).toBe("MacBook")
    expect(textOf(item?.querySelector("small") ?? null)).toBe(
      "device-bound · added 2026-02-01 · last used 2026-03-04",
    )
  })

  it("offers the first passkey differently from the next one", () => {
    const empty = render(<Passkeys passkeys={[]} client={client} />)
    expect(empty.container.querySelector("button")?.textContent).toBe(
      "Add a passkey",
    )

    const one = render(<Passkeys passkeys={[passkey()]} client={client} />)
    expect(one.container.querySelector("button")?.textContent).toBe(
      "Add another passkey",
    )
  })

  it("reloads the page's data once a passkey is saved", async () => {
    const onRegistered = vi.fn()
    const { container } = render(
      <Passkeys
        passkeys={[]}
        client={{ registerPasskey: vi.fn().mockResolvedValue(undefined) }}
        onRegistered={onRegistered}
      />,
    )

    await act(() => container.querySelector("button")?.click())

    expect(onRegistered).toHaveBeenCalled()
    const added = container.querySelector('[data-testid="passkey-added"]')
    expect(textOf(added)).toBe("Passkey added.")
    // Nothing else tells a screen reader the ceremony finished
    expect(added?.getAttribute("role")).toBe("status")
  })

  it("reports a registration that failed", async () => {
    const { container } = render(
      <Passkeys
        passkeys={[]}
        client={{
          registerPasskey: vi.fn().mockRejectedValue(new Error("Cancelled")),
        }}
      />,
    )

    await act(() => container.querySelector("button")?.click())

    const failure = container.querySelector('[data-testid="passkey-error"]')
    expect(textOf(failure)).toBe("Error: Cancelled")
    expect(failure?.getAttribute("role")).toBe("alert")
  })
})

describe("composing the blocks", () => {
  const client = { registerPasskey: vi.fn() }

  it("lets an application order the blocks and put its own between them", () => {
    const { container } = render(
      <div>
        <AccountSummary
          entries={[
            { label: "Email", value: "user@example.com" },
            { label: "Handle", value: "tester" },
          ]}
        />
        <section data-testid="handle-section">Handle</section>
        <Passkeys passkeys={[]} client={client} />
        <section data-testid="shared-by-me">Shared by me</section>
        <SignInMethods identities={[]} linkFlow={LINK_FLOW} />
      </div>,
    )

    expect(
      [...container.querySelectorAll("section")].map((section) =>
        section.getAttribute("data-testid"),
      ),
    ).toEqual([
      "account-summary",
      "handle-section",
      "passkeys",
      "shared-by-me",
      "sign-in-methods",
    ])
  })
})

describe("ProfilePage", () => {
  const client = { registerPasskey: vi.fn() }

  it("renders the three blocks in order", () => {
    const { container } = render(
      <ProfilePage
        email="user@example.com"
        memberSince="2026-01-15T10:00:00.000Z"
        identities={[]}
        linkFlow={LINK_FLOW}
        passkeys={[passkey()]}
        passkeyClient={client}
      />,
    )

    expect(container.querySelector("h1")?.textContent).toBe("Profile")
    expect(
      [...container.querySelectorAll("section")].map((section) =>
        section.getAttribute("data-testid"),
      ),
    ).toEqual(["account-summary", "sign-in-methods", "passkeys"])
  })

  it("drops the passkey block where the application has no passkey client", () => {
    const { container } = render(
      <ProfilePage identities={[]} linkFlow={LINK_FLOW} />,
    )

    expect(container.querySelector('[data-testid="passkeys"]')).toBeNull()
  })

  it("puts the application's own footer after the blocks", () => {
    const { container } = render(
      <ProfilePage identities={[]} linkFlow={LINK_FLOW}>
        <a href="/logout">Sign out</a>
      </ProfilePage>,
    )

    expect(container.lastElementChild?.lastElementChild?.textContent).toBe(
      "Sign out",
    )
  })

  it("passes its styling down to every block", () => {
    const { container } = render(
      <ProfilePage
        identities={[]}
        linkFlow={LINK_FLOW}
        passkeys={[]}
        passkeyClient={client}
        classNames={{ card: "card mb-4" }}
      />,
    )

    const cards = [...container.querySelectorAll("section")]
    expect(cards).toHaveLength(3)
    for (const card of cards) {
      expect(card.getAttribute("class")).toBe("card mb-4")
      expect(card.hasAttribute("style")).toBe(false)
    }
  })
})

describe("BOOTSTRAP_PROFILE_CLASS_NAMES", () => {
  const client = { registerPasskey: vi.fn() }

  it("names every slot the built-in look styles", () => {
    expect(Object.keys(BOOTSTRAP_PROFILE_CLASS_NAMES).sort()).toEqual(
      Object.keys(PROFILE_STYLES).sort(),
    )
  })

  it("leaves no inline style behind to outrank Bootstrap's rules", () => {
    const { container } = render(
      <ProfilePage
        email="user@example.com"
        memberSince="2026-01-15T10:00:00.000Z"
        identities={[
          {
            id: "identity-1",
            provider: "email",
            identifier: "user@example.com",
            createdAt: "2026-01-15T10:00:00.000Z",
            verifiedAt: "2026-01-15T10:00:00.000Z",
          },
        ]}
        linkFlow={{ ...LINK_FLOW, add: "sms", sent: true }}
        addMethods={[{ provider: "sms", callingCode: "+1" }]}
        passkeys={[passkey()]}
        passkeyClient={client}
        classNames={BOOTSTRAP_PROFILE_CLASS_NAMES}
      />,
    )

    expect(container.querySelectorAll("[style]")).toHaveLength(0)
    // An empty entry means the application owns the slot and wants no class
    expect(container.querySelector("td")?.hasAttribute("class")).toBe(false)
    expect(container.querySelector("table")?.getAttribute("class")).toBe(
      "table",
    )
  })
})

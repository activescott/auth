import { describe, it, expect } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import type { AdminUserRow } from "@activescott/auth/admin"
import type {
  AdminConfigLoaderData,
  AdminUsersLoaderData,
} from "../admin/admin-handlers.js"
import { AdminUsersPage } from "../admin/admin-users-page.js"
import { AdminConfigPage } from "../admin/admin-config-page.js"
import { elideIdentifier, humanizeKey } from "../admin/format.js"

function createUser(overrides: Partial<AdminUserRow> = {}): AdminUserRow {
  return {
    id: "user-1",
    metadata: {},
    identities: [
      {
        id: "identity-1",
        provider: "email",
        identifier: "alice@example.com",
        createdAt: "2024-01-01T00:00:00.000Z",
        verifiedAt: "2024-03-04T15:30:00.000Z",
      },
    ],
    createdAt: "2024-01-01T00:00:00.000Z",
    lastLoginAt: "2024-03-04T15:30:00.000Z",
    ...overrides,
  }
}

function createUsersData(
  overrides: Partial<AdminUsersLoaderData> = {},
): AdminUsersLoaderData {
  return {
    users: [createUser()],
    pagination: { page: 1, limit: 20, total: 1 },
    sort: { sortOrder: "desc" },
    basePath: "/admin",
    ...overrides,
  }
}

function render(element: React.ReactElement): string {
  return renderToStaticMarkup(element)
}

describe("AdminUsersPage", () => {
  it("shows each identity with its provider and last use", () => {
    const html = render(<AdminUsersPage data={createUsersData()} />)

    expect(html).toContain("alice@example.com")
    expect(html).toContain("email")
    expect(html).toContain("last used 2024-03-04 15:30 UTC")
  })

  it("formats timestamps in UTC so server and client markup agree", () => {
    const html = render(<AdminUsersPage data={createUsersData()} />)

    // A locale-dependent format would differ between the SSR pass and
    // hydration; assert the fixed one instead.
    expect(html).toContain("2024-01-01 00:00 UTC")
  })

  it("renders application metadata as columns", () => {
    const data = createUsersData({
      users: [
        createUser({
          metadata: { handle: "alice", noteCount: 12, defaultPublic: true },
        }),
      ],
    })

    const html = render(
      <AdminUsersPage
        data={data}
        metadataColumns={[
          { key: "handle", sortable: true },
          { key: "noteCount", label: "Notes", align: "end", render: "badge" },
          { key: "defaultPublic", render: "boolean" },
        ]}
      />,
    )

    expect(html).toContain("alice")
    expect(html).toContain(">Notes")
    expect(html).toContain("12")
    // humanized from the key
    expect(html).toContain("Default Public")
  })

  it("links a sortable heading and flips the direction on the active column", () => {
    const html = render(
      <AdminUsersPage
        data={createUsersData({
          sort: { sortBy: "handle", sortOrder: "desc" },
        })}
        metadataColumns={[{ key: "handle", sortable: true }]}
      />,
    )

    expect(html).toContain("sortBy=handle&amp;sortOrder=asc")
    expect(html).toContain("▼")
    expect(html).toContain('aria-sort="descending"')
  })

  it("does not link an unsortable heading", () => {
    const html = render(
      <AdminUsersPage
        data={createUsersData()}
        metadataColumns={[{ key: "handle" }]}
      />,
    )

    expect(html).not.toContain("sortBy=handle")
  })

  it("elides an identifier too long to read, keeping the full value in the title", () => {
    const credentialId = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    const data = createUsersData({
      users: [
        createUser({
          identities: [
            {
              id: "identity-1",
              provider: "passkey",
              identifier: credentialId,
              createdAt: "2024-01-01T00:00:00.000Z",
            },
          ],
        }),
      ],
    })

    const html = render(<AdminUsersPage data={data} />)

    expect(html).toContain(`title="${credentialId}"`)
    expect(html).toContain("AbCdEfGhIj…456789")
  })

  it("omits built-in columns that the application turns off", () => {
    const html = render(
      <AdminUsersPage
        data={createUsersData()}
        showColumns={{ createdAt: false, id: false }}
      />,
    )

    expect(html).not.toContain(">Created")
    expect(html).not.toContain("User ID")
    expect(html).toContain("Last login")
  })

  it("shows an empty state instead of a bare table", () => {
    const html = render(
      <AdminUsersPage
        data={createUsersData({
          users: [],
          pagination: { page: 1, limit: 20, total: 0 },
        })}
      />,
    )

    expect(html).toContain("No users found.")
    expect(html).not.toContain("<table")
  })

  it("hides pagination when everything fits on one page", () => {
    const html = render(<AdminUsersPage data={createUsersData()} />)

    expect(html).not.toContain("Next")
  })

  it("paginates while preserving the active sort", () => {
    const html = render(
      <AdminUsersPage
        data={createUsersData({
          pagination: { page: 2, limit: 20, total: 100 },
          sort: { sortBy: "handle", sortOrder: "asc" },
        })}
      />,
    )

    expect(html).toContain("Page 2 of 5")
    expect(html).toContain("page=1")
    expect(html).toContain("page=3")
    expect(html).toContain("sortBy=handle")
  })

  it("styles inline, with no stylesheet for the application to import", () => {
    const html = render(<AdminUsersPage data={createUsersData()} />)

    expect(html).not.toContain("<style")
    expect(html).toContain("style=")
    // Follows the reader's theme without a media query, which inline styles
    // cannot express
    expect(html).toContain("color-scheme:light dark")
    expect(html).toContain("CanvasText")
  })

  it("drops the built-in look entirely on request", () => {
    const html = render(
      <AdminUsersPage data={createUsersData()} includeDefaultStyles={false} />,
    )

    expect(html).not.toContain("CanvasText")
    expect(html).not.toContain("border-collapse")
  })

  it("yields a slot to the application's class instead of competing with it", () => {
    const html = render(
      <AdminUsersPage
        data={createUsersData()}
        classNames={{ table: "table table-striped" }}
      />,
    )

    expect(html).toContain('class="table table-striped"')
    // An inline style outranks any class, so the overridden slot gets none
    expect(html).not.toContain("border-collapse")
    // Slots the application did not name keep the built-in look
    expect(html).toContain("CanvasText")
  })

  it("stripes alternate rows without a nth-child rule", () => {
    const html = render(
      <AdminUsersPage
        data={createUsersData({
          users: [
            createUser({ id: "user-1" }),
            createUser({ id: "user-2" }),
            createUser({ id: "user-3" }),
          ],
          pagination: { page: 1, limit: 20, total: 3 },
        })}
      />,
    )

    // Rows 2 of 3 striped: the second only
    expect(html.split("color-mix").length - 1).toBe(1)
  })

  it("routes links through a supplied link component", () => {
    function FakeLink({
      to,
      className,
      children,
    }: {
      to: string
      className?: string
      children: React.ReactNode
    }) {
      return (
        <a href={to} className={className} data-router-link="">
          {children}
        </a>
      )
    }

    const html = render(
      <AdminUsersPage data={createUsersData()} linkComponent={FakeLink} />,
    )

    expect(html).toContain("data-router-link")
  })
})

function createConfigData(): AdminConfigLoaderData {
  return {
    basePath: "/admin",
    config: {
      session: {
        cookieName: "session",
        maxAge: "30d",
        cookie: { secure: true, sameSite: "lax", path: "/" },
        secret: "<redacted>",
        additionalSecretCount: 1,
        issuer: "test",
      },
      providers: [
        {
          id: "email",
          name: "Email",
          initiateSentMessage: "Magic link sent.",
          routes: [
            { method: "POST", path: "/email/initiate", handler: "initiate" },
          ],
          settings: { from: "no@example.com", "smtp.host": "smtp.example.com" },
        },
      ],
      abuse: {
        enabled: true,
        perIp: [
          { windowSeconds: 60, max: 3 },
          { windowSeconds: 3600, max: 10 },
        ],
        perIdentifier: [{ windowSeconds: 86_400, max: 10 }],
        minFormFillSeconds: 2,
        botChecks: ["form-token"],
        respondWith: "generic",
        store: "in-memory",
      },
      stores: {
        userStore: "(object literal)",
        identityStore: "(object literal)",
        challengeStore: "InMemoryChallengeStore",
        capabilities: {
          listUsers: true,
          findByUserIds: false,
          deleteIdentity: false,
        },
      },
    },
  }
}

describe("AdminConfigPage", () => {
  it("shows the session settings with the secret redacted", () => {
    const html = render(<AdminConfigPage data={createConfigData()} />)

    expect(html).toContain("Cookie name")
    expect(html).toContain("&lt;redacted&gt;")
  })

  it("shows each provider's self-described settings and routes", () => {
    const html = render(<AdminConfigPage data={createConfigData()} />)

    expect(html).toContain("Provider: Email (email)")
    expect(html).toContain("no@example.com")
    expect(html).toContain("smtp.example.com")
    expect(html).toContain("POST /email/initiate")
  })

  it("states rate limits in words rather than window seconds", () => {
    const html = render(<AdminConfigPage data={createConfigData()} />)

    expect(html).toContain("3 per minute, 10 per hour")
    expect(html).toContain("10 per day")
  })

  it("reports which optional store capabilities are missing", () => {
    const html = render(<AdminConfigPage data={createConfigData()} />)

    expect(html).toContain("InMemoryChallengeStore")
    expect(html).toContain("Can batch identity lookups")
    expect(html).toContain("No")
  })
})

describe("formatting", () => {
  it("keeps email addresses and phone numbers whole however long", () => {
    expect(elideIdentifier("a-very-long-address-indeed@example.com")).toBe(
      "a-very-long-address-indeed@example.com",
    )
    expect(elideIdentifier("+441234567890123")).toBe("+441234567890123")
  })

  it("elides an opaque identifier past the readable length", () => {
    expect(elideIdentifier("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")).toBe(
      "AbCdEfGhIj…456789",
    )
    expect(elideIdentifier("short-id")).toBe("short-id")
  })

  it("uppercases acronyms in headings instead of title-casing them", () => {
    expect(humanizeKey("otp.maxAttempts")).toBe("OTP Max Attempts")
    expect(humanizeKey("smtp.host")).toBe("SMTP Host")
    expect(humanizeKey("rpName")).toBe("RP Name")
    expect(humanizeKey("maxNoteCount")).toBe("Max Note Count")
    // whole-word match only, so this is not "IDentifier"
    expect(humanizeKey("identifier")).toBe("Identifier")
  })
})

describe("AdminUsersPage accessibility", () => {
  it("hides the sort glyph from assistive tech so it stays out of the header name", () => {
    const html = render(
      <AdminUsersPage
        data={createUsersData({ sort: { sortBy: "handle", sortOrder: "asc" } })}
        metadataColumns={[{ key: "handle", sortable: true }]}
      />,
    )

    expect(html).toContain('aria-hidden="true"')
    expect(html).toContain('aria-sort="ascending"')
    expect(html).toContain("▲")
  })
})

describe("navExtra", () => {
  it("renders application-supplied nav content alongside the built-in links", () => {
    const html = render(
      <AdminUsersPage
        data={createUsersData()}
        navExtra={<a href="/admin">Back to Dashboard</a>}
      />,
    )

    expect(html).toContain("Back to Dashboard")
  })
})

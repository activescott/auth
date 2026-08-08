import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import type { Auth, AuthUser, Identity } from "@activescott/auth"
import { createAdminHandlers } from "../admin/admin-handlers.js"
import { ADMIN_IDENTIFIERS_ENV } from "../admin/require-admin.js"

const TEST_BASE_URL = "https://example.com"
const ADMIN_EMAIL = "admin@example.com"
const OTHER_EMAIL = "nobody@example.com"

function createIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: "identity-1",
    userId: "user-1",
    provider: "email",
    identifier: ADMIN_EMAIL,
    metadata: {},
    createdAt: new Date("2024-01-01T00:00:00.000Z"),
    ...overrides,
  }
}

/**
 * A minimal Auth stand-in: the handlers only reach for verifySession, the
 * stores, and describeConfig.
 */
function createMockAuth(
  options: {
    user?: AuthUser | null
    identities?: Identity[]
    listUsers?: unknown
  } = {},
): Auth {
  const user = options.user === undefined ? { id: "user-1" } : options.user
  const identities = options.identities ?? [createIdentity()]

  const auth = {
    verifySession: vi
      .fn()
      .mockResolvedValue(
        user ? { user, identity: identities[0] ?? createIdentity() } : null,
      ),
    getStores: vi.fn().mockReturnValue({
      identityStore: {
        findByUserId: vi.fn().mockResolvedValue(identities),
        findByUserIds: vi.fn().mockResolvedValue(identities),
      },
      userStore: {
        listUsers:
          options.listUsers ??
          vi.fn().mockResolvedValue({ users: [{ id: "user-1" }], total: 1 }),
      },
      challengeStore: {},
    }),
    describeConfig: vi.fn().mockReturnValue({
      session: {},
      providers: [],
      abuse: {},
      stores: {},
    }),
  }
  return auth as unknown as Auth
}

/** requireAuth that succeeds, as the app's own would for a signed-in user */
const signedIn = vi.fn().mockResolvedValue({ id: "user-1" })

/** requireAuth that redirects, as the real one does when signed out */
const signedOut = vi.fn().mockImplementation(() => {
  throw new Response(null, { status: 302, headers: { Location: "/login" } })
})

function usersRequest(query = ""): Request {
  return new Request(`${TEST_BASE_URL}/admin/users${query}`)
}

const originalEnv = process.env[ADMIN_IDENTIFIERS_ENV]

beforeEach(() => {
  delete process.env[ADMIN_IDENTIFIERS_ENV]
  signedIn.mockClear()
})

afterEach(() => {
  if (originalEnv === undefined) {
    delete process.env[ADMIN_IDENTIFIERS_ENV]
  } else {
    process.env[ADMIN_IDENTIFIERS_ENV] = originalEnv
  }
})

describe("requireAdmin", () => {
  it("admits a user whose identity is on the allowlist", async () => {
    const { requireAdmin } = createAdminHandlers(createMockAuth(), {
      requireAuth: signedIn,
      admins: ADMIN_EMAIL,
    })

    await expect(requireAdmin(usersRequest())).resolves.toEqual({
      id: "user-1",
    })
  })

  it("matches an allowlisted identity the user did not sign in with", async () => {
    const auth = createMockAuth({
      identities: [
        createIdentity({ provider: "sms", identifier: "+15555550100" }),
        createIdentity({ id: "identity-2", identifier: ADMIN_EMAIL }),
      ],
    })
    const { requireAdmin } = createAdminHandlers(auth, {
      requireAuth: signedIn,
      admins: ADMIN_EMAIL,
    })

    await expect(requireAdmin(usersRequest())).resolves.toBeDefined()
  })

  it("answers a signed-in non-admin with 404 so the area stays hidden", async () => {
    const auth = createMockAuth({
      identities: [createIdentity({ identifier: OTHER_EMAIL })],
    })
    const { requireAdmin } = createAdminHandlers(auth, {
      requireAuth: signedIn,
      admins: ADMIN_EMAIL,
    })

    const thrown = await requireAdmin(usersRequest()).catch(
      (error: unknown) => error,
    )
    expect(thrown).toBeInstanceOf(Response)
    expect((thrown as Response).status).toBe(404)
  })

  it("can answer 403 instead when the area is not meant to be secret", async () => {
    const auth = createMockAuth({
      identities: [createIdentity({ identifier: OTHER_EMAIL })],
    })
    const { requireAdmin } = createAdminHandlers(auth, {
      requireAuth: signedIn,
      admins: ADMIN_EMAIL,
      onForbidden: "forbidden",
    })

    const thrown = await requireAdmin(usersRequest()).catch(
      (error: unknown) => error,
    )
    expect((thrown as Response).status).toBe(403)
  })

  it("lets requireAuth redirect a signed-out visitor", async () => {
    const { requireAdmin } = createAdminHandlers(createMockAuth(), {
      requireAuth: signedOut,
      admins: ADMIN_EMAIL,
    })

    const thrown = await requireAdmin(usersRequest()).catch(
      (error: unknown) => error,
    )
    expect((thrown as Response).status).toBe(302)
    expect((thrown as Response).headers.get("Location")).toBe("/login")
  })

  it("denies everyone when no allowlist is configured", async () => {
    const { requireAdmin } = createAdminHandlers(createMockAuth(), {
      requireAuth: signedIn,
    })

    const thrown = await requireAdmin(usersRequest()).catch(
      (error: unknown) => error,
    )
    expect((thrown as Response).status).toBe(404)
  })

  it("denies everyone when the allowlist is present but empty", async () => {
    const { requireAdmin } = createAdminHandlers(createMockAuth(), {
      requireAuth: signedIn,
      admins: "  ,  ",
    })

    const thrown = await requireAdmin(usersRequest()).catch(
      (error: unknown) => error,
    )
    expect((thrown as Response).status).toBe(404)
  })

  it("reads the allowlist from the environment when none is passed", async () => {
    process.env[ADMIN_IDENTIFIERS_ENV] = `someone@example.com, ${ADMIN_EMAIL}`
    const { requireAdmin } = createAdminHandlers(createMockAuth(), {
      requireAuth: signedIn,
    })

    await expect(requireAdmin(usersRequest())).resolves.toBeDefined()
  })

  it("compares email addresses case-insensitively", async () => {
    const auth = createMockAuth({
      identities: [createIdentity({ identifier: "Admin@Example.COM" })],
    })
    const { requireAdmin } = createAdminHandlers(auth, {
      requireAuth: signedIn,
      admins: ADMIN_EMAIL,
    })

    await expect(requireAdmin(usersRequest())).resolves.toBeDefined()
  })

  it("accepts an array and a predicate as well as a delimited string", async () => {
    const fromArray = createAdminHandlers(createMockAuth(), {
      requireAuth: signedIn,
      admins: [ADMIN_EMAIL],
    })
    await expect(fromArray.requireAdmin(usersRequest())).resolves.toBeDefined()

    const predicate = vi.fn().mockReturnValue(true)
    const fromPredicate = createAdminHandlers(createMockAuth(), {
      requireAuth: signedIn,
      admins: predicate,
    })
    await expect(
      fromPredicate.requireAdmin(usersRequest()),
    ).resolves.toBeDefined()
    expect(predicate).toHaveBeenCalledWith({ id: "user-1" }, [
      expect.objectContaining({ identifier: ADMIN_EMAIL }),
    ])
  })
})

describe("adminUsersLoader", () => {
  function createLoader(overrides: Record<string, unknown> = {}) {
    const listUsers = vi
      .fn()
      .mockResolvedValue({ users: [{ id: "user-1" }], total: 42 })
    const handlers = createAdminHandlers(createMockAuth({ listUsers }), {
      requireAuth: signedIn,
      admins: ADMIN_EMAIL,
      ...overrides,
    })
    return { ...handlers, listUsers }
  }

  it("gates on requireAdmin before touching the store", async () => {
    const listUsers = vi.fn()
    const auth = createMockAuth({
      listUsers,
      identities: [createIdentity({ identifier: OTHER_EMAIL })],
    })
    const { adminUsersLoader } = createAdminHandlers(auth, {
      requireAuth: signedIn,
      admins: ADMIN_EMAIL,
    })

    await adminUsersLoader({ request: usersRequest() }).catch(() => undefined)

    expect(listUsers).not.toHaveBeenCalled()
  })

  it("defaults to page 1 at the configured page size", async () => {
    const { adminUsersLoader, listUsers } = createLoader({ pageSize: 25 })

    const data = await adminUsersLoader({ request: usersRequest() })

    expect(listUsers).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 25, offset: 0 }),
    )
    expect(data.pagination).toEqual({ page: 1, limit: 25, total: 42 })
  })

  it("turns the page number into an offset", async () => {
    const { adminUsersLoader, listUsers } = createLoader()

    await adminUsersLoader({ request: usersRequest("?page=3&limit=10") })

    expect(listUsers).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 10, offset: 20 }),
    )
  })

  it("caps the requested page size", async () => {
    const { adminUsersLoader, listUsers } = createLoader()

    await adminUsersLoader({ request: usersRequest("?limit=100000") })

    expect(listUsers).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 100 }),
    )
  })

  it("falls back to page 1 for nonsense page numbers", async () => {
    const { adminUsersLoader, listUsers } = createLoader()

    await adminUsersLoader({ request: usersRequest("?page=-4") })

    expect(listUsers).toHaveBeenCalledWith(
      expect.objectContaining({ offset: 0 }),
    )
  })

  it("passes the sort through to the store verbatim", async () => {
    const { adminUsersLoader, listUsers } = createLoader()

    const data = await adminUsersLoader({
      request: usersRequest("?sortBy=noteCount&sortOrder=asc"),
    })

    expect(listUsers).toHaveBeenCalledWith(
      expect.objectContaining({ sortBy: "noteCount", sortOrder: "asc" }),
    )
    expect(data.sort).toEqual({ sortBy: "noteCount", sortOrder: "asc" })
  })

  it("applies the configured default sort when the request has none", async () => {
    const { adminUsersLoader, listUsers } = createLoader({
      defaultSort: { sortBy: "noteCount", sortOrder: "desc" },
    })

    await adminUsersLoader({ request: usersRequest() })

    expect(listUsers).toHaveBeenCalledWith(
      expect.objectContaining({ sortBy: "noteCount", sortOrder: "desc" }),
    )
  })

  it("ignores an unrecognized sort order rather than forwarding it", async () => {
    const { adminUsersLoader, listUsers } = createLoader()

    await adminUsersLoader({ request: usersRequest("?sortOrder=sideways") })

    expect(listUsers).toHaveBeenCalledWith(
      expect.objectContaining({ sortOrder: "desc" }),
    )
  })

  it("reports the base path so links can be built", async () => {
    const { adminUsersLoader } = createLoader({ basePath: "/dashboard/admin" })

    const data = await adminUsersLoader({ request: usersRequest() })

    expect(data.basePath).toBe("/dashboard/admin")
  })
})

describe("adminConfigLoader", () => {
  it("gates on requireAdmin", async () => {
    const auth = createMockAuth({
      identities: [createIdentity({ identifier: OTHER_EMAIL })],
    })
    const { adminConfigLoader } = createAdminHandlers(auth, {
      requireAuth: signedIn,
      admins: ADMIN_EMAIL,
    })

    const thrown = await adminConfigLoader({ request: usersRequest() }).catch(
      (error: unknown) => error,
    )
    expect((thrown as Response).status).toBe(404)
  })

  it("returns the redacted config description", async () => {
    const auth = createMockAuth()
    const { adminConfigLoader } = createAdminHandlers(auth, {
      requireAuth: signedIn,
      admins: ADMIN_EMAIL,
    })

    const data = await adminConfigLoader({ request: usersRequest() })

    expect(auth.describeConfig).toHaveBeenCalled()
    expect(data.config).toBeDefined()
  })
})

describe("adminUsersLoader filtering", () => {
  function createLoader(overrides: Record<string, unknown> = {}) {
    const listUsers = vi.fn().mockResolvedValue({ users: [], total: 0 })
    const handlers = createAdminHandlers(createMockAuth({ listUsers }), {
      requireAuth: signedIn,
      admins: ADMIN_EMAIL,
      ...overrides,
    })
    return { ...handlers, listUsers }
  }

  it("passes filter.* params to the store verbatim", async () => {
    const { adminUsersLoader, listUsers } = createLoader()

    const data = await adminUsersLoader({
      request: usersRequest("?filter.approvalStatus=PENDING&filter.plan=pro"),
    })

    expect(listUsers).toHaveBeenCalledWith(
      expect.objectContaining({
        filter: { approvalStatus: "PENDING", plan: "pro" },
      }),
    )
    expect(data.filter).toEqual({ approvalStatus: "PENDING", plan: "pro" })
  })

  it("omits filter entirely when the request has none", async () => {
    const { adminUsersLoader, listUsers } = createLoader()

    const data = await adminUsersLoader({ request: usersRequest() })

    expect(listUsers.mock.calls[0]?.[0]).not.toHaveProperty("filter")
    expect(data.filter).toEqual({})
  })

  it("does not mistake paging params for filter criteria", async () => {
    const { adminUsersLoader, listUsers } = createLoader()

    await adminUsersLoader({
      request: usersRequest("?page=2&limit=5&sortBy=email&filter.tier=gold"),
    })

    expect(listUsers).toHaveBeenCalledWith(
      expect.objectContaining({ filter: { tier: "gold" } }),
    )
  })

  it("ignores a bare `filter.` with no key", async () => {
    const { adminUsersLoader } = createLoader()

    const data = await adminUsersLoader({ request: usersRequest("?filter.=x") })

    expect(data.filter).toEqual({})
  })

  it("reports the query string so links can preserve it", async () => {
    const { adminUsersLoader } = createLoader()

    const data = await adminUsersLoader({
      request: usersRequest("?tab=pending&filter.approvalStatus=PENDING"),
    })

    expect(data.searchParams).toContain("tab=pending")
    expect(data.searchParams).toContain("filter.approvalStatus=PENDING")
  })
})

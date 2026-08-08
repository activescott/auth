import { describe, it, expect, vi, afterEach } from "vitest"
import { Auth } from "../auth.js"
import { AdminNotSupportedError, createAdminData } from "../admin/admin-data.js"
import type {
  AuthConfig,
  AuthProvider,
  AuthUser,
  ChallengeStore,
  Identity,
  IdentityStore,
  UserStore,
} from "../types.js"

const TEST_SECRET = "test-session-secret"

function createMockProvider(
  overrides: Partial<AuthProvider> = {},
): AuthProvider {
  return {
    id: "email",
    name: "Email",
    initiateSentMessage: "Magic link sent.",
    initiate: vi.fn(),
    verify: vi.fn(),
    canHandle: vi.fn().mockReturnValue(false),
    getRoutes: vi
      .fn()
      .mockReturnValue([
        { method: "POST", path: "/email/initiate", handler: "initiate" },
      ]),
    describe: vi.fn().mockReturnValue({ settings: { from: "no@example.com" } }),
    ...overrides,
  }
}

function createIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: "identity-1",
    userId: "user-1",
    provider: "email",
    identifier: "alice@example.com",
    metadata: {},
    createdAt: new Date("2024-01-01T00:00:00.000Z"),
    ...overrides,
  }
}

/**
 * Build an Auth over stores whose optional admin methods can be swapped per
 * test, which is the only variable these tests care about.
 */
function createTestAuth(
  options: {
    users?: AuthUser[]
    identities?: Identity[]
    userStore?: Partial<UserStore>
    identityStore?: Partial<IdentityStore>
  } = {},
) {
  const users = options.users ?? []
  const identities = options.identities ?? []

  const userStore: UserStore = {
    findById: vi.fn().mockResolvedValue(null),
    create: vi.fn(),
    listUsers: vi.fn().mockResolvedValue({ users, total: users.length }),
    ...options.userStore,
  }

  const identityStore: IdentityStore = {
    findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
    findByUserId: vi
      .fn()
      .mockImplementation((userId: string) =>
        Promise.resolve(identities.filter((i) => i.userId === userId)),
      ),
    create: vi.fn(),
    update: vi.fn(),
    findByUserIds: vi.fn().mockResolvedValue(identities),
    ...options.identityStore,
  }

  const challengeStore: ChallengeStore = {
    create: vi.fn(),
    findById: vi.fn(),
    incrementAttempts: vi.fn(),
    delete: vi.fn(),
  }

  const config: AuthConfig = {
    session: {
      secret: TEST_SECRET,
      additionalSecrets: ["older-secret"],
      maxAge: "30d",
      cookieName: "session",
      cookie: { secure: true, sameSite: "lax", path: "/" },
      issuer: "test-issuer",
      audience: "test-audience",
    },
    identityStore,
    userStore,
    challengeStore,
    providers: [createMockProvider()],
  }

  const auth = new Auth(config)
  return { auth, userStore, identityStore }
}

const created: Auth[] = []
function trackAuth(auth: Auth): Auth {
  created.push(auth)
  return auth
}

afterEach(() => {
  while (created.length > 0) created.pop()?.destroy()
})

describe("createAdminData.listUsers", () => {
  it("joins each user with its identities", async () => {
    const { auth } = createTestAuth({
      users: [{ id: "user-1", metadata: { handle: "alice" } }],
      identities: [
        createIdentity({
          verifiedAt: new Date("2024-03-01T00:00:00.000Z"),
        }),
        createIdentity({
          id: "identity-2",
          provider: "sms",
          identifier: "+15555550100",
          createdAt: new Date("2024-02-01T00:00:00.000Z"),
        }),
      ],
    })
    trackAuth(auth)

    const page = await createAdminData(auth).listUsers({ limit: 20, offset: 0 })

    expect(page.total).toBe(1)
    expect(page.users[0]?.metadata).toEqual({ handle: "alice" })
    expect(page.users[0]?.identities.map((i) => i.provider)).toEqual([
      "email",
      "sms",
    ])
  })

  it("derives createdAt from the earliest identity and lastLoginAt from the latest verification", async () => {
    const { auth } = createTestAuth({
      users: [{ id: "user-1" }],
      identities: [
        createIdentity({
          createdAt: new Date("2024-05-01T00:00:00.000Z"),
          verifiedAt: new Date("2024-06-01T00:00:00.000Z"),
        }),
        createIdentity({
          id: "identity-2",
          createdAt: new Date("2024-01-01T00:00:00.000Z"),
          verifiedAt: new Date("2024-02-01T00:00:00.000Z"),
        }),
      ],
    })
    trackAuth(auth)

    const page = await createAdminData(auth).listUsers({ limit: 20, offset: 0 })

    expect(page.users[0]?.createdAt).toBe("2024-01-01T00:00:00.000Z")
    expect(page.users[0]?.lastLoginAt).toBe("2024-06-01T00:00:00.000Z")
  })

  it("omits lastLoginAt when no identity has been verified", async () => {
    const { auth } = createTestAuth({
      users: [{ id: "user-1" }],
      identities: [createIdentity()],
    })
    trackAuth(auth)

    const page = await createAdminData(auth).listUsers({ limit: 20, offset: 0 })

    expect(page.users[0]?.lastLoginAt).toBeUndefined()
  })

  it("never exposes identity metadata, only a lastUsedAt derived from it", async () => {
    const { auth } = createTestAuth({
      users: [{ id: "user-1" }],
      identities: [
        createIdentity({
          provider: "passkey",
          metadata: {
            publicKey: "SECRET-CREDENTIAL-PUBLIC-KEY",
            counter: 7,
            lastUsedAt: "2024-04-01T00:00:00.000Z",
          },
        }),
      ],
    })
    trackAuth(auth)

    const page = await createAdminData(auth).listUsers({ limit: 20, offset: 0 })

    expect(page.users[0]?.identities[0]?.lastUsedAt).toBe(
      "2024-04-01T00:00:00.000Z",
    )
    expect(JSON.stringify(page)).not.toContain("SECRET-CREDENTIAL-PUBLIC-KEY")
  })

  it("ignores an unparseable lastUsedAt rather than displaying it", async () => {
    const { auth } = createTestAuth({
      users: [{ id: "user-1" }],
      identities: [createIdentity({ metadata: { lastUsedAt: "not a date" } })],
    })
    trackAuth(auth)

    const page = await createAdminData(auth).listUsers({ limit: 20, offset: 0 })

    expect(page.users[0]?.identities[0]?.lastUsedAt).toBeUndefined()
  })

  it("falls back to findByUserId when the store has no batch method", async () => {
    const findByUserId = vi.fn().mockResolvedValue([createIdentity()])
    const { auth } = createTestAuth({
      users: [{ id: "user-1" }, { id: "user-2" }],
      identityStore: { findByUserId, findByUserIds: undefined },
    })
    trackAuth(auth)

    const page = await createAdminData(auth).listUsers({ limit: 20, offset: 0 })

    expect(findByUserId).toHaveBeenCalledTimes(2)
    expect(page.users).toHaveLength(2)
  })

  it("passes paging and sorting through to the store untouched", async () => {
    const listUsers = vi.fn().mockResolvedValue({ users: [], total: 0 })
    const { auth } = createTestAuth({ userStore: { listUsers } })
    trackAuth(auth)

    await createAdminData(auth).listUsers({
      limit: 50,
      offset: 100,
      sortBy: "noteCount",
      sortOrder: "asc",
    })

    expect(listUsers).toHaveBeenCalledWith({
      limit: 50,
      offset: 100,
      sortBy: "noteCount",
      sortOrder: "asc",
    })
  })

  it("explains the fix when the UserStore cannot enumerate users", async () => {
    const { auth } = createTestAuth({ userStore: { listUsers: undefined } })
    trackAuth(auth)

    await expect(
      createAdminData(auth).listUsers({ limit: 20, offset: 0 }),
    ).rejects.toThrow(AdminNotSupportedError)
    await expect(
      createAdminData(auth).listUsers({ limit: 20, offset: 0 }),
    ).rejects.toThrow(/UserStore\.listUsers/)
  })
})

describe("Auth.describeConfig", () => {
  it("redacts the session secret and counts the additional ones", () => {
    const { auth } = createTestAuth()
    trackAuth(auth)

    const description = auth.describeConfig()

    expect(description.session.secret).toBe("<redacted>")
    expect(description.session.additionalSecretCount).toBe(1)
    const serialized = JSON.stringify(description)
    expect(serialized).not.toContain(TEST_SECRET)
    expect(serialized).not.toContain("older-secret")
  })

  it("reports non-secret session settings", () => {
    const { auth } = createTestAuth()
    trackAuth(auth)

    const { session } = auth.describeConfig()

    expect(session.cookieName).toBe("session")
    expect(session.maxAge).toBe("30d")
    expect(session.issuer).toBe("test-issuer")
    expect(session.audience).toBe("test-audience")
    expect(session.cookie).toEqual({ secure: true, sameSite: "lax", path: "/" })
  })

  it("includes each provider's id, routes, and self-described settings", () => {
    const { auth } = createTestAuth()
    trackAuth(auth)

    const [provider] = auth.describeConfig().providers

    expect(provider?.id).toBe("email")
    expect(provider?.name).toBe("Email")
    expect(provider?.initiateSentMessage).toBe("Magic link sent.")
    expect(provider?.routes).toHaveLength(1)
    expect(provider?.settings).toEqual({ from: "no@example.com" })
  })

  it("resolves abuse defaults that the config leaves unset", () => {
    const { auth } = createTestAuth()
    trackAuth(auth)

    const { abuse } = auth.describeConfig()

    expect(abuse.enabled).toBe(true)
    expect(abuse.perIp).toEqual([
      { windowSeconds: 60, max: 3 },
      { windowSeconds: 3600, max: 10 },
    ])
    expect(abuse.perIdentifier).toEqual([
      { windowSeconds: 3600, max: 3 },
      { windowSeconds: 86_400, max: 10 },
    ])
    expect(abuse.minFormFillSeconds).toBe(2)
    expect(abuse.botChecks).toEqual(["form-token"])
    expect(abuse.respondWith).toBe("generic")
    expect(abuse.store).toBe("in-memory")
  })

  it("reports which optional store capabilities are available", () => {
    const { auth } = createTestAuth()
    trackAuth(auth)

    const { stores } = auth.describeConfig()

    expect(stores.capabilities).toEqual({
      listUsers: true,
      findByUserIds: true,
      deleteIdentity: false,
    })
    expect(stores.userStore).toBe("(object literal)")
  })
})

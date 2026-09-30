import { describe, it, expect, vi, afterEach } from "vitest"
import { Auth } from "../auth.js"
import {
  ADMIN_IDENTIFIERS_ENV,
  createAdminPredicate,
  isAdminUser,
} from "../admin/admin-predicate.js"
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

const ALICE: AuthUser = { id: "user-1" }

function createIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: "identity-1",
    userId: "user-1",
    provider: "email",
    identifier: "alice@example.com",
    providerState: {},
    createdAt: new Date("2024-01-01T00:00:00.000Z"),
    ...overrides,
  }
}

function createMockProvider(): AuthProvider {
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
    describe: vi.fn().mockReturnValue({ settings: {} }),
  }
}

const created: Auth[] = []

/** An Auth whose identity store returns exactly the identities given */
function createTestAuth(identities: Identity[]) {
  const identityStore: IdentityStore = {
    findByProviderAndIdentifier: vi.fn().mockResolvedValue(null),
    findByUserId: vi
      .fn()
      .mockImplementation((userId: string) =>
        Promise.resolve(identities.filter((i) => i.userId === userId)),
      ),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    reassignByUserId: vi.fn(),
  }

  const userStore: UserStore = {
    findById: vi.fn().mockResolvedValue(null),
    create: vi.fn(),
    onMerge: vi.fn(),
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
      maxAge: "30d",
      cookieName: "session",
      cookie: { secure: true, sameSite: "lax", path: "/" },
    },
    identityStore,
    userStore,
    challengeStore,
    providers: [createMockProvider()],
  }

  const auth = new Auth(config)
  created.push(auth)
  return { auth, identityStore }
}

afterEach(() => {
  vi.unstubAllEnvs()
  while (created.length > 0) created.pop()?.destroy()
})

describe("createAdminPredicate", () => {
  it("matches a comma-separated allowlist", async () => {
    const isAdmin = createAdminPredicate("alice@example.com, bob@example.com")
    expect(await isAdmin(ALICE, [createIdentity()])).toBe(true)
  })

  it("matches an allowlist array", async () => {
    const isAdmin = createAdminPredicate(["alice@example.com"])
    expect(await isAdmin(ALICE, [createIdentity()])).toBe(true)
  })

  it("splits on whitespace and newlines too", async () => {
    const isAdmin = createAdminPredicate("bob@example.com\nalice@example.com")
    expect(await isAdmin(ALICE, [createIdentity()])).toBe(true)
  })

  it("ignores case and surrounding whitespace", async () => {
    const isAdmin = createAdminPredicate("  Alice@Example.COM  ")
    const identity = createIdentity({ identifier: "alice@example.com" })
    expect(await isAdmin(ALICE, [identity])).toBe(true)
  })

  it("matches any identity the user owns, not only the first", async () => {
    const isAdmin = createAdminPredicate("+15555550123")
    const identities = [
      createIdentity(),
      createIdentity({
        id: "identity-2",
        provider: "sms",
        identifier: "+15555550123",
      }),
    ]
    expect(await isAdmin(ALICE, identities)).toBe(true)
  })

  it("rejects a user whose identities are all off the list", async () => {
    const isAdmin = createAdminPredicate("bob@example.com")
    expect(await isAdmin(ALICE, [createIdentity()])).toBe(false)
  })

  it("admits nobody when the allowlist is empty", async () => {
    const identities = [createIdentity()]
    expect(await createAdminPredicate("")(ALICE, identities)).toBe(false)
    expect(await createAdminPredicate(" , ")(ALICE, identities)).toBe(false)
    expect(await createAdminPredicate([])(ALICE, identities)).toBe(false)
  })

  it("admits nobody when nothing is configured", async () => {
    vi.stubEnv(ADMIN_IDENTIFIERS_ENV, "")
    const isAdmin = createAdminPredicate(undefined)
    expect(await isAdmin(ALICE, [createIdentity()])).toBe(false)
  })

  it("falls back to the environment allowlist", async () => {
    vi.stubEnv(ADMIN_IDENTIFIERS_ENV, "alice@example.com")
    expect(await createAdminPredicate()(ALICE, [createIdentity()])).toBe(true)
  })

  it("prefers an explicit allowlist over the environment", async () => {
    vi.stubEnv(ADMIN_IDENTIFIERS_ENV, "alice@example.com")
    const isAdmin = createAdminPredicate("bob@example.com")
    expect(await isAdmin(ALICE, [createIdentity()])).toBe(false)
  })

  it("returns a caller's predicate unchanged", () => {
    const custom = () => true
    expect(createAdminPredicate(custom)).toBe(custom)
  })
})

describe("isAdminUser", () => {
  it("admits an admin signed in with an identity other than the allowlisted one", async () => {
    vi.stubEnv(ADMIN_IDENTIFIERS_ENV, "alice@example.com")
    const { auth } = createTestAuth([
      createIdentity({
        id: "identity-2",
        provider: "sms",
        identifier: "+15555550123",
      }),
      createIdentity(),
    ])

    await expect(isAdminUser(auth, ALICE)).resolves.toBe(true)
  })

  it("rejects a user with no allowlisted identity", async () => {
    vi.stubEnv(ADMIN_IDENTIFIERS_ENV, "alice@example.com")
    const { auth } = createTestAuth([
      createIdentity({ userId: "user-2", identifier: "bob@example.com" }),
    ])

    await expect(isAdminUser(auth, { id: "user-2" })).resolves.toBe(false)
  })

  it("admits nobody when the environment allowlist is unset", async () => {
    vi.stubEnv(ADMIN_IDENTIFIERS_ENV, "")
    const { auth } = createTestAuth([createIdentity()])

    await expect(isAdminUser(auth, ALICE)).resolves.toBe(false)
  })

  it("reads the allowlist on every call, not once per process", async () => {
    const { auth } = createTestAuth([createIdentity()])

    vi.stubEnv(ADMIN_IDENTIFIERS_ENV, "")
    await expect(isAdminUser(auth, ALICE)).resolves.toBe(false)

    vi.stubEnv(ADMIN_IDENTIFIERS_ENV, "alice@example.com")
    await expect(isAdminUser(auth, ALICE)).resolves.toBe(true)
  })

  it("loads the user's identities from the identity store", async () => {
    vi.stubEnv(ADMIN_IDENTIFIERS_ENV, "alice@example.com")
    const { auth, identityStore } = createTestAuth([createIdentity()])

    await isAdminUser(auth, ALICE)

    expect(identityStore.findByUserId).toHaveBeenCalledWith("user-1")
  })
})

import { describe, it, expect, vi, afterEach } from "vitest"
import { Auth } from "../auth.js"
import { InMemoryChallengeStore } from "../stores/in-memory-challenge-store.js"
import {
  createWaitlist,
  type ApprovalStatus,
  type ApprovalStore,
  type WaitlistConfig,
} from "../waitlist.js"
import { authenticateWithIdentifier } from "../provider-util.js"
import type {
  AuthContext,
  AuthProvider,
  AuthUser,
  Identity,
  IdentityStore,
  UserStore,
} from "../types.js"
import type { InitiateGateDecision } from "../initiate-gate.js"

/** In-memory stores that behave like a real database, so calls compose */
function createStores() {
  const users = new Map<string, AuthUser>()
  const identities: Identity[] = []
  const statuses = new Map<string, ApprovalStatus>()
  let nextId = 1

  const userStore: UserStore = {
    findById: async (id) => users.get(id) ?? null,
    create: vi.fn(async () => {
      const user = { id: `user-${nextId++}` }
      users.set(user.id, user)
      return user
    }),
    onMerge: vi.fn(),
  }
  const identityStore: IdentityStore = {
    findByProviderAndIdentifier: async (provider, identifier) =>
      identities.find(
        (identity) =>
          identity.provider === provider && identity.identifier === identifier,
      ) ?? null,
    findByUserId: async (userId) =>
      identities.filter((identity) => identity.userId === userId),
    create: vi.fn(async (data) => {
      const identity = {
        ...data,
        id: `identity-${nextId++}`,
        createdAt: new Date(),
      }
      identities.push(identity)
      return identity
    }),
    update: async (id, data) => {
      const identity = identities.find((candidate) => candidate.id === id)
      if (!identity) throw new Error(`no identity ${id}`)
      Object.assign(identity, data)
      return identity
    },
    delete: vi.fn(),
    reassignByUserId: vi.fn(),
  }
  const approvalStore: ApprovalStore = {
    getApprovalStatus: async (userId) => statuses.get(userId) ?? null,
    setApprovalStatus: vi.fn(async (userId, status) => {
      statuses.set(userId, status)
    }),
  }

  /** Seed an existing user with an email identity and a status */
  async function seed(
    identifier: string,
    status: ApprovalStatus | null,
  ): Promise<string> {
    const user = await userStore.create({ provider: "email", identifier })
    await identityStore.create({
      userId: user.id,
      provider: "email",
      identifier,
      providerState: {},
    })
    if (status) statuses.set(user.id, status)
    vi.mocked(userStore.create).mockClear()
    vi.mocked(identityStore.create).mockClear()
    return user.id
  }

  return { userStore, identityStore, approvalStore, statuses, seed }
}

function setup(overrides: Partial<WaitlistConfig> = {}) {
  const stores = createStores()
  const waitlist = createWaitlist({
    identityStore: stores.identityStore,
    approvalStore: stores.approvalStore,
    waitlistUrl: "/waitlist",
    ...overrides,
  })

  /** Sign in with a verified email the way the providers do, then ask the waitlist */
  async function verify(
    identifier: string,
    mode: "signin" | "link" = "signin",
  ): Promise<InitiateGateDecision> {
    const result = await authenticateWithIdentifier("email", identifier, {
      identityStore: stores.identityStore,
      userStore: stores.userStore,
    } as AuthContext)
    if (!result.success) throw new Error(result.error.message)
    return waitlist.onVerified({
      provider: "email",
      identifier,
      mode,
      request: new Request("https://example.com/auth/email/verify", {
        method: "POST",
      }),
      user: result.user,
      identity: result.identity,
      isNewUser: result.isNewUser ?? false,
    })
  }

  return { ...stores, waitlist, verify }
}

describe("createWaitlist onInitiate", () => {
  it("allows every initiate without creating a user or telling anyone", async () => {
    const notify = vi.fn()
    const { waitlist, userStore, identityStore, approvalStore, seed } = setup({
      notify,
    })
    await seed("mallory@example.com", "BLOCKED")

    for (const identifier of ["new@example.com", "mallory@example.com"]) {
      expect(
        await waitlist.onInitiate({
          provider: "email",
          identifier,
          mode: "signin",
          request: new Request("https://example.com/auth/email/initiate", {
            method: "POST",
          }),
        }),
      ).toBe("allow")
    }
    expect(userStore.create).not.toHaveBeenCalled()
    expect(identityStore.create).not.toHaveBeenCalled()
    expect(approvalStore.setApprovalStatus).not.toHaveBeenCalled()
    expect(notify).not.toHaveBeenCalled()
  })
})

describe("createWaitlist onVerified", () => {
  it("lets an approved user sign in", async () => {
    const { verify, seed } = setup()
    await seed("alice@example.com", "APPROVED")

    expect(await verify("alice@example.com")).toBe("allow")
  })

  it("puts a newly verified identifier on the waitlist and tells admins once", async () => {
    const notify = vi.fn()
    const { verify, userStore, statuses } = setup({ notify })

    const first = await verify("new@example.com")
    const second = await verify("new@example.com")

    expect(first).toEqual({ redirect: "/waitlist" })
    expect(second).toEqual({ redirect: "/waitlist" })
    expect(userStore.create).toHaveBeenCalledTimes(1)
    const [userId] = [...statuses.keys()]
    expect(statuses.get(userId as string)).toBe("PENDING")
    expect(notify).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith({
      reason: "waitlisted",
      userId,
      provider: "email",
      identifier: "new@example.com",
    })
  })

  it("waitlists an existing user with no status, and tells admins", async () => {
    const notify = vi.fn()
    const { verify, statuses, seed } = setup({ notify })
    const userId = await seed("old@example.com", null)

    expect(await verify("old@example.com")).toEqual({ redirect: "/waitlist" })
    expect(statuses.get(userId)).toBe("PENDING")
    expect(notify).toHaveBeenCalledWith(
      expect.objectContaining({ reason: "waitlisted", userId }),
    )
  })

  it("sends blocked users to blockedUrl, or to the waitlist when unset", async () => {
    const quiet = setup()
    await quiet.seed("mallory@example.com", "BLOCKED")
    expect(await quiet.verify("mallory@example.com")).toEqual({
      redirect: "/waitlist",
    })

    const told = setup({ blockedUrl: "/login?error=blocked" })
    await told.seed("mallory@example.com", "BLOCKED")
    expect(await told.verify("mallory@example.com")).toEqual({
      redirect: "/login?error=blocked",
    })
  })

  it("lets autoApprove approve a waiting user and tells admins", async () => {
    const notify = vi.fn()
    const autoApprove = vi.fn().mockResolvedValue(true)
    const { verify, statuses } = setup({ autoApprove, notify })

    expect(await verify("invited@example.com")).toBe("allow")
    const [userId] = [...statuses.keys()]
    expect(statuses.get(userId as string)).toBe("APPROVED")
    expect(autoApprove).toHaveBeenCalledWith(
      expect.objectContaining({
        identifier: "invited@example.com",
        userId,
        isNewUser: true,
      }),
    )
    expect(notify).toHaveBeenCalledWith(
      expect.objectContaining({ reason: "auto-approved", userId }),
    )
  })

  it("never asks autoApprove about a blocked user", async () => {
    const autoApprove = vi.fn().mockReturnValue(true)
    const { verify, seed } = setup({ autoApprove })
    await seed("mallory@example.com", "BLOCKED")

    expect(await verify("mallory@example.com")).toEqual({
      redirect: "/waitlist",
    })
    expect(autoApprove).not.toHaveBeenCalled()
  })

  it("never asks autoApprove about a blocked user that userStore.create returns", async () => {
    // Apps that upsert users by email hand back an existing user from create
    // when that user has no identity for this provider yet
    const autoApprove = vi.fn().mockReturnValue(true)
    const { verify, userStore, statuses } = setup({ autoApprove })
    statuses.set("existing", "BLOCKED")
    vi.mocked(userStore.create).mockResolvedValueOnce({ id: "existing" })

    expect(await verify("mallory@example.com")).toEqual({
      redirect: "/waitlist",
    })
    expect(autoApprove).not.toHaveBeenCalled()
    expect(statuses.get("existing")).toBe("BLOCKED")
  })

  it("does not re-announce a waiting user that userStore.create returns", async () => {
    const notify = vi.fn()
    const autoApprove = vi.fn().mockReturnValue(false)
    const { verify, userStore, approvalStore, statuses } = setup({
      autoApprove,
      notify,
    })
    statuses.set("existing", "PENDING")
    vi.mocked(userStore.create).mockResolvedValueOnce({ id: "existing" })

    expect(await verify("pending@example.com")).toEqual({
      redirect: "/waitlist",
    })
    expect(approvalStore.setApprovalStatus).not.toHaveBeenCalled()
    expect(notify).not.toHaveBeenCalled()
  })

  it("keeps a waiting user waiting when autoApprove says no", async () => {
    const autoApprove = vi.fn().mockReturnValue(false)
    const { verify, seed } = setup({ autoApprove })
    await seed("pending@example.com", "PENDING")

    expect(await verify("pending@example.com")).toEqual({
      redirect: "/waitlist",
    })
    expect(autoApprove).toHaveBeenCalledWith(
      expect.objectContaining({ isNewUser: false }),
    )
  })

  it("lets links through without touching the status", async () => {
    const notify = vi.fn()
    const { verify, approvalStore, seed } = setup({ notify })
    await seed("second@example.com", null)

    expect(await verify("second@example.com", "link")).toBe("allow")
    expect(approvalStore.setApprovalStatus).not.toHaveBeenCalled()
    expect(notify).not.toHaveBeenCalled()
  })

  it("logs a failed notify and still answers", async () => {
    const warn = vi.fn()
    const { verify } = setup({
      notify: () => Promise.reject(new Error("smtp down")),
      logger: { warn },
    })

    expect(await verify("new@example.com")).toEqual({ redirect: "/waitlist" })
    expect(warn).toHaveBeenCalledWith(
      "waitlist notify failed",
      expect.objectContaining({ reason: "waitlisted", error: "smtp down" }),
    )
  })
})

describe("createWaitlist behind Auth", () => {
  let auth: Auth | undefined

  afterEach(() => {
    auth?.destroy()
  })

  /**
   * A provider shaped like the email provider: initiate consults the gate
   * and records what it would send; verify signs in whatever identifier the
   * request names, as if its code had checked out.
   */
  function createProvider(sent: string[]): AuthProvider {
    return {
      id: "email",
      name: "Email",
      consultsInitiateGate: true,
      getRoutes: () => [
        { method: "POST", path: "/email/initiate", handler: "initiate" },
        { method: "POST", path: "/email/verify", handler: "verify" },
      ],
      describe: () => ({ settings: {} }),
      async initiate(request, context) {
        const email = new URLSearchParams(await request.text()).get("email")
        if (!email) throw new Error("no email")
        const gated = await context.gate?.check({
          provider: "email",
          identifier: email,
          mode: "signin",
        })
        if (gated) return gated
        sent.push(email)
        return { success: true, message: "Sent" }
      },
      async verify(request, context) {
        const email = new URLSearchParams(await request.text()).get("email")
        if (!email) throw new Error("no email")
        return authenticateWithIdentifier("email", email, context)
      },
    }
  }

  function setupAuth() {
    const notify = vi.fn()
    const sent: string[] = []
    const stores = createStores()
    // Configured as apps did before the waitlist moved to onVerified
    const waitlist = createWaitlist({
      identityStore: stores.identityStore,
      userStore: stores.userStore,
      approvalStore: stores.approvalStore,
      waitlistUrl: "/waitlist",
      notify,
    })
    auth = new Auth({
      session: {
        secret: "test-session-secret",
        maxAge: "7d",
        cookieName: "auth_session",
        cookie: { secure: false, sameSite: "lax" },
      },
      identityStore: stores.identityStore,
      userStore: stores.userStore,
      challengeStore: new InMemoryChallengeStore(),
      providers: [createProvider(sent)],
      gate: waitlist,
    })
    return { ...stores, auth, notify, sent }
  }

  function post(action: "initiate" | "verify", email: string): Request {
    return new Request(`https://example.com/auth/email/${action}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({ email }).toString(),
    })
  }

  it("creates no waitlist row and sends admins nothing for an unverified initiate", async () => {
    const { auth, userStore, identityStore, statuses, notify, sent } =
      setupAuth()

    const response = await auth.handleRequest(
      post("initiate", "stranger@example.com"),
    )

    expect(response.status).toBe(200)
    expect(sent).toEqual(["stranger@example.com"])
    expect(userStore.create).not.toHaveBeenCalled()
    expect(identityStore.create).not.toHaveBeenCalled()
    expect(statuses.size).toBe(0)
    expect(notify).not.toHaveBeenCalled()
  })

  it("waitlists a non-approved address once it is verified, with no session", async () => {
    const { auth, statuses, notify } = setupAuth()

    await auth.handleRequest(post("initiate", "new@example.com"))
    const response = await auth.handleRequest(post("verify", "new@example.com"))

    expect(response.status).toBe(302)
    expect(response.headers.get("Location")).toBe("/waitlist")
    expect(response.headers.get("Set-Cookie")).toBeNull()
    const [userId] = [...statuses.keys()]
    expect(statuses.get(userId as string)).toBe("PENDING")
    expect(notify).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith({
      reason: "waitlisted",
      userId,
      provider: "email",
      identifier: "new@example.com",
    })
  })

  it("signs in an approved address", async () => {
    const { auth, seed, notify } = setupAuth()
    await seed("alice@example.com", "APPROVED")

    const response = await auth.handleRequest(
      post("verify", "alice@example.com"),
    )

    expect(response.status).toBe(200)
    expect(notify).not.toHaveBeenCalled()
  })
})

describe("createWaitlist redirectFor", () => {
  it("returns null only for approved users", async () => {
    const { waitlist, seed } = setup({ blockedUrl: "/blocked" })

    expect(
      await waitlist.redirectFor(await seed("a@example.com", "APPROVED")),
    ).toBeNull()
    expect(
      await waitlist.redirectFor(await seed("p@example.com", "PENDING")),
    ).toBe("/waitlist")
    expect(
      await waitlist.redirectFor(await seed("b@example.com", "BLOCKED")),
    ).toBe("/blocked")
    expect(await waitlist.redirectFor(await seed("n@example.com", null))).toBe(
      "/waitlist",
    )
  })
})

describe("createWaitlist handleAdminAction", () => {
  function form(fields: Record<string, string>): FormData {
    const data = new FormData()
    for (const [key, value] of Object.entries(fields)) data.set(key, value)
    return data
  }

  it("approves and blocks", async () => {
    const { waitlist, statuses, seed } = setup()
    const userId = await seed("p@example.com", "PENDING")

    expect(
      await waitlist.handleAdminAction(form({ userId, intent: "approve" })),
    ).toEqual({ success: true, userId, status: "APPROVED" })
    expect(statuses.get(userId)).toBe("APPROVED")

    await waitlist.handleAdminAction(form({ userId, intent: "block" }))
    expect(statuses.get(userId)).toBe("BLOCKED")
  })

  it("rejects a missing userId or an unknown intent without writing", async () => {
    const { waitlist, approvalStore } = setup()

    expect(
      await waitlist.handleAdminAction(form({ intent: "approve" })),
    ).toMatchObject({ success: false })
    expect(
      await waitlist.handleAdminAction(form({ userId: "u", intent: "delete" })),
    ).toMatchObject({ success: false })
    expect(approvalStore.setApprovalStatus).not.toHaveBeenCalled()
  })
})

describe("createWaitlist onApproved", () => {
  function form(fields: Record<string, string>): FormData {
    const data = new FormData()
    for (const [key, value] of Object.entries(fields)) data.set(key, value)
    return data
  }

  it("tells a waiting user they were approved, with their identities", async () => {
    const onApproved = vi.fn()
    const { waitlist, seed } = setup({ onApproved })
    const userId = await seed("p@example.com", "PENDING")

    await waitlist.handleAdminAction(form({ userId, intent: "approve" }))

    expect(onApproved).toHaveBeenCalledTimes(1)
    expect(onApproved).toHaveBeenCalledWith({
      userId,
      identities: [{ provider: "email", identifier: "p@example.com" }],
    })
  })

  it("tells an unblocked user, and a user with no status", async () => {
    const onApproved = vi.fn()
    const { waitlist, seed } = setup({ onApproved })

    await waitlist.approve(await seed("b@example.com", "BLOCKED"))
    await waitlist.approve(await seed("n@example.com", null))

    expect(onApproved).toHaveBeenCalledTimes(2)
  })

  it("stays quiet for an approved user, a block, and autoApprove", async () => {
    const onApproved = vi.fn()
    const { waitlist, verify, seed } = setup({
      onApproved,
      autoApprove: () => true,
    })
    const approved = await seed("a@example.com", "APPROVED")
    const pending = await seed("p@example.com", "PENDING")

    await waitlist.approve(approved)
    await waitlist.handleAdminAction(form({ userId: pending, intent: "block" }))
    await verify("invited@example.com")

    expect(onApproved).not.toHaveBeenCalled()
  })

  it("logs a failed onApproved and keeps the approval", async () => {
    const warn = vi.fn()
    const { waitlist, statuses, seed } = setup({
      onApproved: () => Promise.reject(new Error("smtp down")),
      logger: { warn },
    })
    const userId = await seed("p@example.com", "PENDING")

    expect(
      await waitlist.handleAdminAction(form({ userId, intent: "approve" })),
    ).toEqual({ success: true, userId, status: "APPROVED" })
    expect(statuses.get(userId)).toBe("APPROVED")
    expect(warn).toHaveBeenCalledWith(
      "waitlist onApproved failed",
      expect.objectContaining({ userId, error: "smtp down" }),
    )
  })
})

describe("createWaitlist lifecycle", () => {
  it("holds a user at the gate until approved and again once blocked", async () => {
    const { waitlist, verify, statuses } = setup({ blockedUrl: "/blocked" })

    // Unknown identifier: waitlisted once verified, and on every request
    expect(await verify("new@example.com")).toEqual({
      redirect: "/waitlist",
    })
    const [userId] = [...statuses.keys()] as [string]
    expect(await waitlist.redirectFor(userId)).toBe("/waitlist")

    // PENDING -> APPROVED: through the gate
    await waitlist.approve(userId)
    expect(await verify("new@example.com")).toBe("allow")
    expect(await waitlist.redirectFor(userId)).toBeNull()

    // APPROVED -> BLOCKED: turned away at both checks
    await waitlist.block(userId)
    expect(await verify("new@example.com")).toEqual({
      redirect: "/blocked",
    })
    expect(await waitlist.redirectFor(userId)).toBe("/blocked")

    // BLOCKED -> APPROVED: an admin can undo a block
    await waitlist.approve(userId)
    expect(await verify("new@example.com")).toBe("allow")
    expect(await waitlist.redirectFor(userId)).toBeNull()
  })

  it("lets an admin block a waiting user, who stays out", async () => {
    const { waitlist, verify, seed } = setup({ blockedUrl: "/blocked" })
    const userId = await seed("p@example.com", "PENDING")

    await waitlist.block(userId)

    expect(await verify("p@example.com")).toEqual({
      redirect: "/blocked",
    })
    expect(await waitlist.redirectFor(userId)).toBe("/blocked")
  })
})

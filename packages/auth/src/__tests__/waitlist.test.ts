import { describe, it, expect, vi } from "vitest"
import {
  createWaitlist,
  type ApprovalStatus,
  type ApprovalStore,
  type WaitlistConfig,
} from "../waitlist.js"
import { authenticateWithIdentifier } from "../provider-util.js"
import type {
  AuthContext,
  AuthUser,
  Identity,
  IdentityStore,
  UserStore,
} from "../types.js"
import type { InitiateGateInput } from "../initiate-gate.js"

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
    userStore: stores.userStore,
    approvalStore: stores.approvalStore,
    waitlistUrl: "/waitlist",
    ...overrides,
  })
  return { ...stores, waitlist }
}

function signin(identifier: string): InitiateGateInput {
  return {
    provider: "email",
    identifier,
    mode: "signin",
    request: new Request("https://example.com/auth/email/initiate", {
      method: "POST",
    }),
  }
}

describe("createWaitlist onInitiate", () => {
  it("lets an approved user sign in", async () => {
    const { waitlist, seed } = setup()
    await seed("alice@example.com", "APPROVED")

    expect(await waitlist.onInitiate(signin("alice@example.com"))).toBe("allow")
  })

  it("puts an unknown identifier on the waitlist and tells admins once", async () => {
    const notify = vi.fn()
    const { waitlist, userStore, identityStore, statuses } = setup({ notify })

    const first = await waitlist.onInitiate(signin("new@example.com"))
    const second = await waitlist.onInitiate(signin("new@example.com"))

    expect(first).toEqual({ redirect: "/waitlist" })
    expect(second).toEqual({ redirect: "/waitlist" })
    expect(userStore.create).toHaveBeenCalledTimes(1)
    expect(identityStore.create).toHaveBeenCalledTimes(1)
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

  it("creates the identity the verify step then signs in, not a second user", async () => {
    const { waitlist, userStore, identityStore, statuses } = setup()
    await waitlist.onInitiate(signin("new@example.com"))
    const [userId] = [...statuses.keys()]

    const result = await authenticateWithIdentifier(
      "email",
      "new@example.com",
      { identityStore, userStore } as AuthContext,
    )

    expect(result.success && result.user.id).toBe(userId)
    expect(userStore.create).toHaveBeenCalledTimes(1)
  })

  it("waitlists an existing user with no status, and tells admins", async () => {
    const notify = vi.fn()
    const { waitlist, statuses, seed } = setup({ notify })
    const userId = await seed("old@example.com", null)

    expect(await waitlist.onInitiate(signin("old@example.com"))).toEqual({
      redirect: "/waitlist",
    })
    expect(statuses.get(userId)).toBe("PENDING")
    expect(notify).toHaveBeenCalledWith(
      expect.objectContaining({ reason: "waitlisted", userId }),
    )
  })

  it("sends blocked users to blockedUrl, or to the waitlist when unset", async () => {
    const quiet = setup()
    await quiet.seed("mallory@example.com", "BLOCKED")
    expect(
      await quiet.waitlist.onInitiate(signin("mallory@example.com")),
    ).toEqual({ redirect: "/waitlist" })

    const told = setup({ blockedUrl: "/login?error=blocked" })
    await told.seed("mallory@example.com", "BLOCKED")
    expect(
      await told.waitlist.onInitiate(signin("mallory@example.com")),
    ).toEqual({ redirect: "/login?error=blocked" })
  })

  it("lets autoApprove approve a waiting user and tells admins", async () => {
    const notify = vi.fn()
    const autoApprove = vi.fn().mockResolvedValue(true)
    const { waitlist, statuses } = setup({ autoApprove, notify })

    expect(await waitlist.onInitiate(signin("invited@example.com"))).toBe(
      "allow",
    )
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
    const { waitlist, seed } = setup({ autoApprove })
    await seed("mallory@example.com", "BLOCKED")

    expect(await waitlist.onInitiate(signin("mallory@example.com"))).toEqual({
      redirect: "/waitlist",
    })
    expect(autoApprove).not.toHaveBeenCalled()
  })

  it("never asks autoApprove about a blocked user that userStore.create returns", async () => {
    // Apps that upsert users by email hand back an existing user from create
    // when that user has no identity for this provider yet
    const autoApprove = vi.fn().mockReturnValue(true)
    const { waitlist, userStore, statuses } = setup({ autoApprove })
    statuses.set("existing", "BLOCKED")
    vi.mocked(userStore.create).mockResolvedValueOnce({ id: "existing" })

    expect(await waitlist.onInitiate(signin("mallory@example.com"))).toEqual({
      redirect: "/waitlist",
    })
    expect(autoApprove).not.toHaveBeenCalled()
    expect(statuses.get("existing")).toBe("BLOCKED")
  })

  it("does not re-announce a waiting user that userStore.create returns", async () => {
    const notify = vi.fn()
    const autoApprove = vi.fn().mockReturnValue(false)
    const { waitlist, userStore, approvalStore, statuses } = setup({
      autoApprove,
      notify,
    })
    statuses.set("existing", "PENDING")
    vi.mocked(userStore.create).mockResolvedValueOnce({ id: "existing" })

    expect(await waitlist.onInitiate(signin("pending@example.com"))).toEqual({
      redirect: "/waitlist",
    })
    expect(approvalStore.setApprovalStatus).not.toHaveBeenCalled()
    expect(notify).not.toHaveBeenCalled()
  })

  it("keeps a waiting user waiting when autoApprove says no", async () => {
    const autoApprove = vi.fn().mockReturnValue(false)
    const { waitlist, seed } = setup({ autoApprove })
    await seed("pending@example.com", "PENDING")

    expect(await waitlist.onInitiate(signin("pending@example.com"))).toEqual({
      redirect: "/waitlist",
    })
    expect(autoApprove).toHaveBeenCalledWith(
      expect.objectContaining({ isNewUser: false }),
    )
  })

  it("lets link initiates through without creating anything", async () => {
    const { waitlist, userStore } = setup()

    const decision = await waitlist.onInitiate({
      ...signin("second@example.com"),
      mode: "link",
    })

    expect(decision).toBe("allow")
    expect(userStore.create).not.toHaveBeenCalled()
  })

  it("logs a failed notify and still answers", async () => {
    const warn = vi.fn()
    const { waitlist } = setup({
      notify: () => Promise.reject(new Error("smtp down")),
      logger: { warn },
    })

    expect(await waitlist.onInitiate(signin("new@example.com"))).toEqual({
      redirect: "/waitlist",
    })
    expect(warn).toHaveBeenCalledWith(
      "waitlist notify failed",
      expect.objectContaining({ reason: "waitlisted", error: "smtp down" }),
    )
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

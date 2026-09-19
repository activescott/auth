import { describe, it, expect, vi } from "vitest"
import {
  createPrismaIdentityStore,
  toProviderState,
  type PrismaIdentityModel,
} from "../prisma-identity-store.js"

interface Row {
  id: string
  userId: string
  provider: string
  identifier: string
  metadata: unknown
  createdAt: Date
  verifiedAt: Date | null
}

/**
 * An in-memory stand-in for `prisma.identity` that mimics the Prisma
 * behavior the store relies on: undefined fields in `data` are skipped, a
 * missing JSON column reads back as null, and deleting or updating a missing
 * row throws a P2025 error.
 */
function fakeModel(): PrismaIdentityModel<Row> & { rows: Row[] } {
  const rows: Row[] = []
  let nextId = 1
  let clock = Date.UTC(2026, 0, 1)

  function notFound(): Error {
    return Object.assign(new Error("Record to delete does not exist."), {
      code: "P2025",
    })
  }

  function defined(data: Record<string, unknown>): Record<string, unknown> {
    return Object.fromEntries(
      Object.entries(data).filter(([, value]) => value !== undefined),
    )
  }

  return {
    rows,
    async findUnique({ where }) {
      const { provider, identifier } = where.provider_identifier
      return (
        rows.find(
          (row) => row.provider === provider && row.identifier === identifier,
        ) ?? null
      )
    },
    async findMany({ where }) {
      const matches = rows.filter((row) =>
        typeof where.userId === "string"
          ? row.userId === where.userId
          : where.userId.in.includes(row.userId),
      )
      return matches.sort(
        (a, b) => b.createdAt.getTime() - a.createdAt.getTime(),
      )
    },
    async create({ data }) {
      const row: Row = {
        metadata: null,
        verifiedAt: null,
        ...defined(data),
        id: String(nextId++),
        createdAt: new Date((clock += 1000)),
      } as Row
      rows.push(row)
      return row
    },
    async update({ where, data }) {
      const row = rows.find((candidate) => candidate.id === where.id)
      if (!row) throw notFound()
      Object.assign(row, defined(data))
      return row
    },
    async delete({ where }) {
      const index = rows.findIndex((row) => row.id === where.id)
      if (index === -1) throw notFound()
      return rows.splice(index, 1)[0]
    },
    async updateMany({ where, data }) {
      const matches = rows.filter((row) => row.userId === where.userId)
      for (const row of matches) row.userId = data.userId
      return { count: matches.length }
    },
  }
}

function setup() {
  const model = fakeModel()
  const store = createPrismaIdentityStore({
    model,
    providerStateField: "metadata",
  })
  return { model, store }
}

describe("createPrismaIdentityStore", () => {
  it("writes providerState to the named column and reads it back", async () => {
    const { model, store } = setup()

    const created = await store.create({
      userId: "u1",
      provider: "passkey",
      identifier: "cred-1",
      providerState: { counter: 0 },
    })

    expect(model.rows[0].metadata).toEqual({ counter: 0 })
    expect(created).toEqual({
      id: created.id,
      userId: "u1",
      provider: "passkey",
      identifier: "cred-1",
      providerState: { counter: 0 },
      createdAt: expect.any(Date),
      verifiedAt: undefined,
    })
    expect(created).not.toHaveProperty("metadata")
  })

  it("finds an identity by provider and identifier", async () => {
    const { store } = setup()
    await store.create({
      userId: "u1",
      provider: "email",
      identifier: "a@example.com",
      providerState: {},
    })

    const found = await store.findByProviderAndIdentifier(
      "email",
      "a@example.com",
    )

    expect(found?.userId).toBe("u1")
    expect(
      await store.findByProviderAndIdentifier("sms", "a@example.com"),
    ).toBeNull()
  })

  it("returns a user's identities newest first", async () => {
    const { store } = setup()
    const first = await store.create({
      userId: "u1",
      provider: "email",
      identifier: "a@example.com",
      providerState: {},
    })
    const second = await store.create({
      userId: "u1",
      provider: "sms",
      identifier: "+15555550100",
      providerState: {},
    })
    await store.create({
      userId: "u2",
      provider: "email",
      identifier: "b@example.com",
      providerState: {},
    })

    const identities = await store.findByUserId("u1")

    expect(identities.map((identity) => identity.id)).toEqual([
      second.id,
      first.id,
    ])
  })

  it("finds the identities of several users in one query", async () => {
    const { model, store } = setup()
    for (const userId of ["u1", "u2", "u3"]) {
      await store.create({
        userId,
        provider: "email",
        identifier: `${userId}@example.com`,
        providerState: {},
      })
    }
    const findMany = vi.spyOn(model, "findMany")

    const identities = await store.findByUserIds!(["u1", "u3"])

    expect(identities.map((identity) => identity.userId).sort()).toEqual([
      "u1",
      "u3",
    ])
    expect(findMany).toHaveBeenCalledTimes(1)
  })

  it("skips the query when asked for no users", async () => {
    const { model, store } = setup()
    const findMany = vi.spyOn(model, "findMany")

    expect(await store.findByUserIds!([])).toEqual([])
    expect(findMany).not.toHaveBeenCalled()
  })

  it("replaces providerState and sets verifiedAt on update", async () => {
    const { store } = setup()
    const created = await store.create({
      userId: "u1",
      provider: "passkey",
      identifier: "cred-1",
      providerState: { counter: 0, publicKey: "pk" },
    })
    const verifiedAt = new Date(Date.UTC(2026, 5, 1))

    const updated = await store.update(created.id, {
      providerState: { counter: 1 },
      verifiedAt,
    })

    expect(updated.providerState).toEqual({ counter: 1 })
    expect(updated.verifiedAt).toEqual(verifiedAt)
  })

  it("leaves providerState alone when an update only sets verifiedAt", async () => {
    const { store } = setup()
    const created = await store.create({
      userId: "u1",
      provider: "passkey",
      identifier: "cred-1",
      providerState: { counter: 3 },
    })

    const updated = await store.update(created.id, { verifiedAt: new Date() })

    expect(updated.providerState).toEqual({ counter: 3 })
  })

  it("deletes an identity, and ignores one that is already gone", async () => {
    const { model, store } = setup()
    const created = await store.create({
      userId: "u1",
      provider: "email",
      identifier: "a@example.com",
      providerState: {},
    })

    await store.delete(created.id)
    await expect(store.delete(created.id)).resolves.toBeUndefined()
    expect(model.rows).toHaveLength(0)
  })

  it("rethrows delete errors other than record-not-found", async () => {
    const { model, store } = setup()
    vi.spyOn(model, "delete").mockRejectedValue(new Error("connection lost"))

    await expect(store.delete("1")).rejects.toThrow("connection lost")
  })

  it("reassigns identities with one updateMany by default", async () => {
    const { model, store } = setup()
    await store.create({
      userId: "from",
      provider: "email",
      identifier: "a@example.com",
      providerState: {},
    })
    await store.create({
      userId: "from",
      provider: "sms",
      identifier: "+15555550100",
      providerState: {},
    })
    const updateMany = vi.spyOn(model, "updateMany")

    await store.reassignByUserId("from", "into")

    expect(updateMany).toHaveBeenCalledTimes(1)
    expect(await store.findByUserId("from")).toEqual([])
    expect(await store.findByUserId("into")).toHaveLength(2)
  })

  it("uses a caller-supplied reassignByUserId instead of the default", async () => {
    const model = fakeModel()
    const mergeAccounts = vi.fn(async () => {})
    const store = createPrismaIdentityStore({
      model,
      providerStateField: "metadata",
      reassignByUserId: mergeAccounts,
    })
    const updateMany = vi.spyOn(model, "updateMany")

    await store.reassignByUserId("from", "into")

    expect(mergeAccounts).toHaveBeenCalledWith("from", "into")
    expect(updateMany).not.toHaveBeenCalled()
  })
})

describe("toProviderState", () => {
  it("copies a JSON object", () => {
    const value = { counter: 1, transports: ["internal"] }
    const providerState = toProviderState(value)

    expect(providerState).toEqual(value)
    expect(providerState).not.toBe(value)
  })

  it.each([
    ["null", null],
    ["an array", [1, 2]],
    ["a string", "state"],
    ["a number", 42],
  ])("reads %s as an empty object", (_label, value) => {
    expect(toProviderState(value)).toEqual({})
  })
})

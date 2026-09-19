import type { Identity, IdentityStore } from "@activescott/auth"

/**
 * The columns every identity row must have. Prisma's generated row type for
 * the model satisfies this as long as the field names match; the column
 * backing `providerState` is named separately via `providerStateField`.
 */
export interface PrismaIdentityRow {
  id: string
  userId: string
  provider: string
  identifier: string
  createdAt: Date
  verifiedAt: Date | null
}

/**
 * The slice of a Prisma model delegate (`prisma.identity`, or `tx.identity`
 * inside a transaction) this store calls. Typed structurally so this package
 * does not depend on `@prisma/client`: any generated client whose model has
 * the {@link PrismaIdentityRow} fields and a `@@unique([provider, identifier])`
 * (Prisma names that compound key `provider_identifier`) is accepted as-is.
 */
export interface PrismaIdentityModel<Row extends PrismaIdentityRow> {
  findUnique(args: {
    where: { provider_identifier: { provider: string; identifier: string } }
  }): PromiseLike<Row | null>
  findMany(args: {
    where: { userId: string | { in: string[] } }
    orderBy: { createdAt: "desc" }
  }): PromiseLike<Row[]>
  create(args: {
    data: { userId: string; provider: string; identifier: string } & {
      [field: string]: unknown
    }
  }): PromiseLike<Row>
  update(args: {
    where: { id: string }
    data: { [field: string]: unknown }
  }): PromiseLike<Row>
  delete(args: { where: { id: string } }): PromiseLike<unknown>
  updateMany(args: {
    where: { userId: string }
    data: { userId: string }
  }): PromiseLike<unknown>
}

/** Options for {@link createPrismaIdentityStore}. */
export interface PrismaIdentityStoreOptions<Row extends PrismaIdentityRow> {
  /** The identity model delegate, e.g. `prisma.identity`. */
  model: PrismaIdentityModel<Row>
  /**
   * Name of the JSON column that stores `Identity.providerState`, e.g.
   * `"metadata"` for a schema that predates the v5 rename. Checked against
   * the model's row type, so a typo fails to compile.
   */
  providerStateField: Exclude<keyof Row & string, keyof PrismaIdentityRow>
  /**
   * Replaces the default `reassignByUserId`, which moves the identities with
   * one `updateMany`. Pass your own when the account merge must move app data
   * in the same transaction (see the account-merge docs in the
   * `@activescott/auth` README), or one that throws to refuse merges.
   */
  reassignByUserId?: IdentityStore["reassignByUserId"]
}

/**
 * Creates an `IdentityStore` backed by a Prisma model. Rows come back newest
 * first, a `null` or non-object JSON column reads as an empty
 * `providerState`, and deleting an identity that is already gone is a no-op.
 */
export function createPrismaIdentityStore<Row extends PrismaIdentityRow>(
  options: PrismaIdentityStoreOptions<Row>,
): IdentityStore {
  const { model, providerStateField } = options

  function toIdentity(row: Row): Identity {
    return {
      id: row.id,
      userId: row.userId,
      provider: row.provider,
      identifier: row.identifier,
      providerState: toProviderState(row[providerStateField]),
      createdAt: row.createdAt,
      verifiedAt: row.verifiedAt ?? undefined,
    }
  }

  return {
    async findByProviderAndIdentifier(provider, identifier) {
      const row = await model.findUnique({
        where: { provider_identifier: { provider, identifier } },
      })
      return row ? toIdentity(row) : null
    },

    async findByUserId(userId) {
      const rows = await model.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
      })
      return rows.map(toIdentity)
    },

    async findByUserIds(userIds) {
      if (userIds.length === 0) return []
      const rows = await model.findMany({
        where: { userId: { in: userIds } },
        orderBy: { createdAt: "desc" },
      })
      return rows.map(toIdentity)
    },

    async create(data) {
      const row = await model.create({
        data: {
          userId: data.userId,
          provider: data.provider,
          identifier: data.identifier,
          [providerStateField]: data.providerState,
        },
      })
      return toIdentity(row)
    },

    async update(id, data) {
      // Prisma skips undefined fields, so a partial update leaves the rest.
      const row = await model.update({
        where: { id },
        data: {
          [providerStateField]: data.providerState,
          verifiedAt: data.verifiedAt,
        },
      })
      return toIdentity(row)
    },

    async delete(id) {
      try {
        await model.delete({ where: { id } })
      } catch (error) {
        if (!isRecordNotFound(error)) throw error
      }
    },

    reassignByUserId:
      options.reassignByUserId ??
      (async (fromUserId, toUserId) => {
        await model.updateMany({
          where: { userId: fromUserId },
          data: { userId: toUserId },
        })
      }),
  }
}

/**
 * Coerces a Prisma JSON column value (`JsonValue | null`) into the plain
 * object `Identity.providerState` requires. Anything that is not a JSON
 * object — `null`, an array, a scalar — becomes `{}`.
 */
export function toProviderState(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return {}
  }
  return { ...value }
}

// Prisma's "record to delete does not exist" error. Checked by code rather
// than `instanceof PrismaClientKnownRequestError` to stay free of
// @prisma/client.
function isRecordNotFound(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "P2025"
  )
}

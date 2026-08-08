import type { Auth } from "../auth.js"
import type {
  AuthConfigDescription,
  Identity,
  IdentityStore,
  ListUsersOptions,
} from "../types.js"

/**
 * One identity as shown on the admin dashboard.
 *
 * Dates are ISO strings, not `Date`s: these rows cross a server-to-client
 * boundary (a framework loader, a JSON response) that does not preserve
 * `Date`, and a half-serialized shape is worse than one that is honest about
 * it.
 *
 * `Identity.metadata` is deliberately absent. It is provider-owned and
 * documented as possibly sensitive — the passkey provider keeps credential
 * public keys there — so nothing derived from it is exposed beyond the
 * last-used timestamp below.
 */
export interface AdminIdentityRow {
  id: string
  /** Provider that authenticated this identity, e.g. "email", "sms" */
  provider: string
  /** Email address, E.164 phone number, or passkey credential id */
  identifier: string
  createdAt: string
  /** When this identity last completed authentication */
  verifiedAt?: string
  /** Provider-reported last use, when the provider tracks one separately */
  lastUsedAt?: string
}

/**
 * One user as shown on the admin dashboard: the store's own record plus the
 * identities it can sign in with.
 */
export interface AdminUserRow {
  id: string
  /**
   * Whatever `UserStore.listUsers` put in `AuthUser.metadata`. The dashboard
   * renders configured keys from here as columns, which is how applications
   * add their own data to the page without a wider store interface.
   */
  metadata: Record<string, unknown>
  identities: AdminIdentityRow[]
  /** Earliest identity creation — the closest thing to a signup date */
  createdAt?: string
  /** Latest successful authentication across all identities */
  lastLoginAt?: string
}

/** A page of users for the admin dashboard */
export interface AdminUsersPage {
  users: AdminUserRow[]
  /** Total users in the store, ignoring limit/offset */
  total: number
}

/**
 * Reads the admin dashboard's data out of the configured stores. Framework
 * agnostic on purpose: adapters render these plain objects however they like.
 */
export interface AdminData {
  listUsers(options: ListUsersOptions): Promise<AdminUsersPage>
  describeConfig(): AuthConfigDescription
}

/**
 * Thrown when the users page is requested but the application's `UserStore`
 * cannot enumerate users. Carries the fix in its message because the page has
 * no other way to explain itself.
 */
export class AdminNotSupportedError extends Error {
  public constructor(message: string) {
    super(message)
    this.name = "AdminNotSupportedError"
  }
}

/**
 * Create the admin dashboard's data reader over an `Auth` instance.
 *
 * @example
 * ```ts
 * const admin = createAdminData(auth)
 * const { users, total } = await admin.listUsers({ limit: 20, offset: 0 })
 * ```
 */
export function createAdminData(auth: Auth): AdminData {
  return {
    async listUsers(options: ListUsersOptions): Promise<AdminUsersPage> {
      const { userStore, identityStore } = auth.getStores()

      if (!userStore.listUsers) {
        throw new AdminNotSupportedError(
          "The admin users page needs UserStore.listUsers, which this " +
            "application's UserStore does not implement. Add it: it receives " +
            "{ limit, offset, sortBy, sortOrder } and returns { users, total }.",
        )
      }

      const { users, total } = await userStore.listUsers(options)
      const identities = await loadIdentities(
        identityStore,
        users.map((user) => user.id),
      )

      return {
        total,
        users: users.map((user) => {
          const owned = identities.get(user.id) ?? []
          return {
            id: user.id,
            metadata: user.metadata ?? {},
            identities: owned.map(toIdentityRow),
            createdAt: earliest(owned.map((identity) => identity.createdAt)),
            lastLoginAt: latest(owned.map((identity) => identity.verifiedAt)),
          }
        }),
      }
    },

    describeConfig(): AuthConfigDescription {
      return auth.describeConfig()
    },
  }
}

/**
 * Group every identity belonging to `userIds` by user, in one round trip when
 * the store supports it and one query per user when it does not.
 */
async function loadIdentities(
  identityStore: IdentityStore,
  userIds: string[],
): Promise<Map<string, Identity[]>> {
  const found = identityStore.findByUserIds
    ? await identityStore.findByUserIds(userIds)
    : (
        await Promise.all(
          userIds.map((userId) => identityStore.findByUserId(userId)),
        )
      ).flat()

  const byUser = new Map<string, Identity[]>()
  for (const identity of found) {
    const existing = byUser.get(identity.userId)
    if (existing) {
      existing.push(identity)
    } else {
      byUser.set(identity.userId, [identity])
    }
  }
  return byUser
}

function toIdentityRow(identity: Identity): AdminIdentityRow {
  return {
    id: identity.id,
    provider: identity.provider,
    identifier: identity.identifier,
    createdAt: identity.createdAt.toISOString(),
    verifiedAt: identity.verifiedAt?.toISOString(),
    lastUsedAt: readLastUsedAt(identity.metadata),
  }
}

/**
 * Read a provider's own last-use timestamp out of identity metadata. The
 * passkey provider records `lastUsedAt` there on every assertion, which is
 * more precise than `verifiedAt` for credentials used outside a sign-in.
 * Anything that is not a parseable date is ignored rather than displayed.
 */
function readLastUsedAt(metadata: Record<string, unknown>): string | undefined {
  const value = metadata["lastUsedAt"]
  if (typeof value !== "string") return undefined
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString()
}

function earliest(dates: Date[]): string | undefined {
  if (dates.length === 0) return undefined
  return new Date(
    Math.min(...dates.map((date) => date.getTime())),
  ).toISOString()
}

function latest(dates: (Date | undefined)[]): string | undefined {
  const times = dates
    .filter((date): date is Date => date !== undefined)
    .map((date) => date.getTime())
  if (times.length === 0) return undefined
  return new Date(Math.max(...times)).toISOString()
}

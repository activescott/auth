import type { Auth } from "../auth.js"
import type { AuthUser, Identity } from "../types.js"

/** Environment variable read when `admins` is not configured explicitly */
export const ADMIN_IDENTIFIERS_ENV = "AUTH_ADMIN_IDENTIFIERS"

/**
 * Decides whether a signed-in user is an admin. Receives every identity the
 * user owns, not just the one they signed in with, so a user allowlisted by
 * email still counts after signing in by SMS.
 */
export type AdminPredicate = (
  user: AuthUser,
  identities: Identity[],
) => boolean | Promise<boolean>

/**
 * Build the check that decides whether a user is an admin.
 *
 * With no `admins` argument the allowlist comes from
 * `AUTH_ADMIN_IDENTIFIERS`. Read through `globalThis.process` because this
 * runs on runtimes that have no `process` at all (Workers, Deno); there, the
 * variable is simply absent and the caller must pass `admins`.
 *
 * The allowlist is read once, when the predicate is built.
 *
 * @param admins - A delimited allowlist of identifiers (email addresses and/or
 *   E.164 phone numbers, separated by commas or whitespace), an array of them,
 *   or a predicate, which is returned unchanged.
 *
 * @example
 * ```ts
 * const isAdmin = createAdminPredicate(process.env.ADMIN_EMAILS)
 * const identities = await identityStore.findByUserId(user.id)
 * if (await isAdmin(user, identities)) { ... }
 * ```
 */
export function createAdminPredicate(
  admins?: string | string[] | AdminPredicate,
): AdminPredicate {
  if (typeof admins === "function") return admins

  const configured =
    admins ?? globalThis.process?.env?.[ADMIN_IDENTIFIERS_ENV] ?? ""
  const allowed = new Set(
    (Array.isArray(configured) ? configured : splitAllowlist(configured))
      .map(normalizeIdentifier)
      .filter((entry) => entry.length > 0),
  )

  // Fail closed: an unset or empty allowlist admits nobody. The alternative —
  // admitting everyone — turns a forgotten environment variable into a data
  // leak.
  if (allowed.size === 0) return () => false

  return (_user: AuthUser, identities: Identity[]) =>
    identities.some((identity) =>
      allowed.has(normalizeIdentifier(identity.identifier)),
    )
}

/**
 * Whether `user` is on the `AUTH_ADMIN_IDENTIFIERS` allowlist, matched against
 * every identity they own. This is the check the admin dashboard makes, for
 * apps that gate something of their own on the same allowlist.
 *
 * Loads the user's identities from the configured `IdentityStore` on every
 * call, so a removed identity stops matching immediately. Call it after your
 * own session check, on the `AuthUser` that session returned.
 *
 * For an allowlist that does not come from the environment, build the
 * predicate yourself with {@link createAdminPredicate}.
 *
 * @example
 * ```ts
 * const session = await auth.verifySession(request)
 * if (!session || !(await isAdminUser(auth, session.user))) {
 *   return new Response("Not Found", { status: 404 })
 * }
 * ```
 */
export async function isAdminUser(
  auth: Auth,
  user: AuthUser,
): Promise<boolean> {
  const identities = await auth.getStores().identityStore.findByUserId(user.id)
  return createAdminPredicate()(user, identities)
}

/**
 * Split a delimited allowlist. Commas are the documented separator; whitespace
 * and newlines are accepted too so a multi-line environment variable or a
 * space-separated list works without surprises.
 */
function splitAllowlist(value: string): string[] {
  return value.split(/[,\s]+/)
}

/**
 * Fold an identifier to its comparable form. Email addresses are
 * case-insensitive in practice, and everything gets trimmed; E.164 phone
 * numbers are already canonical and are left alone apart from case.
 */
function normalizeIdentifier(identifier: string): string {
  return identifier.trim().toLowerCase()
}

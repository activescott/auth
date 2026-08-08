import type { Auth, AuthUser, Identity } from "@activescott/auth"
import type { AdminForbiddenBehavior, AdminPredicate } from "./admin-options.js"

const HTTP_NOT_FOUND = 404
const HTTP_FORBIDDEN = 403

/** Environment variable read when `admins` is not configured explicitly */
export const ADMIN_IDENTIFIERS_ENV = "AUTH_ADMIN_IDENTIFIERS"

/**
 * Build the check that decides whether a user is an admin.
 *
 * With no `admins` option the allowlist comes from
 * `AUTH_ADMIN_IDENTIFIERS`. Read through `globalThis.process` because the
 * adapter also runs on runtimes that have no `process` at all (Workers, Deno);
 * there, the variable is simply absent and the caller must pass `admins`.
 */
export function createAdminPredicate(
  admins: string | string[] | AdminPredicate | undefined,
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

/**
 * Load every identity the user owns, so an allowlist entry matches whichever
 * of the user's addresses or numbers it names — not only the one used for the
 * current session.
 */
export async function loadUserIdentities(
  auth: Auth,
  user: AuthUser,
): Promise<Identity[]> {
  return auth.getStores().identityStore.findByUserId(user.id)
}

/**
 * The response a signed-in non-admin receives.
 */
export function forbiddenResponse(
  behavior: AdminForbiddenBehavior,
  request: Request,
): Response {
  if (typeof behavior === "function") return behavior(request)
  return behavior === "forbidden"
    ? new Response("Forbidden", { status: HTTP_FORBIDDEN })
    : new Response("Not Found", { status: HTTP_NOT_FOUND })
}

import type { Auth, AuthUser, Identity } from "@activescott/auth"
import type { AdminForbiddenBehavior } from "./admin-options.js"

const HTTP_NOT_FOUND = 404
const HTTP_FORBIDDEN = 403

// The allowlist check itself lives in core, at @activescott/auth/admin, so
// apps gating their own pages on the same allowlist run the same code the
// dashboard does.
export {
  ADMIN_IDENTIFIERS_ENV,
  createAdminPredicate,
} from "@activescott/auth/admin"

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

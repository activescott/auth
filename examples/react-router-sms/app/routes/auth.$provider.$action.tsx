/**
 * Catch-all route for every auth provider's HTTP endpoints.
 *
 * URL shape: /auth/<provider>/<action>
 *   - GET  /auth/email/verify?token=...   → user clicked the magic link
 *   - POST /auth/email/initiate           → server-side magic-link send
 *   - (future) /auth/google/callback, /auth/sms/verify, etc.
 *
 * `handleAuth` (from the React Router adapter) dispatches to the right
 * provider, runs `verify` or `initiate`, sets/clears the session cookie, and
 * returns a redirect Response. Both `loader` (GET) and `action` (POST) point
 * at it so this single file covers every provider × action combo.
 */
import { handleAuth } from "~/lib/auth.server"
import type { Route } from "./+types/auth.$provider.$action"

export function loader({ request }: Route.LoaderArgs) {
  return handleAuth({ request })
}

export function action({ request }: Route.ActionArgs) {
  return handleAuth({ request })
}

import type { AuthLogger } from "@activescott/auth"

const HTTP_BAD_REQUEST = 400

/** The methods react-router runs its own Origin check on. */
const MUTATION_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"])

/**
 * Whether `request` is a mutation carrying an `Origin` from somewhere other
 * than the app itself.
 *
 * The comparison is react-router's own (`throwIfPotentialCSRFAttack`): the
 * whole origin, scheme and port included, against `request.url`. Behind a
 * proxy that terminates TLS and forwards plain HTTP, `request.url` says
 * `https://` only because the app trusts the proxy (express `trust proxy`);
 * without that every POST from the browser looks cross-origin.
 *
 * A request with no `Origin` passes, again as react-router does. Browsers send
 * one on every mutation, so refusing them would only lock out curl and the
 * probes. `Origin: null`, which a sandboxed iframe sends, is refused.
 */
export function isCrossOriginMutation(request: Request): boolean {
  if (!MUTATION_METHODS.has(request.method.toUpperCase())) return false

  const origin = request.headers.get("origin")
  if (origin === null) return false

  try {
    return new URL(origin).origin !== new URL(request.url).origin
  } catch {
    return true
  }
}

/**
 * react-router checks `Origin` on document and single-fetch action requests,
 * but `handleResourceRequest` does not, and an app's auth and logout routes
 * are resource routes: an action and no component. So `handleAuth` and
 * `logout` run this first. Returns the refusal, or null to fall through.
 */
export function applyOriginGate(
  request: Request,
  logger?: AuthLogger,
): Response | null {
  if (!isCrossOriginMutation(request)) return null
  logger?.warn("refused a cross-origin action", {
    origin: request.headers.get("origin"),
  })
  // The same answer react-router gives when its own check fails.
  return new Response("Bad Request", { status: HTTP_BAD_REQUEST })
}

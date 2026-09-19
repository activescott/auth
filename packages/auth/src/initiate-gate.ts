import type { AuthError, AuthInitResult, AuthLogger } from "./types.js"
import { buildReturnUrl, isBrowserFormPost } from "./provider-util.js"

/**
 * What an initiate is for: `"signin"` resolves a user from the identifier,
 * `"link"` attaches the identifier to the already signed-in user.
 */
export type InitiateMode = "signin" | "link"

/**
 * What {@link InitiateGate.onInitiate} is told about an initiate that is about
 * to send a message.
 */
export interface InitiateGateInput {
  /** Id of the provider handling the initiate, e.g. "email" or "sms" */
  provider: string
  /**
   * The recipient as the provider will store it: parsed out of the request
   * body, normalized (lower-cased email, E.164 phone number), and already
   * validated. A malformed identifier is rejected by the provider before the
   * gate runs, so the gate never sees one.
   */
  identifier: string
  /** Whether this is a sign-in or a link to the signed-in user */
  mode: InitiateMode
  /**
   * The initiate request, for headers, cookies, or the URL. Its body is
   * still readable, but prefer `identifier` over re-parsing it.
   */
  request: Request
}

/**
 * The gate's verdict:
 * - `"allow"` — carry on and send the message;
 * - `{ redirect }` — send nothing and answer with a 302 to this URL (for
 *   example a waitlist page). Every caller gets the 302, including fetch
 *   callers;
 * - `{ error }` — send nothing and answer like any other initiate failure:
 *   browser form posts are redirected back to the submitting page with
 *   `?error=<code>`, other callers get the error as JSON.
 */
export type InitiateGateDecision =
  "allow" | { redirect: string } | { error: AuthError }

/**
 * Application policy deciding who may start a sign-in or link — an
 * allowlist, an invite-only beta, a blocked domain. Configured as
 * `AuthConfig.gate`.
 */
export interface InitiateGate {
  /**
   * Called for every initiate once the provider has validated the identifier
   * and before anything is created or sent. Runs inside `Auth.handleRequest`,
   * so an app route that calls it cannot forget the gate. A thrown error
   * fails the initiate; nothing is sent.
   */
  onInitiate(
    input: InitiateGateInput,
  ): InitiateGateDecision | Promise<InitiateGateDecision>
}

/**
 * The part of the gate that providers see on `AuthContext.gate`, bound to the
 * request being handled.
 */
export interface InitiateGateContext {
  /**
   * Consult the application's gate. Call it once the identifier is parsed,
   * normalized and validated, and before creating a challenge or sending
   * anything. Returns undefined when the initiate may proceed; otherwise
   * return the value from `initiate` as-is.
   */
  check(input: {
    provider: string
    identifier: string
    mode: InitiateMode
  }): Promise<AuthInitResult | Response | undefined>
}

/**
 * Bind the application's gate to one request for `AuthContext.gate`.
 *
 * `request` must still have an unread body: the gate receives a clone of it,
 * taken here, so the gate can read the body even after the provider has.
 */
export function initiateGateContextFor(
  gate: InitiateGate,
  request: Request,
  logger?: AuthLogger,
): InitiateGateContext {
  const gateRequest = request.bodyUsed ? request : request.clone()
  return {
    check: async ({ provider, identifier, mode }) => {
      const decision = await gate.onInitiate({
        provider,
        identifier,
        mode,
        request: gateRequest,
      })
      if (decision === "allow") return undefined
      if ("redirect" in decision) {
        return new Response(null, {
          status: 302,
          headers: { Location: decision.redirect },
        })
      }
      if (isBrowserFormPost(request)) {
        return new Response(null, {
          status: 302,
          headers: {
            Location: buildReturnUrl(
              request,
              { error: decision.error.code },
              logger,
            ),
          },
        })
      }
      return { success: false, error: decision.error }
    },
  }
}

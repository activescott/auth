import type {
  AuthContext,
  AuthInitResult,
  AuthResult,
  Challenge,
} from "./types.js"
import { AuthErrors } from "./errors.js"

// Time unit multipliers in seconds
const SECONDS_PER_MINUTE = 60
const SECONDS_PER_HOUR = 3600
const SECONDS_PER_DAY = 86_400
const MS_PER_SECOND = 1000

/** Challenge type of a merge ticket (see {@link completeLinkVerification}) */
export const MERGE_TICKET_TYPE = "account-merge"
/** Cookie binding a merge ticket to the browser that proved possession */
export const MERGE_TICKET_COOKIE_NAME = "auth_merge_ticket"
/** How long a merge ticket stays redeemable */
const MERGE_TICKET_EXPIRY_SECONDS = 10 * SECONDS_PER_MINUTE

/**
 * Parse a request body into a plain object. Handles JSON and
 * application/x-www-form-urlencoded; returns {} when the body is
 * unparseable.
 */
export async function parseRequestBody(
  request: Request,
): Promise<Record<string, unknown>> {
  const contentType = request.headers.get("content-type") ?? ""

  if (contentType.includes("application/json")) {
    return (await request.json()) as Record<string, unknown>
  }

  if (contentType.includes("application/x-www-form-urlencoded")) {
    const text = await request.text()
    const parameters = new URLSearchParams(text)
    const result: Record<string, unknown> = {}
    for (const [key, value] of parameters.entries()) {
      result[key] = value
    }
    return result
  }

  // Try to parse as JSON anyway
  try {
    return (await request.json()) as Record<string, unknown>
  } catch {
    return {}
  }
}

/**
 * True for a browser form post: urlencoded body and the client renders
 * HTML. Providers answer these with redirects; JSON/fetch callers get
 * result objects.
 */
export function isBrowserFormPost(request: Request): boolean {
  const contentType = request.headers.get("content-type") ?? ""
  const accept = request.headers.get("accept") ?? ""
  return (
    contentType.includes("application/x-www-form-urlencoded") &&
    accept.includes("text/html")
  )
}

/**
 * Where to send the browser back after a form post: the submitting page
 * (Referer) with the given query params merged in, falling back to
 * /login.
 */
export function buildReturnUrl(
  request: Request,
  params: Record<string, string>,
): string {
  const referer = request.headers.get("referer")
  let url: URL
  try {
    url = new URL(referer ?? "/login", request.url)
  } catch {
    url = new URL("/login", request.url)
  }
  for (const [name, value] of Object.entries(params)) {
    url.searchParams.set(name, value)
  }
  return url.toString()
}

/**
 * The "we've sent it" answer to an initiate request: a redirect back to the
 * submitting page with ?sent=1 for browser form posts, the AuthInitResult for
 * everyone else.
 *
 * Shared by the providers' success paths and by the silent block that abuse
 * protection returns, so a caller cannot distinguish a message that was sent
 * from one that was suppressed. Pass no cookies for the suppressed case —
 * there is no challenge to bind.
 */
export function initiateAccepted(
  request: Request,
  message: string,
  setCookies: string[] = [],
): AuthInitResult | Response {
  if (isBrowserFormPost(request)) {
    const headers = new Headers({
      Location: buildReturnUrl(request, { sent: "1" }),
    })
    for (const cookie of setCookies) {
      headers.append("Set-Cookie", cookie)
    }
    return new Response(null, { status: 302, headers })
  }

  return { success: true, message, setCookies }
}

/**
 * Build the Set-Cookie value binding a challenge to the browser that
 * initiated it. HttpOnly, SameSite=Lax, scoped to /auth; Secure when the
 * app runs on https.
 */
export function buildChallengeCookie(
  name: string,
  challengeId: string,
  maxAgeSeconds: number,
  baseUrl: string,
): string {
  const secure = baseUrl.startsWith("https://") ? "; Secure" : ""
  return `${name}=${challengeId}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure}`
}

/**
 * Build a Set-Cookie value that clears a challenge cookie
 */
export function buildChallengeClearingCookie(
  name: string,
  baseUrl: string,
): string {
  const secure = baseUrl.startsWith("https://") ? "; Secure" : ""
  return `${name}=; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=0${secure}`
}

/**
 * Read a cookie value from the request's Cookie header. Returns null when
 * the cookie is absent or empty.
 */
export function readCookie(request: Request, name: string): string | null {
  const cookieHeader = request.headers.get("Cookie")
  if (!cookieHeader) return null

  const cookies = cookieHeader.split(";").map((part) => part.trim())
  const target = cookies.find((part) => part.startsWith(`${name}=`))
  if (!target) return null

  const value = target.slice(name.length + 1)
  return value || null
}

/**
 * Parse a duration string like "30d", "24h", "15m", or "3600s" to
 * seconds. Returns 0 for unrecognized input.
 */
export function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)([dhms])$/)
  if (!match) return 0

  const [, valueString, unitChar] = match
  if (!valueString || !unitChar) return 0

  const value = Number.parseInt(valueString, 10)
  const multipliers: Record<string, number> = {
    s: 1,
    m: SECONDS_PER_MINUTE,
    h: SECONDS_PER_HOUR,
    d: SECONDS_PER_DAY,
  }

  return value * (multipliers[unitChar] ?? 1)
}

/**
 * Look up or create the user and identity for a verified identifier
 * (an email address, phone number, etc.). Every provider's redemption
 * paths converge here after the credential is proven; a future
 * identity-merge feature extends this single point.
 */
export async function authenticateWithIdentifier(
  providerId: string,
  identifier: string,
  context: AuthContext,
): Promise<AuthResult> {
  let identity = await context.identityStore.findByProviderAndIdentifier(
    providerId,
    identifier,
  )

  let user

  if (identity) {
    user = await context.userStore.findById(identity.userId)
    if (!user) {
      return {
        success: false,
        error: AuthErrors.userNotFound({ identifier }),
      }
    }
  } else {
    user = await context.userStore.create({
      provider: providerId,
      identifier,
    })

    identity = await context.identityStore.create({
      userId: user.id,
      provider: providerId,
      identifier,
      metadata: {},
    })
  }

  await context.identityStore.update(identity.id, {
    verifiedAt: new Date(),
  })

  return {
    success: true,
    user,
    identity,
  }
}

/**
 * The user id a link-mode challenge is bound to, or undefined for an
 * ordinary sign-in challenge. Providers stamp `data.linkUserId` at initiate
 * when the request carries `mode: "link"`, so at verify time the mode comes
 * from the stored challenge — a sign-in challenge can never be redeemed as a
 * link and vice versa.
 */
export function linkUserIdFromChallenge(
  challenge: Pick<Challenge, "data">,
): string | undefined {
  const value = challenge.data?.linkUserId
  return typeof value === "string" ? value : undefined
}

/**
 * Attach a freshly verified identifier to the signed-in user instead of
 * resolving a user from it. The link-mode counterpart of
 * {@link authenticateWithIdentifier}; providers call it after the OTP round
 * trip proves possession of the identifier.
 *
 * Outcomes:
 * - identifier unknown → an Identity is created for the session user;
 * - identifier already on the session user → verifiedAt is refreshed
 *   (idempotent);
 * - identifier on a DIFFERENT user → IDENTITY_CONFLICT, plus a short-lived
 *   single-use merge ticket bound to this browser by cookie. The app may
 *   then offer to merge the accounts; POSTing /auth/{provider}/link-merge
 *   redeems the ticket (see Auth.mergeUsers). Possession was proven by the
 *   OTP that got us here, and the ticket additionally requires the same
 *   authenticated session at redemption, so no silent takeover is possible.
 *
 * The session must still be present and belong to `linkUserId` — the user id
 * the challenge was bound to at initiate.
 */
export async function completeLinkVerification(
  providerId: string,
  identifier: string,
  linkUserId: string,
  request: Request,
  context: AuthContext,
): Promise<AuthResult> {
  if (!context.getSession) {
    return {
      success: false,
      error: AuthErrors.configurationError(
        "Identity linking requires AuthContext.getSession (upgrade @activescott/auth)",
      ),
    }
  }

  const session = await context.getSession(request)
  if (!session || session.user.id !== linkUserId) {
    return {
      success: false,
      error: AuthErrors.sessionInvalid({
        reason: "Sign in again to finish linking this identifier",
      }),
    }
  }

  const existing = await context.identityStore.findByProviderAndIdentifier(
    providerId,
    identifier,
  )

  if (!existing) {
    const created = await context.identityStore.create({
      userId: session.user.id,
      provider: providerId,
      identifier,
      metadata: {},
    })
    const identity = await context.identityStore.update(created.id, {
      verifiedAt: new Date(),
    })
    await context.userStore.onIdentityLinked?.(session.user, identity)
    return { success: true, user: session.user, identity }
  }

  if (existing.userId === session.user.id) {
    const identity = await context.identityStore.update(existing.id, {
      verifiedAt: new Date(),
    })
    return { success: true, user: session.user, identity }
  }

  const ticketId = crypto.randomUUID()
  await context.challengeStore.create({
    id: ticketId,
    type: MERGE_TICKET_TYPE,
    identifier,
    data: {
      fromUserId: existing.userId,
      intoUserId: session.user.id,
      provider: providerId,
    },
    maxAttempts: 1,
    expiresAt: new Date(
      Date.now() + MERGE_TICKET_EXPIRY_SECONDS * MS_PER_SECOND,
    ),
  })

  return {
    success: false,
    error: AuthErrors.identityConflict({ provider: providerId, identifier }),
    setCookies: [
      buildChallengeCookie(
        MERGE_TICKET_COOKIE_NAME,
        ticketId,
        MERGE_TICKET_EXPIRY_SECONDS,
        context.baseUrl,
      ),
    ],
  }
}

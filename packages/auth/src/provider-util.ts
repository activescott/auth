import type { AuthContext, AuthInitResult, AuthResult } from "./types.js"
import { AuthErrors } from "./errors.js"

// Time unit multipliers in seconds
const SECONDS_PER_MINUTE = 60
const SECONDS_PER_HOUR = 3600
const SECONDS_PER_DAY = 86_400

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

import { constantTimeEqual } from "@activescott/auth"
import {
  clientFromMetadataDocument,
  looksLikeMetadataDocumentUrl,
  metadataDocumentUrlProblem,
  normalizeHost,
} from "./client-id-metadata-document.js"
import { randomToken, sha256Hex } from "./crypto.js"
import {
  mediaType,
  readBodyText,
  singleValuedParams,
  withHeaders,
} from "./http.js"
import { isLoopbackUrl, matchesRegisteredRedirectUri } from "./redirect-uri.js"
import { addSeconds, type ServerContext } from "./server-context.js"
import type {
  AuthorizeErrorPage,
  ConsentPrompt,
  OAuthAuthorizationRequest,
  OAuthClient,
} from "./types.js"

const HTTP_FOUND = 302
const HTTP_SEE_OTHER = 303
const HTTP_METHOD_NOT_ALLOWED = 405
/** An S256 challenge is the base64url SHA-256 of the verifier: 43 characters. */
const S256_CHALLENGE = /^[A-Za-z0-9_-]{43}$/

/**
 * Sent with every authorization endpoint response, whatever the app's own
 * headers are, so the consent page cannot be framed for clickjacking and its
 * URL does not leak through `Referer`.
 */
const PAGE_HEADERS: Record<string, string> = {
  "X-Frame-Options": "DENY",
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
}

/**
 * The authorization endpoint for a signed-in user. GET validates the request
 * and renders consent; POST is the consent form's answer.
 */
export async function handleAuthorization(
  context: ServerContext,
  request: Request,
  userId: string,
): Promise<Response> {
  let response: Response
  if (request.method === "GET") {
    response = await beginAuthorization(context, request, userId)
  } else if (request.method === "POST") {
    response = await completeAuthorization(context, request, userId)
  } else {
    response = new Response(null, {
      status: HTTP_METHOD_NOT_ALLOWED,
      headers: { Allow: "GET, POST" },
    })
  }
  const framed = withHeaders(response, PAGE_HEADERS)
  // Appended, not set: a second policy can only narrow the app's own CSP.
  framed.headers.append("Content-Security-Policy", "frame-ancestors 'none'")
  return framed
}

async function beginAuthorization(
  context: ServerContext,
  request: Request,
  userId: string,
): Promise<Response> {
  const parsed = singleValuedParams(new URL(request.url).searchParams)
  if ("repeated" in parsed) {
    return errorPage(context, request, {
      error: "invalid_request",
      description: `${parsed.repeated} was sent more than once`,
    })
  }
  const params = parsed.values

  const clientId = params.get("client_id")
  if (!clientId) {
    return errorPage(context, request, {
      error: "invalid_client",
      description: "client_id is missing",
    })
  }
  const client = await resolveClient(context, clientId, userId)
  if ("error" in client) return errorPage(context, request, client)

  const redirectUri = params.get("redirect_uri")
  if (
    !redirectUri ||
    !matchesRegisteredRedirectUri(redirectUri, client.redirectUris)
  ) {
    return errorPage(context, request, {
      error: "invalid_redirect_uri",
      description: "redirect_uri is missing or not registered for this client",
    })
  }

  // The client and redirect URI are trusted from here on, so errors go back
  // to the client (RFC 6749 §4.1.2.1).
  const state = params.get("state") ?? null
  const fail = (error: string, description: string) =>
    redirectToClient(context, redirectUri, HTTP_FOUND, {
      error,
      error_description: description,
      state,
    })

  if (params.get("response_type") !== "code") {
    return fail("unsupported_response_type", "response_type must be code")
  }
  const codeChallenge = params.get("code_challenge")
  if (!codeChallenge) {
    return fail("invalid_request", "code_challenge is required")
  }
  if (params.get("code_challenge_method") !== "S256") {
    return fail("invalid_request", "code_challenge_method must be S256")
  }
  if (!S256_CHALLENGE.test(codeChallenge)) {
    return fail("invalid_request", "code_challenge is not an S256 challenge")
  }
  const resource = params.get("resource")
  if (resource !== context.config.resource.uri) {
    return fail(
      "invalid_target",
      `resource must be ${context.config.resource.uri}`,
    )
  }
  const scopes = parseScopes(params.get("scope"))
  if (scopes.some((scope) => !context.config.resource.scopes.includes(scope))) {
    return fail("invalid_scope", "an unknown scope was requested")
  }
  const requestedScopes =
    scopes.length > 0 ? scopes : context.config.resource.defaultScopes
  if (!(await context.isUserActive(userId))) {
    return fail("access_denied", "this account cannot authorize applications")
  }

  const verdict = await context.rateLimiter.check(
    `oauth:authorize:user:${userId}`,
    context.rateLimits.authorizationRequestsPerUser,
  )
  if (!verdict.allowed) {
    return fail("temporarily_unavailable", "too many authorization requests")
  }

  const now = context.now()
  const csrfToken = randomToken()
  const stored: OAuthAuthorizationRequest = {
    id: randomToken(),
    userId,
    csrfTokenHash: await sha256Hex(csrfToken),
    clientId: client.clientId,
    redirectUri,
    scopes: requestedScopes,
    state,
    codeChallenge,
    resource,
    createdAt: now,
    expiresAt: addSeconds(now, context.lifetimes.authorizationRequest),
  }
  await context.config.store.createAuthorizationRequest(stored)

  return context.config.renderConsent(
    consentPrompt(context, client, stored, csrfToken),
    request,
  )
}

async function completeAuthorization(
  context: ServerContext,
  request: Request,
  userId: string,
): Promise<Response> {
  if (mediaType(request) !== "application/x-www-form-urlencoded") {
    return errorPage(context, request, {
      error: "invalid_request",
      description: "the consent form must be URL-encoded",
    })
  }
  const text = await readBodyText(request)
  const parsed =
    text === null
      ? null
      : singleValuedParams(new URLSearchParams(text), new Set(["scope"]))
  if (!parsed || "repeated" in parsed) {
    return errorPage(context, request, {
      error: "invalid_request",
      description: "the consent form is malformed",
    })
  }
  const form = parsed.values
  const requestId = form.get("request_id")
  const csrfToken = form.get("csrf_token")
  if (!requestId || !csrfToken) {
    return errorPage(context, request, {
      error: "invalid_request",
      description: "the consent form is missing its request",
    })
  }

  // Keyed by the session's user: another user's request id finds nothing.
  const stored = await context.config.store.consumeAuthorizationRequest(
    userId,
    requestId,
  )
  const now = context.now()
  if (!stored || stored.expiresAt <= now) {
    return errorPage(context, request, {
      error: "request_expired",
      description:
        "This authorization request has expired or was already answered. Start again from the application.",
    })
  }
  if (!constantTimeEqual(await sha256Hex(csrfToken), stored.csrfTokenHash)) {
    return errorPage(context, request, {
      error: "invalid_request",
      description: "the consent form failed its CSRF check",
    })
  }

  // Everything below comes from the stored request, re-checked against the
  // client as it is now; the form contributes only the decision and the
  // optional scopes the user ticked.
  const client = await context.config.store.getClient(stored.clientId)
  if (
    !client ||
    !matchesRegisteredRedirectUri(stored.redirectUri, client.redirectUris)
  ) {
    return errorPage(context, request, {
      error: "invalid_client",
      description: "the client is no longer registered",
    })
  }

  if (form.get("decision") !== "approve") {
    return redirectToClient(context, stored.redirectUri, HTTP_SEE_OTHER, {
      error: "access_denied",
      error_description: "the user denied the request",
      state: stored.state,
    })
  }
  if (!(await context.isUserActive(userId))) {
    return redirectToClient(context, stored.redirectUri, HTTP_SEE_OTHER, {
      error: "access_denied",
      error_description: "this account cannot authorize applications",
      state: stored.state,
    })
  }

  const ticked = new Set(new URLSearchParams(text!).getAll("scope"))
  const scopes = stored.scopes.filter(
    (scope) => !context.optionalScopes.has(scope) || ticked.has(scope),
  )
  if (scopes.length === 0) {
    return redirectToClient(context, stored.redirectUri, HTTP_SEE_OTHER, {
      error: "access_denied",
      error_description: "the user granted no scopes",
      state: stored.state,
    })
  }

  const code = randomToken()
  await context.config.store.createCode({
    codeHash: await sha256Hex(code),
    clientId: stored.clientId,
    userId,
    redirectUri: stored.redirectUri,
    scopes,
    resource: stored.resource,
    codeChallenge: stored.codeChallenge,
    createdAt: now,
    expiresAt: addSeconds(now, context.lifetimes.code),
    usedAt: null,
  })
  return redirectToClient(context, stored.redirectUri, HTTP_SEE_OTHER, {
    code,
    state: stored.state,
  })
}

/**
 * Find the client for a `client_id`, fetching its metadata document when it
 * is an HTTPS URL and the cached copy is missing or stale. Only this endpoint
 * fetches, and only for a signed-in user.
 */
async function resolveClient(
  context: ServerContext,
  clientId: string,
  userId: string,
): Promise<OAuthClient | AuthorizeErrorPage> {
  const { store, fetchClientMetadata } = context.config
  const stored = await store.getClient(clientId)
  if (stored && stored.kind !== "cimd") return stored

  if (!fetchClientMetadata || !looksLikeMetadataDocumentUrl(clientId)) {
    return { error: "invalid_client", description: "unknown client" }
  }
  const problem = metadataDocumentUrlProblem(clientId, context.ownHosts)
  if (problem) return { error: "invalid_client", description: problem }

  const now = context.now()
  if (stored?.metadataExpiresAt && stored.metadataExpiresAt > now) {
    return stored
  }

  for (const [key, rules] of [
    [`oauth:cimd:user:${userId}`, context.rateLimits.metadataFetchPerUser],
    ["oauth:cimd:global", context.rateLimits.metadataFetchGlobal],
  ] as const) {
    const verdict = await context.rateLimiter.check(key, rules)
    if (!verdict.allowed) {
      return {
        error: "temporarily_unavailable",
        description: "too many client lookups; try again later",
      }
    }
  }

  let fetched: Awaited<ReturnType<typeof fetchClientMetadata>>
  try {
    fetched = await fetchClientMetadata(new URL(clientId))
  } catch {
    return {
      error: "invalid_client",
      description: "the client's metadata document could not be fetched",
    }
  }
  const client = clientFromMetadataDocument(
    clientId,
    fetched.document,
    fetched.maxAgeSeconds,
    now,
  )
  if ("error" in client) {
    return { error: "invalid_client", description: client.description }
  }
  if (stored) client.createdAt = stored.createdAt
  await store.saveClient(client)
  return client
}

function consentPrompt(
  context: ServerContext,
  client: OAuthClient,
  stored: OAuthAuthorizationRequest,
  csrfToken: string,
): ConsentPrompt {
  const clientIdHost =
    client.kind === "cimd"
      ? normalizeHost(new URL(client.clientId).hostname)
      : null
  const redirectHost = normalizeHost(new URL(stored.redirectUri).hostname)
  return {
    userId: stored.userId,
    action: context.endpoints.authorization,
    fields: { request_id: stored.id, csrf_token: csrfToken },
    client: {
      clientId: client.clientId,
      kind: client.kind,
      name: client.name,
      clientIdHost,
      redirectUri: stored.redirectUri,
      redirectHost,
    },
    warnings: {
      loopbackRedirects: client.redirectUris.every((uri) =>
        isLoopbackUrl(new URL(uri)),
      ),
      redirectHostDiffers:
        clientIdHost !== null && clientIdHost !== redirectHost,
      unregisteredClient: client.kind === "dynamic",
    },
    scopes: stored.scopes.map((scope) => ({
      scope,
      optional: context.optionalScopes.has(scope),
    })),
    resource: stored.resource,
  }
}

export function parseScopes(scope: string | null | undefined): string[] {
  if (!scope) return []
  return [...new Set(scope.split(" ").filter(Boolean))]
}

async function errorPage(
  context: ServerContext,
  request: Request,
  error: AuthorizeErrorPage,
): Promise<Response> {
  return context.config.renderError(error, request)
}

/**
 * Redirect to a redirect URI that has already been matched against the
 * client's registrations, adding `iss` (RFC 9207) to every response.
 */
function redirectToClient(
  context: ServerContext,
  redirectUri: string,
  status: number,
  params: Record<string, string | null>,
): Response {
  const url = new URL(redirectUri)
  for (const [name, value] of Object.entries(params)) {
    if (value !== null) url.searchParams.append(name, value)
  }
  url.searchParams.append("iss", context.issuer)
  return new Response(null, {
    status,
    headers: { Location: url.toString() },
  })
}

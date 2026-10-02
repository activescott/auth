import { constantTimeEqual } from "@activescott/auth"
import { parseScopes } from "./authorization-endpoint.js"
import { authenticateClient } from "./client-authentication.js"
import { randomToken, s256Challenge, sha256Hex } from "./crypto.js"
import {
  jsonResponse,
  mediaType,
  oauthError,
  readBodyText,
  singleValuedParams,
} from "./http.js"
import { addSeconds, type ServerContext } from "./server-context.js"
import type { OAuthClient, OAuthGrant, OAuthToken } from "./types.js"

const HTTP_METHOD_NOT_ALLOWED = 405
const MS_PER_SECOND = 1000
/** RFC 7636 §4.1: 43 to 128 unreserved characters. */
const CODE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/

/**
 * Parse a token or revocation endpoint request: POST, URL-encoded, no
 * repeated parameters, and an authenticated client.
 */
export async function parseClientRequest(
  context: ServerContext,
  request: Request,
): Promise<
  { params: Map<string, string>; client: OAuthClient } | { response: Response }
> {
  if (request.method !== "POST") {
    return {
      response: oauthError(
        "invalid_request",
        "use POST",
        HTTP_METHOD_NOT_ALLOWED,
        {
          Allow: "POST",
        },
      ),
    }
  }
  if (mediaType(request) !== "application/x-www-form-urlencoded") {
    return {
      response: oauthError(
        "invalid_request",
        "Content-Type must be application/x-www-form-urlencoded",
      ),
    }
  }
  const text = await readBodyText(request)
  if (text === null) {
    return {
      response: oauthError("invalid_request", "request body is too large"),
    }
  }
  const parsed = singleValuedParams(new URLSearchParams(text))
  if ("repeated" in parsed) {
    return {
      response: oauthError(
        "invalid_request",
        `${parsed.repeated} was sent more than once`,
      ),
    }
  }
  const authenticated = await authenticateClient(
    context,
    request,
    parsed.values,
  )
  if ("response" in authenticated) return authenticated
  return { params: parsed.values, client: authenticated.client }
}

/**
 * The token endpoint: `authorization_code` with S256 PKCE, and rotating
 * `refresh_token`.
 */
export async function handleToken(
  context: ServerContext,
  request: Request,
): Promise<Response> {
  const parsed = await parseClientRequest(context, request)
  if ("response" in parsed) return parsed.response
  const { params, client } = parsed
  switch (params.get("grant_type")) {
    case "authorization_code":
      return redeemCode(context, params, client)
    case "refresh_token":
      return refresh(context, params, client)
    case undefined:
      return oauthError("invalid_request", "grant_type is missing")
    default:
      return oauthError("unsupported_grant_type", "grant_type is not supported")
  }
}

async function redeemCode(
  context: ServerContext,
  params: Map<string, string>,
  client: OAuthClient,
): Promise<Response> {
  const { store } = context.config
  const code = params.get("code")
  const redirectUri = params.get("redirect_uri")
  const verifier = params.get("code_verifier")
  if (!code || !redirectUri || !verifier) {
    return oauthError(
      "invalid_request",
      "code, redirect_uri and code_verifier are required",
    )
  }
  if (!CODE_VERIFIER.test(verifier)) {
    return oauthError("invalid_request", "code_verifier is malformed")
  }

  const codeHash = await sha256Hex(code)
  const stored = await store.findCode(codeHash)
  const now = context.now()
  if (!stored || stored.clientId !== client.clientId) {
    return invalidGrant("the authorization code is invalid")
  }
  if (stored.usedAt) {
    // RFC 6749 §4.1.2: a code used twice revokes what it issued.
    await store.revokeTokensForCode(codeHash, now, "code_reuse")
    return invalidGrant("the authorization code was already used")
  }
  if (stored.expiresAt <= now) {
    return invalidGrant("the authorization code has expired")
  }
  if (stored.redirectUri !== redirectUri) {
    return invalidGrant("redirect_uri does not match the authorization request")
  }
  const resource = params.get("resource")
  if (resource !== undefined && resource !== stored.resource) {
    return oauthError("invalid_target", "resource does not match the code")
  }
  if (!constantTimeEqual(await s256Challenge(verifier), stored.codeChallenge)) {
    return invalidGrant("code_verifier does not match the code_challenge")
  }
  if (!(await context.isUserActive(stored.userId))) {
    return invalidGrant("the user can no longer authorize applications")
  }
  const grant = await store.upsertGrant(
    {
      userId: stored.userId,
      clientId: stored.clientId,
      scopes: stored.scopes,
      resource: stored.resource,
    },
    now,
  )
  // Tokens are stored before the code is marked used, so a concurrent second
  // redemption that loses the conditional update revokes them too.
  const issued = await issueTokens(context, {
    grant,
    scopes: stored.scopes,
    resource: stored.resource,
    codeHash,
    rotatedFromId: null,
    refreshTokenExpiresAt: addSeconds(now, context.lifetimes.refreshToken),
    now,
  })
  // One conditional update, so two concurrent redemptions cannot both win.
  if (!(await store.markCodeUsed(codeHash, now))) {
    await store.revokeTokensForCode(codeHash, now, "code_reuse")
    return invalidGrant("the authorization code was already used")
  }
  return issued.response
}

/**
 * Rotate a refresh token. A refresh token used twice revokes the whole
 * grant, except within the grace window after its rotation when the pair
 * that rotation issued is still unused: that is a client retrying after a
 * lost response, so it gets a fresh pair and the unused pair is revoked.
 * Presenting a refresh token the grace path revoked counts as reuse.
 */
async function refresh(
  context: ServerContext,
  params: Map<string, string>,
  client: OAuthClient,
): Promise<Response> {
  const { store } = context.config
  const refreshToken = params.get("refresh_token")
  if (!refreshToken) {
    return oauthError("invalid_request", "refresh_token is required")
  }
  const refreshHash = await sha256Hex(refreshToken)
  let token = await store.findTokenByRefreshHash(refreshHash)
  const now = context.now()
  if (!token || token.clientId !== client.clientId) {
    return invalidGrant("the refresh token is invalid")
  }
  const grant = await store.getGrant(token.grantId)
  if (!grant || grant.revokedAt) {
    return invalidGrant("the grant was revoked")
  }
  if (token.revokedAt) return rejectRevoked(context, token, grant, now)
  if (token.refreshTokenExpiresAt <= now) {
    return invalidGrant("the refresh token has expired")
  }
  const resource = params.get("resource")
  if (resource !== undefined && resource !== token.resource) {
    return oauthError("invalid_target", "resource does not match the grant")
  }
  const requested = parseScopes(params.get("scope"))
  if (requested.some((scope) => !token!.scopes.includes(scope))) {
    return oauthError("invalid_scope", "scope exceeds what was granted")
  }
  const scopes = requested.length > 0 ? requested : token.scopes
  if (!(await context.isUserActive(token.userId))) {
    return invalidGrant("the user can no longer authorize applications")
  }

  const issueFrom = (from: OAuthToken) =>
    issueTokens(context, {
      grant,
      scopes,
      resource: from.resource,
      codeHash: from.codeHash,
      rotatedFromId: from.id,
      refreshTokenExpiresAt: from.refreshTokenExpiresAt,
      now,
    })

  if (token.rotatedAt === null) {
    // The new pair is stored before the rotation is marked, so a concurrent
    // request that finds this token rotated also finds the pair to revoke.
    const issued = await issueFrom(token)
    if (await store.markTokenRotated(token.id, now)) return issued.response
    await store.revokeToken(issued.tokenId, now, "grace")
    // Another request rotated or revoked it first; decide on its state now.
    token = await store.findTokenByRefreshHash(refreshHash)
    if (!token) return invalidGrant("the refresh token is invalid")
    if (token.revokedAt) return rejectRevoked(context, token, grant, now)
  }

  const rotatedAt = token.rotatedAt
  if (
    rotatedAt &&
    now.getTime() - rotatedAt.getTime() <=
      context.lifetimes.refreshReuseGrace * MS_PER_SECOND
  ) {
    const unrevoked = (await store.findTokensRotatedFrom(token.id)).filter(
      (child) => !child.revokedAt,
    )
    let unused = true
    for (const child of unrevoked) {
      if (!(await store.revokeUnrotatedToken(child.id, now))) unused = false
    }
    if (unused) return (await issueFrom(token)).response
  }

  await store.revokeGrant(grant.id, now)
  return invalidGrant("the refresh token was already used")
}

async function rejectRevoked(
  context: ServerContext,
  token: OAuthToken,
  grant: OAuthGrant,
  now: Date,
): Promise<Response> {
  if (token.revokedReason === "grace") {
    await context.config.store.revokeGrant(grant.id, now)
  }
  return invalidGrant("the refresh token was revoked")
}

async function issueTokens(
  context: ServerContext,
  input: {
    grant: OAuthGrant
    scopes: string[]
    resource: string
    codeHash: string
    rotatedFromId: string | null
    refreshTokenExpiresAt: Date
    now: Date
  },
): Promise<{ tokenId: string; response: Response }> {
  const accessToken = randomToken(context.accessTokenPrefix)
  const refreshToken = randomToken(context.refreshTokenPrefix)
  const { grant, now } = input
  const tokenId = crypto.randomUUID()
  await context.config.store.createToken({
    id: tokenId,
    grantId: grant.id,
    clientId: grant.clientId,
    userId: grant.userId,
    accessTokenHash: await sha256Hex(accessToken),
    refreshTokenHash: await sha256Hex(refreshToken),
    scopes: input.scopes,
    resource: input.resource,
    accessTokenExpiresAt: addSeconds(now, context.lifetimes.accessToken),
    refreshTokenExpiresAt: input.refreshTokenExpiresAt,
    codeHash: input.codeHash,
    rotatedFromId: input.rotatedFromId,
    rotatedAt: null,
    revokedAt: null,
    revokedReason: null,
    createdAt: now,
  })
  await context.config.store.touchGrant(grant.id, now)
  return {
    tokenId,
    response: jsonResponse({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: context.lifetimes.accessToken,
      refresh_token: refreshToken,
      scope: input.scopes.join(" "),
    }),
  }
}

function invalidGrant(description: string): Response {
  return oauthError("invalid_grant", description)
}

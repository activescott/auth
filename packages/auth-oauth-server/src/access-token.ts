import { sha256Hex } from "./crypto.js"
import { protectedResourceMetadataUrl } from "./metadata.js"
import type { ServerContext } from "./server-context.js"
import type { OAuthToken } from "./types.js"

const HTTP_UNAUTHORIZED = 401
const HTTP_FORBIDDEN = 403

/** A verified bearer token and who it acts for. */
export interface VerifiedAccessToken {
  ok: true
  userId: string
  clientId: string
  grantId: string
  scopes: string[]
  token: OAuthToken
}

/** A rejected request, with the 401 or 403 to send back. */
export interface RejectedAccessToken {
  ok: false
  response: Response
}

/**
 * Verify the bearer token on a request to the protected resource: hash
 * lookup, expiry, revocation of the token and its grant, audience equal to
 * the configured resource, the user still active, and the required scopes.
 * A missing scope answers 403 `insufficient_scope` naming the scopes needed,
 * so the client can step up; everything else answers 401 with
 * `resource_metadata` so the client can discover the authorization server.
 */
export async function verifyAccessToken(
  context: ServerContext,
  request: Request,
  requiredScopes: string[],
): Promise<VerifiedAccessToken | RejectedAccessToken> {
  const match = /^Bearer\s+(\S+)$/i.exec(
    request.headers.get("authorization") ?? "",
  )
  if (!match) return unauthorized(context, null)

  const { store } = context.config
  const token = await store.findTokenByAccessHash(await sha256Hex(match[1]!))
  const now = context.now()
  if (!token || token.revokedAt || token.accessTokenExpiresAt <= now) {
    return unauthorized(context, "the access token is invalid or expired")
  }
  if (token.resource !== context.config.resource.uri) {
    return unauthorized(context, "the access token is for another resource")
  }
  const grant = await store.getGrant(token.grantId)
  if (!grant || grant.revokedAt) {
    return unauthorized(context, "the access token was revoked")
  }
  if (!(await context.isUserActive(token.userId))) {
    return unauthorized(context, "the user can no longer use this application")
  }
  const missing = requiredScopes.filter(
    (scope) => !token.scopes.includes(scope),
  )
  if (missing.length > 0) {
    // The union, so a client that replaces its scopes on step-up keeps the
    // ones it already had.
    const scope = [...new Set([...token.scopes, ...requiredScopes])].join(" ")
    return {
      ok: false,
      response: new Response(null, {
        status: HTTP_FORBIDDEN,
        headers: {
          "WWW-Authenticate": challenge(context, {
            error: "insufficient_scope",
            scope,
          }),
        },
      }),
    }
  }
  await store.touchGrant(grant.id, now)
  return {
    ok: true,
    userId: token.userId,
    clientId: token.clientId,
    grantId: token.grantId,
    scopes: token.scopes,
    token,
  }
}

/**
 * The 401 for a request with no usable token. Without a token the challenge
 * carries no error code (RFC 6750 §3.1); with a bad one it is `invalid_token`.
 */
export function unauthorized(
  context: ServerContext,
  errorDescription: string | null,
): RejectedAccessToken {
  const fields: Record<string, string> = {
    scope: context.config.resource.defaultScopes.join(" "),
  }
  if (errorDescription) {
    fields.error = "invalid_token"
    fields.error_description = errorDescription
  }
  return {
    ok: false,
    response: new Response(null, {
      status: HTTP_UNAUTHORIZED,
      headers: { "WWW-Authenticate": challenge(context, fields) },
    }),
  }
}

function challenge(
  context: ServerContext,
  fields: Record<string, string>,
): string {
  const all: Record<string, string> = {
    ...fields,
    resource_metadata: protectedResourceMetadataUrl(
      context.config.resource.uri,
    ),
  }
  const params = Object.entries(all).map(
    ([name, value]) => `${name}="${value.replace(/["\\]/g, "")}"`,
  )
  return `Bearer ${params.join(", ")}`
}

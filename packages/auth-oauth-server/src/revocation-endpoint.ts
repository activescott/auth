import { sha256Hex } from "./crypto.js"
import { oauthError } from "./http.js"
import type { ServerContext } from "./server-context.js"
import { parseClientRequest } from "./token-endpoint.js"

/**
 * RFC 7009 token revocation. Revoking a refresh token revokes every token
 * descended from the same authorization code; revoking an access token
 * revokes it and the refresh token issued with it. A token that is unknown
 * or belongs to another client is ignored, and the answer is 200 either
 * way, so the endpoint cannot be used to probe for valid tokens.
 */
export async function handleRevocation(
  context: ServerContext,
  request: Request,
): Promise<Response> {
  const parsed = await parseClientRequest(context, request)
  if ("response" in parsed) return parsed.response
  const { params, client } = parsed
  const token = params.get("token")
  if (!token) return oauthError("invalid_request", "token is required")

  const { store } = context.config
  const hash = await sha256Hex(token)
  const now = context.now()
  const lookups =
    params.get("token_type_hint") === "access_token"
      ? [findAccess, findRefresh]
      : [findRefresh, findAccess]
  for (const lookup of lookups) {
    const found = await lookup(hash)
    if (!found) continue
    if (found.token.clientId === client.clientId) {
      if (found.kind === "refresh") {
        await store.revokeTokensForCode(found.token.codeHash, now, "client")
      } else {
        await store.revokeToken(found.token.id, now, "client")
      }
    }
    break
  }
  return new Response(null, {
    status: 200,
    headers: { "Cache-Control": "no-store", Pragma: "no-cache" },
  })

  async function findAccess(hash: string) {
    const found = await store.findTokenByAccessHash(hash)
    return found ? { kind: "access" as const, token: found } : null
  }
  async function findRefresh(hash: string) {
    const found = await store.findTokenByRefreshHash(hash)
    return found ? { kind: "refresh" as const, token: found } : null
  }
}

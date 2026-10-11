import { constantTimeEqual } from "@activescott/auth"
import { sha256Hex } from "./crypto.js"
import { oauthError } from "./http.js"
import type { ServerContext } from "./server-context.js"
import type { OAuthClient } from "./types.js"

const HTTP_UNAUTHORIZED = 401

/**
 * Authenticate the client at the token or revocation endpoint (RFC 6749
 * §2.3). A public client (`none`) identifies itself with `client_id` alone;
 * a confidential client must present its secret by HTTP Basic or in the
 * body, not both. Only stored clients count: this never fetches a metadata
 * document, so a `client_id` the authorization endpoint has not stored is
 * `invalid_client`.
 */
export async function authenticateClient(
  context: ServerContext,
  request: Request,
  params: Map<string, string>,
): Promise<{ client: OAuthClient } | { response: Response }> {
  const bodyClientId = params.get("client_id") || null
  const bodySecret = params.get("client_secret") || null
  const basic = /^Basic\s+(\S+)$/i.exec(
    request.headers.get("authorization") ?? "",
  )

  if (basic) {
    if (bodySecret) {
      return {
        response: oauthError(
          "invalid_request",
          "use only one client authentication method",
        ),
      }
    }
    const credentials = decodeBasic(basic[1]!)
    if (!credentials) return unauthorized(true)
    if (bodyClientId && bodyClientId !== credentials.clientId) {
      return {
        response: oauthError("invalid_request", "client_id does not match"),
      }
    }
    const client = await context.config.store.getClient(credentials.clientId)
    if (!client || !(await secretMatches(client, credentials.secret))) {
      return unauthorized(true)
    }
    return { client }
  }

  if (!bodyClientId) return unauthorized(false)
  const client = await context.config.store.getClient(bodyClientId)
  if (!client) return unauthorized(false)
  if (client.tokenEndpointAuthMethod === "none") {
    return bodySecret ? unauthorized(false) : { client }
  }
  if (!bodySecret || !(await secretMatches(client, bodySecret))) {
    return unauthorized(false)
  }
  return { client }
}

async function secretMatches(
  client: OAuthClient,
  secret: string,
): Promise<boolean> {
  if (client.tokenEndpointAuthMethod === "none" || !client.clientSecretHash) {
    return false
  }
  return constantTimeEqual(await sha256Hex(secret), client.clientSecretHash)
}

/**
 * Decode `Authorization: Basic`, whose id and secret are each form-URL-encoded
 * before joining (RFC 6749 §2.3.1).
 */
function decodeBasic(
  encoded: string,
): { clientId: string; secret: string } | null {
  try {
    const decoded = atob(encoded)
    const colon = decoded.indexOf(":")
    if (colon < 0) return null
    const formDecode = (value: string) =>
      decodeURIComponent(value.replace(/\+/g, " "))
    return {
      clientId: formDecode(decoded.slice(0, colon)),
      secret: formDecode(decoded.slice(colon + 1)),
    }
  } catch {
    return null
  }
}

function unauthorized(usedBasic: boolean): { response: Response } {
  return {
    response: oauthError(
      "invalid_client",
      "client authentication failed",
      HTTP_UNAUTHORIZED,
      usedBasic ? { "WWW-Authenticate": 'Basic realm="oauth"' } : {},
    ),
  }
}

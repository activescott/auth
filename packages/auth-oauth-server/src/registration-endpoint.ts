import {
  isClientMetadataError,
  validateClientMetadata,
} from "./client-metadata.js"
import { isReservedClientName } from "./client-name.js"
import { randomToken, sha256Hex } from "./crypto.js"
import { jsonResponse, mediaType, oauthError, readBodyText } from "./http.js"
import type { ServerContext } from "./server-context.js"
import type { OAuthClient } from "./types.js"

const HTTP_CREATED = 201
const HTTP_METHOD_NOT_ALLOWED = 405
const HTTP_TOO_MANY_REQUESTS = 429
const MS_PER_SECOND = 1000

/**
 * RFC 7591 Dynamic Client Registration. Public clients (`none`) are allowed.
 * `clientIp` must be the address the app's own proxy observed, never a
 * client-supplied `X-Forwarded-For`.
 */
export async function handleRegistration(
  context: ServerContext,
  request: Request,
  clientIp: string | null,
): Promise<Response> {
  if (!context.dynamicRegistration) {
    return oauthError(
      "invalid_request",
      "dynamic registration is disabled",
      404,
    )
  }
  if (request.method !== "POST") {
    return oauthError("invalid_request", "use POST", HTTP_METHOD_NOT_ALLOWED, {
      Allow: "POST",
    })
  }
  if (mediaType(request) !== "application/json") {
    return oauthError(
      "invalid_client_metadata",
      "Content-Type must be application/json",
    )
  }

  const verdict = await context.rateLimiter.check(
    `oauth:register:ip:${clientIp ?? "unknown"}`,
    context.rateLimits.registrationPerIp,
  )
  if (!verdict.allowed) {
    return oauthError(
      "too_many_requests",
      "too many registrations; try again later",
      HTTP_TOO_MANY_REQUESTS,
      { "Retry-After": String(verdict.retryAfterSeconds) },
    )
  }

  const text = await readBodyText(request)
  if (text === null) {
    return oauthError("invalid_client_metadata", "request body is too large")
  }
  let body: unknown
  try {
    body = JSON.parse(text)
  } catch {
    return oauthError("invalid_client_metadata", "request body is not JSON")
  }

  const metadata = validateClientMetadata(body, "client_secret_basic")
  if (isClientMetadataError(metadata)) {
    return oauthError(metadata.error, metadata.description)
  }
  if (
    metadata.name &&
    isReservedClientName(metadata.name, context.reservedClientNames)
  ) {
    return oauthError(
      "invalid_client_metadata",
      "client_name is reserved for a registered client",
    )
  }

  const now = context.now()
  const clientId = randomToken(context.dynamicClientIdPrefix)
  const confidential = metadata.tokenEndpointAuthMethod !== "none"
  const clientSecret = confidential ? randomToken() : null
  const client: OAuthClient = {
    clientId,
    kind: "dynamic",
    applicationType: metadata.applicationType,
    name: metadata.name,
    redirectUris: metadata.redirectUris,
    tokenEndpointAuthMethod: metadata.tokenEndpointAuthMethod,
    clientSecretHash: clientSecret ? await sha256Hex(clientSecret) : null,
    createdAt: now,
    metadataFetchedAt: null,
    metadataExpiresAt: null,
  }
  await context.config.store.saveClient(client)

  return jsonResponse(
    {
      client_id: clientId,
      client_id_issued_at: Math.floor(now.getTime() / MS_PER_SECOND),
      ...(clientSecret
        ? { client_secret: clientSecret, client_secret_expires_at: 0 }
        : {}),
      ...(client.name ? { client_name: client.name } : {}),
      redirect_uris: client.redirectUris,
      application_type: client.applicationType,
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    },
    HTTP_CREATED,
  )
}

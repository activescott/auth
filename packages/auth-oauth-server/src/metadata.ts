import type { ServerContext } from "./server-context.js"

const PROTECTED_RESOURCE_WELL_KNOWN = "/.well-known/oauth-protected-resource"
const AUTHORIZATION_SERVER_WELL_KNOWN =
  "/.well-known/oauth-authorization-server"

/**
 * Where the protected resource metadata for `resource` lives (RFC 9728 §3.1):
 * the well-known path inserted between the host and the resource's path, so
 * `https://example.com/mcp` gets
 * `https://example.com/.well-known/oauth-protected-resource/mcp`.
 */
export function protectedResourceMetadataUrl(resource: string): string {
  const url = new URL(resource)
  const path = url.pathname === "/" ? "" : url.pathname
  return `${url.origin}${PROTECTED_RESOURCE_WELL_KNOWN}${path}`
}

/**
 * Where the authorization server metadata for `issuer` lives (RFC 8414 §3.1).
 */
export function authorizationServerMetadataUrl(issuer: string): string {
  const url = new URL(issuer)
  const path = url.pathname === "/" ? "" : url.pathname.replace(/\/+$/, "")
  return `${url.origin}${AUTHORIZATION_SERVER_WELL_KNOWN}${path}`
}

/** RFC 9728 protected resource metadata. */
export function protectedResourceMetadata(
  context: ServerContext,
): Record<string, unknown> {
  const { resource } = context.config
  return {
    resource: resource.uri,
    authorization_servers: [context.issuer],
    scopes_supported: resource.scopes,
    bearer_methods_supported: ["header"],
    ...(resource.name ? { resource_name: resource.name } : {}),
  }
}

/** RFC 8414 authorization server metadata. */
export function authorizationServerMetadata(
  context: ServerContext,
): Record<string, unknown> {
  const authMethods = ["none", "client_secret_basic", "client_secret_post"]
  return {
    issuer: context.issuer,
    authorization_endpoint: context.endpoints.authorization,
    token_endpoint: context.endpoints.token,
    ...(context.dynamicRegistration
      ? { registration_endpoint: context.endpoints.registration }
      : {}),
    revocation_endpoint: context.endpoints.revocation,
    scopes_supported: context.config.resource.scopes,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: authMethods,
    revocation_endpoint_auth_methods_supported: authMethods,
    client_id_metadata_document_supported: Boolean(
      context.config.fetchClientMetadata,
    ),
    authorization_response_iss_parameter_supported: true,
  }
}

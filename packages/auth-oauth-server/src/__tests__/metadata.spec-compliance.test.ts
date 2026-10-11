/**
 * Metadata spec compliance:
 * - RFC 9728 OAuth 2.0 Protected Resource Metadata
 * - RFC 8414 OAuth 2.0 Authorization Server Metadata
 * - MCP authorization (2026-07-28): S256 only, CIMD, `iss` in responses
 */
import { describe, expect, it } from "vitest"
import {
  authorizationServerMetadataUrl,
  protectedResourceMetadataUrl,
} from "../metadata.js"
import { createTestServer, ISSUER, RESOURCE } from "./helpers.js"

describe("Protected Resource Metadata (RFC 9728)", () => {
  /** RFC 9728 §3.1: the well-known suffix goes between host and path. */
  it("lives at the well-known path inserted before the resource path", () => {
    expect(protectedResourceMetadataUrl(RESOURCE)).toBe(
      "https://app.example/.well-known/oauth-protected-resource/mcp",
    )
    const t = createTestServer()
    expect(t.server.protectedResourceMetadataUrl).toBe(
      "https://app.example/.well-known/oauth-protected-resource/mcp",
    )
  })

  /** RFC 9728 §2: `resource` REQUIRED, and must match the resource URI. */
  it("names the resource, its authorization server, scopes and bearer method", async () => {
    const t = createTestServer()
    const response = t.server.handleProtectedResourceMetadata()
    expect(response.headers.get("Content-Type")).toBe("application/json")
    expect(await response.json()).toEqual({
      resource: RESOURCE,
      authorization_servers: [ISSUER],
      scopes_supported: ["files:read", "files:write"],
      bearer_methods_supported: ["header"],
    })
  })
})

describe("Authorization Server Metadata (RFC 8414)", () => {
  it("lives at /.well-known/oauth-authorization-server", () => {
    expect(authorizationServerMetadataUrl(ISSUER)).toBe(
      "https://app.example/.well-known/oauth-authorization-server",
    )
    expect(authorizationServerMetadataUrl("https://app.example/tenant/")).toBe(
      "https://app.example/.well-known/oauth-authorization-server/tenant",
    )
  })

  /** RFC 8414 §3.3: `issuer` must be identical to the issuer the client used. */
  it("states the issuer and endpoints", () => {
    const metadata = createTestServer().server.authorizationServerMetadata()
    expect(metadata.issuer).toBe(ISSUER)
    expect(metadata.authorization_endpoint).toBe(`${ISSUER}/oauth/authorize`)
    expect(metadata.token_endpoint).toBe(`${ISSUER}/oauth/token`)
    expect(metadata.registration_endpoint).toBe(`${ISSUER}/oauth/register`)
    expect(metadata.revocation_endpoint).toBe(`${ISSUER}/oauth/revoke`)
  })

  /** MCP: PKCE with S256 is required; `plain` is never advertised. */
  it("advertises only S256 for PKCE", () => {
    const metadata = createTestServer().server.authorizationServerMetadata()
    expect(metadata.code_challenge_methods_supported).toEqual(["S256"])
  })

  it("advertises the code flow, refresh tokens, and client auth methods", () => {
    const metadata = createTestServer().server.authorizationServerMetadata()
    expect(metadata.response_types_supported).toEqual(["code"])
    expect(metadata.grant_types_supported).toEqual([
      "authorization_code",
      "refresh_token",
    ])
    expect(metadata.token_endpoint_auth_methods_supported).toEqual([
      "none",
      "client_secret_basic",
      "client_secret_post",
    ])
    expect(metadata.scopes_supported).toEqual(["files:read", "files:write"])
  })

  /** RFC 9207 §3: the server advertises that it sends `iss`. */
  it("advertises the iss authorization response parameter", () => {
    const metadata = createTestServer().server.authorizationServerMetadata()
    expect(metadata.authorization_response_iss_parameter_supported).toBe(true)
  })

  it("advertises CIMD only when a metadata fetcher is configured", () => {
    expect(
      createTestServer().server.authorizationServerMetadata()
        .client_id_metadata_document_supported,
    ).toBe(true)
    expect(
      createTestServer({
        fetchClientMetadata: undefined,
      }).server.authorizationServerMetadata()
        .client_id_metadata_document_supported,
    ).toBe(false)
  })

  it("omits registration_endpoint when dynamic registration is off", () => {
    const metadata = createTestServer({
      dynamicRegistration: false,
    }).server.authorizationServerMetadata()
    expect(metadata).not.toHaveProperty("registration_endpoint")
  })

  /** No OIDC until it is built: no id_token, JWKS or userinfo. */
  it("does not claim OpenID Connect", () => {
    const metadata = createTestServer().server.authorizationServerMetadata()
    expect(metadata).not.toHaveProperty("jwks_uri")
    expect(metadata).not.toHaveProperty("userinfo_endpoint")
    expect(metadata).not.toHaveProperty("id_token_signing_alg_values_supported")
  })
})

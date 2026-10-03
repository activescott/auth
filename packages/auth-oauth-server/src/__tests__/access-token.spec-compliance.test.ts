/**
 * Protected resource checks:
 * - RFC 6750 §3 WWW-Authenticate for bearer tokens
 * - RFC 9728 §5.1 `resource_metadata` in the challenge
 * - RFC 8707 audience binding
 * - MCP authorization (2026-07-28): 403 insufficient_scope for step-up
 */
import { describe, expect, it } from "vitest"
import {
  createTestServer,
  obtainTokens,
  RESOURCE,
  resourceRequest,
} from "./helpers.js"

const METADATA = `resource_metadata="https://app.example/.well-known/oauth-protected-resource/mcp"`

describe("Access token verification", () => {
  it("accepts a valid token and says who it acts for", async () => {
    const t = createTestServer()
    const { accessToken, clientId } = await obtainTokens(t)
    const result = await t.server.verifyAccessToken(
      resourceRequest(accessToken),
      {
        scopes: ["files:read"],
      },
    )
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.userId).toBe("user-1")
    expect(result.clientId).toBe(clientId)
    expect(result.scopes).toEqual(["files:read"])
    expect(result.grantId).toBe([...t.store.grants.values()][0]!.id)
  })

  it("records when the grant was last used", async () => {
    const t = createTestServer()
    const { accessToken } = await obtainTokens(t)
    t.clock.advance(600)
    await t.server.verifyAccessToken(resourceRequest(accessToken))
    expect([...t.store.grants.values()][0]!.lastUsedAt).toEqual(t.clock.now)
  })

  /** RFC 6750 §3.1: no error code when the request has no authentication. */
  it("challenges a request without a token, naming the metadata and default scope", async () => {
    const t = createTestServer()
    const result = await t.server.verifyAccessToken(resourceRequest())
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.response.status).toBe(401)
    const challenge = result.response.headers.get("WWW-Authenticate")!
    expect(challenge).toMatch(/^Bearer /)
    expect(challenge).toContain(METADATA)
    expect(challenge).toContain(`scope="files:read"`)
    expect(challenge).not.toContain("error=")
  })

  it.each([
    ["an unknown token", "oat_unknown"],
    ["a non-bearer scheme", null],
  ])("rejects %s", async (_label, token) => {
    const t = createTestServer()
    await obtainTokens(t)
    const request =
      token === null
        ? new Request(RESOURCE, { headers: { Authorization: "Basic abc" } })
        : resourceRequest(token)
    const result = await t.server.verifyAccessToken(request)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.response.status).toBe(401)
  })

  it("answers invalid_token for an expired token", async () => {
    const t = createTestServer()
    const { accessToken } = await obtainTokens(t)
    t.clock.advance(3600)
    const result = await t.server.verifyAccessToken(
      resourceRequest(accessToken),
    )
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.response.headers.get("WWW-Authenticate")).toContain(
      `error="invalid_token"`,
    )
  })

  /** RFC 8707: a token issued for one resource is refused by another. */
  it("refuses a token whose audience is another resource", async () => {
    const t = createTestServer()
    const { accessToken } = await obtainTokens(t)
    const other = createTestServer({
      store: t.store,
      resource: {
        uri: "https://app.example/api",
        scopes: ["files:read"],
        defaultScopes: ["files:read"],
      },
    })
    const result = await other.server.verifyAccessToken(
      new Request("https://app.example/api", {
        headers: { Authorization: `Bearer ${accessToken}` },
      }),
    )
    expect(result.ok).toBe(false)
  })

  it("refuses a token after Disconnect revokes its grant", async () => {
    const t = createTestServer()
    const { accessToken } = await obtainTokens(t)
    const grant = [...t.store.grants.values()][0]!
    await t.server.revokeGrant("user-1", grant.id)
    const result = await t.server.verifyAccessToken(
      resourceRequest(accessToken),
    )
    expect(result.ok).toBe(false)
  })

  it("refuses a token for a blocked user at once", async () => {
    const t = createTestServer()
    const { accessToken } = await obtainTokens(t)
    t.blockedUsers.add("user-1")
    const result = await t.server.verifyAccessToken(
      resourceRequest(accessToken),
    )
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.response.status).toBe(401)
  })

  it("answers 403 insufficient_scope with the scope needed for step-up", async () => {
    const t = createTestServer()
    const { accessToken } = await obtainTokens(t)
    const result = await t.server.verifyAccessToken(
      resourceRequest(accessToken),
      {
        scopes: ["files:write"],
      },
    )
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.response.status).toBe(403)
    const challenge = result.response.headers.get("WWW-Authenticate")!
    expect(challenge).toContain(`error="insufficient_scope"`)
    expect(challenge).toContain(`scope="files:read files:write"`)
    expect(challenge).toContain(METADATA)
  })
})

describe("Connected apps", () => {
  it("lists the user's grants with the client's name and host", async () => {
    const t = createTestServer()
    const { clientId } = await obtainTokens(t)
    const apps = await t.server.listConnectedApps("user-1")
    expect(apps).toHaveLength(1)
    expect(apps[0]!.client).toEqual({
      clientId,
      kind: "dynamic",
      name: "Test Client",
      host: "client.example",
    })
    expect(await t.server.listConnectedApps("user-2")).toEqual([])
  })

  it("drops a grant from the list once revoked", async () => {
    const t = createTestServer()
    await obtainTokens(t)
    const grant = [...t.store.grants.values()][0]!
    await t.server.revokeGrant("user-1", grant.id)
    expect(await t.server.listConnectedApps("user-1")).toEqual([])
  })

  it("refuses to revoke another user's grant", async () => {
    const t = createTestServer()
    const { accessToken } = await obtainTokens(t)
    const grant = [...t.store.grants.values()][0]!
    expect(await t.server.revokeGrant("user-2", grant.id)).toBe(false)
    expect(
      (await t.server.verifyAccessToken(resourceRequest(accessToken))).ok,
    ).toBe(true)
  })
})

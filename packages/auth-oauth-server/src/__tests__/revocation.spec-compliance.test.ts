/**
 * Revocation endpoint spec compliance:
 * - RFC 7009 OAuth 2.0 Token Revocation
 */
import { describe, expect, it } from "vitest"
import {
  createTestServer,
  ISSUER,
  obtainTokens,
  refreshRequest,
  registerClient,
  resourceRequest,
  type TestServer,
} from "./helpers.js"

function revoke(t: TestServer, params: Record<string, string>) {
  return t.server.handleRevocation(
    new Request(`${ISSUER}/oauth/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params).toString(),
    }),
  )
}

async function accessWorks(t: TestServer, accessToken: string) {
  return (await t.server.verifyAccessToken(resourceRequest(accessToken))).ok
}

describe("Token revocation (RFC 7009)", () => {
  /** §2.2: revoking a refresh token invalidates access tokens from the same grant. */
  it("revokes a refresh token and every token descended from the same code", async () => {
    const t = createTestServer()
    const first = await obtainTokens(t)
    const rotated = (await (
      await t.server.handleToken(
        refreshRequest(first.clientId, first.refreshToken),
      )
    ).json()) as { access_token: string; refresh_token: string }

    const response = await revoke(t, {
      client_id: first.clientId,
      token: rotated.refresh_token,
      token_type_hint: "refresh_token",
    })
    expect(response.status).toBe(200)
    expect(await accessWorks(t, first.accessToken)).toBe(false)
    expect(await accessWorks(t, rotated.access_token)).toBe(false)
    const refreshed = await t.server.handleToken(
      refreshRequest(first.clientId, rotated.refresh_token),
    )
    expect(((await refreshed.json()) as { error: string }).error).toBe(
      "invalid_grant",
    )
  })

  it("revokes an access token", async () => {
    const t = createTestServer()
    const first = await obtainTokens(t)
    const response = await revoke(t, {
      client_id: first.clientId,
      token: first.accessToken,
      token_type_hint: "access_token",
    })
    expect(response.status).toBe(200)
    expect(await accessWorks(t, first.accessToken)).toBe(false)
  })

  it("finds the token whatever the hint says", async () => {
    const t = createTestServer()
    const first = await obtainTokens(t)
    await revoke(t, {
      client_id: first.clientId,
      token: first.accessToken,
      token_type_hint: "refresh_token",
    })
    expect(await accessWorks(t, first.accessToken)).toBe(false)
  })

  /** §2.2: invalid tokens get 200, so the endpoint cannot probe for valid ones. */
  it("answers 200 for an unknown token", async () => {
    const t = createTestServer()
    const { client_id: clientId } = await registerClient(t)
    const response = await revoke(t, { client_id: clientId!, token: "nope" })
    expect(response.status).toBe(200)
  })

  /** §2.1: the server verifies the token was issued to the requesting client. */
  it("ignores another client's token", async () => {
    const t = createTestServer()
    const first = await obtainTokens(t)
    const other = await registerClient(t)
    const response = await revoke(t, {
      client_id: other.client_id!,
      token: first.refreshToken,
    })
    expect(response.status).toBe(200)
    expect(await accessWorks(t, first.accessToken)).toBe(true)
  })

  it("requires client authentication", async () => {
    const t = createTestServer()
    const first = await obtainTokens(t)
    const response = await revoke(t, { token: first.accessToken })
    expect(response.status).toBe(401)
    expect(await accessWorks(t, first.accessToken)).toBe(true)
  })

  it("requires token", async () => {
    const t = createTestServer()
    const { client_id: clientId } = await registerClient(t)
    const response = await revoke(t, { client_id: clientId! })
    expect(response.status).toBe(400)
  })

  it("does not count a revoked refresh token as reuse", async () => {
    const t = createTestServer()
    const first = await obtainTokens(t)
    await revoke(t, { client_id: first.clientId, token: first.refreshToken })
    await t.server.handleToken(
      refreshRequest(first.clientId, first.refreshToken),
    )
    expect([...t.store.grants.values()][0]!.revokedAt).toBeNull()
  })
})

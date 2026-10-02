/**
 * Token endpoint spec compliance, refresh_token grant:
 * - RFC 6749 §6 refreshing an access token
 * - OAuth 2.1 §4.3.1 refresh token rotation and reuse detection
 * - RFC 8707 §2.2 resource on refresh
 * - Lost-response exception: reuse within 60 seconds of rotation, while the
 *   rotated pair is unused, gets a fresh pair instead of revoking the grant
 */
import { describe, expect, it } from "vitest"
import {
  createTestServer,
  obtainTokens,
  refreshRequest,
  registerClient,
  RESOURCE,
  resourceRequest,
  type TestServer,
} from "./helpers.js"

interface TokenBody {
  access_token: string
  refresh_token: string
  scope: string
  error?: string
}

async function refresh(
  t: TestServer,
  clientId: string,
  refreshToken: string,
  extra: Record<string, string> = {},
): Promise<{ status: number; body: TokenBody }> {
  const response = await t.server.handleToken(
    refreshRequest(clientId, refreshToken, extra),
  )
  return { status: response.status, body: (await response.json()) as TokenBody }
}

async function accessWorks(
  t: TestServer,
  accessToken: string,
): Promise<boolean> {
  return (await t.server.verifyAccessToken(resourceRequest(accessToken))).ok
}

describe("Token endpoint: refresh_token (RFC 6749 §6)", () => {
  it("rotates: returns a new access and refresh token", async () => {
    const t = createTestServer()
    const first = await obtainTokens(t)
    const { status, body } = await refresh(
      t,
      first.clientId,
      first.refreshToken,
    )
    expect(status).toBe(200)
    expect(body.refresh_token).not.toBe(first.refreshToken)
    expect(body.access_token).not.toBe(first.accessToken)
    expect(await accessWorks(t, body.access_token)).toBe(true)
  })

  it("chains rotations", async () => {
    const t = createTestServer()
    const first = await obtainTokens(t)
    let current = first.refreshToken
    for (let round = 0; round < 3; round++) {
      t.clock.advance(120)
      const { status, body } = await refresh(t, first.clientId, current)
      expect(status).toBe(200)
      current = body.refresh_token
    }
  })

  it("binds the refresh token to its client", async () => {
    const t = createTestServer()
    const first = await obtainTokens(t)
    const other = await registerClient(t)
    const { body } = await refresh(t, other.client_id!, first.refreshToken)
    expect(body.error).toBe("invalid_grant")
    const legit = await refresh(t, first.clientId, first.refreshToken)
    expect(legit.status).toBe(200)
  })

  it("refuses an unknown refresh token", async () => {
    const t = createTestServer()
    const first = await obtainTokens(t)
    const { body } = await refresh(t, first.clientId, "ort_nope")
    expect(body.error).toBe("invalid_grant")
  })

  describe("reuse detection", () => {
    it("revokes the whole grant when a rotated token is reused after the grace window", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      const rotated = await refresh(t, first.clientId, first.refreshToken)
      t.clock.advance(61)
      const reuse = await refresh(t, first.clientId, first.refreshToken)
      expect(reuse.body.error).toBe("invalid_grant")
      expect(await accessWorks(t, rotated.body.access_token)).toBe(false)
      const next = await refresh(t, first.clientId, rotated.body.refresh_token)
      expect(next.body.error).toBe("invalid_grant")
      expect([...t.store.grants.values()][0]!.revokedAt).not.toBeNull()
    })

    it("revokes the grant when reuse comes after the rotated pair was itself used", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      const rotated = await refresh(t, first.clientId, first.refreshToken)
      const used = await refresh(t, first.clientId, rotated.body.refresh_token)
      expect(used.status).toBe(200)
      const reuse = await refresh(t, first.clientId, first.refreshToken)
      expect(reuse.body.error).toBe("invalid_grant")
      expect(await accessWorks(t, used.body.access_token)).toBe(false)
    })
  })

  describe("lost-response exception", () => {
    it("gives a retry within 60 seconds a fresh pair and revokes the first rotation's pair", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      const lost = await refresh(t, first.clientId, first.refreshToken)
      t.clock.advance(60)
      const retry = await refresh(t, first.clientId, first.refreshToken)
      expect(retry.status).toBe(200)
      expect(retry.body.refresh_token).not.toBe(lost.body.refresh_token)
      expect(await accessWorks(t, retry.body.access_token)).toBe(true)
      expect(await accessWorks(t, lost.body.access_token)).toBe(false)
      expect([...t.store.grants.values()][0]!.revokedAt).toBeNull()

      const next = await refresh(t, first.clientId, retry.body.refresh_token)
      expect(next.status).toBe(200)
    })

    it("treats a refresh token the grace path revoked as reuse and revokes the grant", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      const thief = await refresh(t, first.clientId, first.refreshToken)
      const client = await refresh(t, first.clientId, first.refreshToken)
      expect(client.status).toBe(200)
      const thiefAgain = await refresh(
        t,
        first.clientId,
        thief.body.refresh_token,
      )
      expect(thiefAgain.body.error).toBe("invalid_grant")
      expect(await accessWorks(t, client.body.access_token)).toBe(false)
      expect([...t.store.grants.values()][0]!.revokedAt).not.toBeNull()
    })

    it("keeps the absolute refresh expiry on grace pairs", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      await refresh(t, first.clientId, first.refreshToken)
      await refresh(t, first.clientId, first.refreshToken)
      const expiries = new Set(
        [...t.store.tokens.values()].map((row) =>
          row.refreshTokenExpiresAt.getTime(),
        ),
      )
      expect(expiries.size).toBe(1)
    })

    it("answers two concurrent refreshes of one token without revoking the grant", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      const results = await Promise.all([
        refresh(t, first.clientId, first.refreshToken),
        refresh(t, first.clientId, first.refreshToken),
      ])
      expect(results.map((result) => result.status)).toEqual([200, 200])
      expect([...t.store.grants.values()][0]!.revokedAt).toBeNull()
      const working = await Promise.all(
        results.map((result) => accessWorks(t, result.body.access_token)),
      )
      expect(working.filter(Boolean)).toHaveLength(1)
    })
  })

  describe("lifetime", () => {
    it("expires refresh tokens 30 days after consent, however often they rotate", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      let current = first.refreshToken
      for (let day = 0; day < 29; day++) {
        t.clock.advance(86_400)
        const { status, body } = await refresh(t, first.clientId, current)
        expect(status).toBe(200)
        current = body.refresh_token
      }
      t.clock.advance(86_400)
      const expired = await refresh(t, first.clientId, current)
      expect(expired.body.error).toBe("invalid_grant")
    })

    it("expires access tokens after one hour", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      t.clock.advance(3599)
      expect(await accessWorks(t, first.accessToken)).toBe(true)
      t.clock.advance(1)
      expect(await accessWorks(t, first.accessToken)).toBe(false)
    })
  })

  describe("RFC 8707 resource", () => {
    it("accepts the grant's resource or none", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      const withResource = await refresh(
        t,
        first.clientId,
        first.refreshToken,
        {
          resource: RESOURCE,
        },
      )
      expect(withResource.status).toBe(200)
      const without = await refresh(
        t,
        first.clientId,
        withResource.body.refresh_token,
      )
      expect(without.status).toBe(200)
      expect(
        [...t.store.tokens.values()].every((row) => row.resource === RESOURCE),
      ).toBe(true)
    })

    it("refuses another resource with invalid_target", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      const { body } = await refresh(t, first.clientId, first.refreshToken, {
        resource: "https://app.example/api",
      })
      expect(body.error).toBe("invalid_target")
    })
  })

  describe("scope", () => {
    it("may narrow the scope", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t, {
        scope: "files:read files:write",
        scopes: ["files:write"],
      })
      expect(first.body.scope).toBe("files:read files:write")
      const { body } = await refresh(t, first.clientId, first.refreshToken, {
        scope: "files:read",
      })
      expect(body.scope).toBe("files:read")
    })

    it("may not widen the scope", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      const { body } = await refresh(t, first.clientId, first.refreshToken, {
        scope: "files:read files:write",
      })
      expect(body.error).toBe("invalid_scope")
    })
  })

  describe("revocation and user status", () => {
    it("refuses a refresh after Disconnect", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      const grant = [...t.store.grants.values()][0]!
      expect(await t.server.revokeGrant("user-1", grant.id)).toBe(true)
      const { body } = await refresh(t, first.clientId, first.refreshToken)
      expect(body.error).toBe("invalid_grant")
    })

    it("refuses a refresh for a blocked user", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      t.blockedUsers.add("user-1")
      const { body } = await refresh(t, first.clientId, first.refreshToken)
      expect(body.error).toBe("invalid_grant")
    })

    it("requires refresh_token", async () => {
      const t = createTestServer()
      const first = await obtainTokens(t)
      const response = await t.server.handleToken(
        refreshRequest(first.clientId, ""),
      )
      expect(((await response.json()) as TokenBody).error).toBe(
        "invalid_request",
      )
    })
  })
})

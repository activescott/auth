/**
 * Token endpoint spec compliance, authorization_code grant:
 * - RFC 6749 §2.3 client authentication, §4.1.3 token request, §5.1/§5.2
 *   responses
 * - RFC 7636 §4.5-4.6 PKCE verification (S256 only)
 * - RFC 8707 §2.2 resource on the token request
 */
import { describe, expect, it } from "vitest"
import { sha256Hex } from "../crypto.js"
import {
  createTestServer,
  ISSUER,
  obtainCode,
  obtainTokens,
  registerClient,
  RESOURCE,
  resourceRequest,
  tokenRequest,
  WEB_REDIRECT,
  type TestServer,
} from "./helpers.js"

async function codeFor(t: TestServer, body?: Record<string, unknown>) {
  const registered = await registerClient(t, body)
  const code = await obtainCode(t, { clientId: registered.client_id! })
  return { registered, clientId: registered.client_id!, ...code }
}

function redeem(
  t: TestServer,
  params: Record<string, string>,
  headers: Record<string, string> = {},
) {
  return t.server.handleToken(
    tokenRequest({ grant_type: "authorization_code", ...params }, headers),
  )
}

async function errorOf(response: Response): Promise<string> {
  return ((await response.json()) as { error: string }).error
}

describe("Token endpoint: authorization_code (RFC 6749 §4.1.3)", () => {
  describe("§5.1 successful response", () => {
    it("returns a bearer access token, a refresh token, expiry and scope", async () => {
      const t = createTestServer({
        tokenPrefixes: { access: "ffat_", refresh: "ffrt_" },
      })
      const { body } = await obtainTokens(t)
      expect(body.token_type).toBe("Bearer")
      expect(body.expires_in).toBe(3600)
      expect(body.scope).toBe("files:read")
      // 256 bits is 43 base64url characters.
      expect(body.access_token).toMatch(/^ffat_[A-Za-z0-9_-]{43}$/)
      expect(body.refresh_token).toMatch(/^ffrt_[A-Za-z0-9_-]{43}$/)
    })

    it("forbids caching the response", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t)
      const response = await redeem(t, {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(response.headers.get("Cache-Control")).toBe("no-store")
      expect(response.headers.get("Pragma")).toBe("no-cache")
    })

    it("stores tokens only as SHA-256 hashes, bound to the resource", async () => {
      const t = createTestServer()
      const { accessToken, refreshToken } = await obtainTokens(t)
      const rows = [...t.store.tokens.values()]
      expect(rows).toHaveLength(1)
      expect(rows[0]!.accessTokenHash).toBe(await sha256Hex(accessToken))
      expect(rows[0]!.refreshTokenHash).toBe(await sha256Hex(refreshToken))
      expect(rows[0]!.resource).toBe(RESOURCE)
      const dump = JSON.stringify(rows)
      expect(dump).not.toContain(accessToken)
      expect(dump).not.toContain(refreshToken)
    })

    it("creates one grant per user and client", async () => {
      const t = createTestServer()
      const { clientId } = await obtainTokens(t)
      const second = await obtainCode(t, { clientId })
      await redeem(t, {
        client_id: clientId,
        code: second.code,
        code_verifier: second.verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(t.store.grants.size).toBe(1)
      expect([...t.store.grants.values()][0]).toMatchObject({
        userId: "user-1",
        clientId,
        scopes: ["files:read"],
        resource: RESOURCE,
      })
    })

    it("accepts redemption without resource, using the code's", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t)
      const response = await redeem(t, {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(response.status).toBe(200)
    })
  })

  describe("RFC 7636 PKCE", () => {
    it("requires code_verifier", async () => {
      const t = createTestServer()
      const { clientId, code } = await codeFor(t)
      const response = await redeem(t, {
        client_id: clientId,
        code,
        redirect_uri: WEB_REDIRECT,
      })
      expect(response.status).toBe(400)
      expect(await errorOf(response)).toBe("invalid_request")
    })

    it("refuses a verifier that does not hash to the challenge", async () => {
      const t = createTestServer()
      const { clientId, code } = await codeFor(t)
      const response = await redeem(t, {
        client_id: clientId,
        code,
        code_verifier: "w".repeat(43),
        redirect_uri: WEB_REDIRECT,
      })
      expect(await errorOf(response)).toBe("invalid_grant")
    })

    /** S256 only: the challenge itself as verifier is the `plain` method. */
    it("refuses the challenge sent back as the verifier", async () => {
      const t = createTestServer()
      const { clientId, code } = await codeFor(t)
      const challenge = [...t.store.codes.values()][0]!.codeChallenge
      const response = await redeem(t, {
        client_id: clientId,
        code,
        code_verifier: challenge,
        redirect_uri: WEB_REDIRECT,
      })
      expect(await errorOf(response)).toBe("invalid_grant")
    })

    it.each([
      ["too short", "a".repeat(42)],
      ["too long", "a".repeat(129)],
      ["outside the unreserved set", `${"a".repeat(42)}!`],
    ])("refuses a verifier that is %s", async (_label, verifier) => {
      const t = createTestServer()
      const { clientId, code } = await codeFor(t)
      const response = await redeem(t, {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(await errorOf(response)).toBe("invalid_request")
    })
  })

  describe("§4.1.3 code checks", () => {
    it("refuses an unknown code", async () => {
      const t = createTestServer()
      const { clientId, verifier } = await codeFor(t)
      const response = await redeem(t, {
        client_id: clientId,
        code: "not-a-code",
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(await errorOf(response)).toBe("invalid_grant")
    })

    it("refuses a code issued to another client, and leaves it redeemable", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t)
      const other = await registerClient(t)
      const stolen = await redeem(t, {
        client_id: other.client_id!,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(await errorOf(stolen)).toBe("invalid_grant")
      const legit = await redeem(t, {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(legit.status).toBe(200)
    })

    it("requires the same redirect_uri as the authorization request", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t, {
        redirect_uris: [WEB_REDIRECT, "https://client.example/other"],
        token_endpoint_auth_method: "none",
      })
      for (const redirectUri of ["https://client.example/other", undefined]) {
        const response = await redeem(t, {
          client_id: clientId,
          code,
          code_verifier: verifier,
          ...(redirectUri ? { redirect_uri: redirectUri } : {}),
        })
        expect(response.status).toBe(400)
      }
    })

    it("refuses a code after 10 minutes", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t)
      t.clock.advance(600)
      const response = await redeem(t, {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(await errorOf(response)).toBe("invalid_grant")
    })

    /** RFC 8707 §2.2: a resource on the token request must match the grant. */
    it("refuses a resource that differs from the code's", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t)
      const response = await redeem(t, {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
        resource: "https://app.example/other",
      })
      expect(await errorOf(response)).toBe("invalid_target")
    })

    it("refuses a user the app has since blocked", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t)
      t.blockedUsers.add("user-1")
      const response = await redeem(t, {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(await errorOf(response)).toBe("invalid_grant")
    })
  })

  describe("§4.1.2 single use", () => {
    it("revokes the tokens from the first redemption when a code is used twice", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t)
      const params = {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      }
      const first = (await (await redeem(t, params)).json()) as {
        access_token: string
      }
      expect(
        (await t.server.verifyAccessToken(resourceRequest(first.access_token)))
          .ok,
      ).toBe(true)
      const second = await redeem(t, params)
      expect(await errorOf(second)).toBe("invalid_grant")
      expect(
        (await t.server.verifyAccessToken(resourceRequest(first.access_token)))
          .ok,
      ).toBe(false)
    })

    it("lets only one of two concurrent redemptions win", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t)
      const params = {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      }
      const responses = await Promise.all([
        redeem(t, params),
        redeem(t, params),
      ])
      const statuses = responses.map((response) => response.status).sort()
      expect(statuses).toEqual([200, 400])
      // The loser counts as a second redemption, so the winner's tokens go too.
      const winner = responses.find((response) => response.status === 200)!
      const { access_token: accessToken } = (await winner.json()) as {
        access_token: string
      }
      expect(
        (await t.server.verifyAccessToken(resourceRequest(accessToken))).ok,
      ).toBe(false)
    })
  })

  describe("§2.3 client authentication", () => {
    async function confidential(t: TestServer) {
      const registered = await registerClient(t, {
        redirect_uris: [WEB_REDIRECT],
        client_name: "Confidential",
      })
      const code = await obtainCode(t, { clientId: registered.client_id! })
      return {
        clientId: registered.client_id!,
        secret: registered.client_secret!,
        ...code,
      }
    }

    function basic(id: string, secret: string): string {
      const encode = (value: string) =>
        encodeURIComponent(value).replace(/%20/g, "+")
      return `Basic ${btoa(`${encode(id)}:${encode(secret)}`)}`
    }

    it("lets a public client authenticate with client_id alone", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t)
      const response = await redeem(t, {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(response.status).toBe(200)
    })

    it("refuses a public client that sends a secret", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t)
      const response = await redeem(t, {
        client_id: clientId,
        client_secret: "guess",
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(response.status).toBe(401)
    })

    it("accepts a confidential client's secret by HTTP Basic", async () => {
      const t = createTestServer()
      const { clientId, secret, code, verifier } = await confidential(t)
      const response = await redeem(
        t,
        { code, code_verifier: verifier, redirect_uri: WEB_REDIRECT },
        { Authorization: basic(clientId, secret) },
      )
      expect(response.status).toBe(200)
    })

    it("accepts a confidential client's secret in the body", async () => {
      const t = createTestServer()
      const { clientId, secret, code, verifier } = await confidential(t)
      const response = await redeem(t, {
        client_id: clientId,
        client_secret: secret,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      expect(response.status).toBe(200)
    })

    it.each([
      ["no secret", {}],
      ["a wrong secret", { client_secret: "wrong" }],
    ])("refuses a confidential client with %s", async (_label, extra) => {
      const t = createTestServer()
      const { clientId, code, verifier } = await confidential(t)
      const response = await redeem(t, {
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
        ...extra,
      })
      expect(response.status).toBe(401)
      expect(await errorOf(response)).toBe("invalid_client")
    })

    it("answers a wrong Basic secret with 401 and WWW-Authenticate", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await confidential(t)
      const response = await redeem(
        t,
        { code, code_verifier: verifier, redirect_uri: WEB_REDIRECT },
        { Authorization: basic(clientId, "wrong") },
      )
      expect(response.status).toBe(401)
      expect(response.headers.get("WWW-Authenticate")).toMatch(/^Basic/)
    })

    it("refuses two authentication methods at once", async () => {
      const t = createTestServer()
      const { clientId, secret, code, verifier } = await confidential(t)
      const response = await redeem(
        t,
        {
          client_secret: secret,
          code,
          code_verifier: verifier,
          redirect_uri: WEB_REDIRECT,
        },
        { Authorization: basic(clientId, secret) },
      )
      expect(await errorOf(response)).toBe("invalid_request")
    })

    it("refuses an unknown client with 401", async () => {
      const t = createTestServer()
      const response = await redeem(t, {
        client_id: "dyn_nobody",
        code: "x",
        code_verifier: "v".repeat(43),
        redirect_uri: WEB_REDIRECT,
      })
      expect(response.status).toBe(401)
    })
  })

  describe("request format", () => {
    it("refuses a JSON body", async () => {
      const t = createTestServer()
      const response = await t.server.handleToken(
        new Request(`${ISSUER}/oauth/token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ grant_type: "authorization_code" }),
        }),
      )
      expect(await errorOf(response)).toBe("invalid_request")
    })

    it("answers GET with 405", async () => {
      const t = createTestServer()
      const response = await t.server.handleToken(
        new Request(`${ISSUER}/oauth/token`),
      )
      expect(response.status).toBe(405)
    })

    /** RFC 6749 §3.2: parameters MUST NOT be included more than once. */
    it("refuses a repeated parameter", async () => {
      const t = createTestServer()
      const { clientId, code, verifier } = await codeFor(t)
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: WEB_REDIRECT,
      })
      body.append("code", "other")
      const response = await t.server.handleToken(
        new Request(`${ISSUER}/oauth/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: body.toString(),
        }),
      )
      expect(await errorOf(response)).toBe("invalid_request")
    })

    it.each([
      ["unsupported_grant_type", "client_credentials"],
      ["unsupported_grant_type", "password"],
    ])("answers %s for %s", async (error, grantType) => {
      const t = createTestServer()
      const { client_id: clientId } = await registerClient(t)
      const response = await t.server.handleToken(
        tokenRequest({ grant_type: grantType, client_id: clientId! }),
      )
      expect(await errorOf(response)).toBe(error)
    })
  })
})

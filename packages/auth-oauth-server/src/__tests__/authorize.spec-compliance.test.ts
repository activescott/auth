/**
 * Authorization endpoint spec compliance:
 * - RFC 6749 §4.1.1, §4.1.2 authorization request and response
 * - OAuth 2.1 draft-13 §4.1.1, §8.4.2 PKCE and loopback redirects
 * - RFC 7636 PKCE (S256 only), RFC 8707 resource indicators
 * - RFC 9207 `iss` in the authorization response
 * - MCP authorization (2026-07-28) consent requirements
 */
import { describe, expect, it } from "vitest"
import {
  answerConsent,
  authorizeParams,
  authorizeRequest,
  consentRequest,
  createTestServer,
  ISSUER,
  locationParams,
  LOOPBACK_REDIRECT,
  pkcePair,
  registerClient,
  RESOURCE,
  USER,
  WEB_REDIRECT,
  type TestServer,
} from "./helpers.js"

async function setup(overrides = {}) {
  const t = createTestServer(overrides)
  const { client_id: clientId } = await registerClient(t)
  const { challenge } = await pkcePair()
  return { t, clientId: clientId!, challenge }
}

function authorize(
  t: TestServer,
  params: Record<string, string>,
  userId = USER,
): Promise<Response> {
  return t.server.handleAuthorization(authorizeRequest(params), { userId })
}

function expectFrameDenied(response: Response) {
  expect(response.headers.get("X-Frame-Options")).toBe("DENY")
  expect(response.headers.get("Content-Security-Policy")).toContain(
    "frame-ancestors 'none'",
  )
}

describe("Authorization endpoint", () => {
  describe("RFC 6749 §4.1.2.1: untrusted client or redirect URI never redirects", () => {
    it("shows an error page for an unknown client_id", async () => {
      const { t, challenge } = await setup()
      const response = await authorize(
        t,
        authorizeParams("dyn_unknown", challenge),
      )
      expect(response.status).toBe(400)
      expect(response.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("invalid_client")
    })

    it("shows an error page for a missing client_id", async () => {
      const { t, challenge } = await setup()
      const params = authorizeParams("x", challenge, { client_id: undefined })
      const response = await authorize(t, params)
      expect(response.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("invalid_client")
    })

    it.each([
      ["missing", undefined],
      ["unregistered", "https://evil.example/callback"],
      ["registered plus a path", `${WEB_REDIRECT}/more`],
      ["registered plus a query", `${WEB_REDIRECT}?next=1`],
      ["registered with userinfo", "https://user@client.example/callback"],
      ["registered with a fragment", `${WEB_REDIRECT}#x`],
      ["registered with another port", "https://client.example:8443/callback"],
    ])(
      "shows an error page for a %s redirect_uri",
      async (_label, redirectUri) => {
        const { t, clientId, challenge } = await setup()
        const response = await authorize(
          t,
          authorizeParams(clientId, challenge, { redirect_uri: redirectUri }),
        )
        expect(response.headers.get("Location")).toBeNull()
        expect(t.errors.at(-1)?.error).toBe("invalid_redirect_uri")
      },
    )

    /** RFC 6749 §3.1: parameters MUST NOT be included more than once. */
    it("shows an error page for a repeated parameter", async () => {
      const { t, clientId, challenge } = await setup()
      const query = new URLSearchParams(authorizeParams(clientId, challenge))
      query.append("redirect_uri", "https://evil.example/cb")
      const response = await t.server.handleAuthorization(
        new Request(`${ISSUER}/oauth/authorize?${query.toString()}`),
        { userId: USER },
      )
      expect(response.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("invalid_request")
    })
  })

  describe("OAuth 2.1 §8.4.2: loopback redirect URIs ignore the port", () => {
    async function nativeSetup(redirectUris: string[]) {
      const t = createTestServer()
      const { client_id: clientId } = await registerClient(t, {
        redirect_uris: redirectUris,
        token_endpoint_auth_method: "none",
      })
      const { challenge } = await pkcePair()
      return { t, clientId: clientId!, challenge }
    }

    it.each([
      [
        "127.0.0.1",
        "http://127.0.0.1/callback",
        "http://127.0.0.1:51234/callback",
      ],
      ["[::1]", "http://[::1]/callback", "http://[::1]:51234/callback"],
      [
        "localhost",
        "http://localhost/callback",
        "http://localhost:51234/callback",
      ],
      [
        "a registered port",
        "http://127.0.0.1:3000/callback",
        "http://127.0.0.1:4000/callback",
      ],
    ])("matches %s on any port", async (_label, registered, requested) => {
      const { t, clientId, challenge } = await nativeSetup([registered])
      const response = await authorize(
        t,
        authorizeParams(clientId, challenge, { redirect_uri: requested }),
      )
      expect(response.status).toBe(200)
      expect(t.prompts).toHaveLength(1)
    })

    it.each([
      ["another loopback host", "http://localhost:5000/callback"],
      ["another path", "http://127.0.0.1:5000/other"],
      ["another query", "http://127.0.0.1:5000/callback?x=1"],
      ["https", "https://127.0.0.1:5000/callback"],
      ["userinfo", "http://user@127.0.0.1:5000/callback"],
    ])("does not match %s", async (_label, requested) => {
      const { t, clientId, challenge } = await nativeSetup([LOOPBACK_REDIRECT])
      const response = await authorize(
        t,
        authorizeParams(clientId, challenge, { redirect_uri: requested }),
      )
      expect(response.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("invalid_redirect_uri")
    })
  })

  describe("RFC 6749 §4.1.2.1: errors after validation redirect with state and iss", () => {
    it.each([
      ["unsupported_response_type", { response_type: "token" }],
      ["unsupported_response_type", { response_type: undefined }],
      ["invalid_request", { code_challenge: undefined }],
      ["invalid_request", { code_challenge_method: undefined }],
      ["invalid_request", { code_challenge_method: "plain" }],
      ["invalid_request", { code_challenge: "too-short" }],
      ["invalid_target", { resource: undefined }],
      ["invalid_target", { resource: "https://app.example/other" }],
      ["invalid_target", { resource: "https://app.example/mcp/" }],
      ["invalid_scope", { scope: "files:read admin" }],
    ])("redirects %s for %j", async (error, overrides) => {
      const { t, clientId, challenge } = await setup()
      const response = await authorize(
        t,
        authorizeParams(clientId, challenge, overrides),
      )
      expect(response.status).toBe(302)
      const location = new URL(response.headers.get("Location")!)
      expect(`${location.origin}${location.pathname}`).toBe(WEB_REDIRECT)
      expect(location.searchParams.get("error")).toBe(error)
      expect(location.searchParams.get("state")).toBe("state-123")
      expect(location.searchParams.get("iss")).toBe(ISSUER)
      expect(t.prompts).toHaveLength(0)
    })

    it("refuses a user the app has blocked", async () => {
      const { t, clientId, challenge } = await setup()
      t.blockedUsers.add(USER)
      const response = await authorize(t, authorizeParams(clientId, challenge))
      expect(locationParams(response).get("error")).toBe("access_denied")
    })

    it("rate-limits stored authorization requests per user", async () => {
      const { t, clientId, challenge } = await setup({
        rateLimits: {
          authorizationRequestsPerUser: [{ windowSeconds: 60, max: 1 }],
        },
      })
      expect(
        (await authorize(t, authorizeParams(clientId, challenge))).status,
      ).toBe(200)
      const blocked = await authorize(t, authorizeParams(clientId, challenge))
      expect(locationParams(blocked).get("error")).toBe(
        "temporarily_unavailable",
      )
    })
  })

  describe("consent page", () => {
    it("renders consent from the validated request", async () => {
      const { t, clientId, challenge } = await setup()
      const response = await authorize(
        t,
        authorizeParams(clientId, challenge, {
          scope: "files:read files:write",
        }),
      )
      expect(response.status).toBe(200)
      const prompt = t.prompts[0]!
      expect(prompt.userId).toBe(USER)
      expect(prompt.action).toBe(`${ISSUER}/oauth/authorize`)
      expect(prompt.fields.request_id).toBeTypeOf("string")
      expect(prompt.fields.csrf_token).toBeTypeOf("string")
      expect(prompt.client).toMatchObject({
        clientId,
        kind: "dynamic",
        name: "Test Client",
        clientIdHost: null,
        redirectUri: WEB_REDIRECT,
        redirectHost: "client.example",
      })
      expect(prompt.scopes).toEqual([
        { scope: "files:read", optional: false },
        { scope: "files:write", optional: true },
      ])
      expect(prompt.resource).toBe(RESOURCE)
    })

    it("uses the default scopes when none are requested", async () => {
      const { t, clientId, challenge } = await setup()
      await authorize(
        t,
        authorizeParams(clientId, challenge, { scope: undefined }),
      )
      expect(t.prompts[0]!.scopes).toEqual([
        { scope: "files:read", optional: false },
      ])
    })

    it("labels a dynamic client unregistered", async () => {
      const { t, clientId, challenge } = await setup()
      await authorize(t, authorizeParams(clientId, challenge))
      expect(t.prompts[0]!.warnings).toEqual({
        loopbackRedirects: false,
        redirectHostDiffers: false,
        unregisteredClient: true,
      })
    })

    it("warns when every redirect is loopback", async () => {
      const t = createTestServer()
      const { client_id: clientId } = await registerClient(t, {
        redirect_uris: [LOOPBACK_REDIRECT, "http://localhost/callback"],
        token_endpoint_auth_method: "none",
      })
      const { challenge } = await pkcePair()
      await authorize(
        t,
        authorizeParams(clientId!, challenge, {
          redirect_uri: LOOPBACK_REDIRECT,
        }),
      )
      expect(t.prompts[0]!.warnings.loopbackRedirects).toBe(true)
    })

    it("refuses framing on the consent page, error pages and redirects", async () => {
      const { t, clientId, challenge } = await setup()
      expectFrameDenied(
        await authorize(t, authorizeParams(clientId, challenge)),
      )
      expectFrameDenied(
        await authorize(t, authorizeParams("dyn_unknown", challenge)),
      )
      expectFrameDenied(
        await authorize(
          t,
          authorizeParams(clientId, challenge, { resource: "x" }),
        ),
      )
      expectFrameDenied(await answerConsent(t, t.prompts[0]!))
    })

    it("keeps the app's own CSP and adds frame-ancestors to it", async () => {
      const t = createTestServer({
        renderConsent: () =>
          new Response("consent", {
            headers: {
              "Content-Security-Policy": "default-src 'self'",
              "X-Frame-Options": "SAMEORIGIN",
            },
          }),
      })
      const { client_id: clientId } = await registerClient(t)
      const { challenge } = await pkcePair()
      const response = await authorize(t, authorizeParams(clientId!, challenge))
      const csp = response.headers.get("Content-Security-Policy")!
      expect(csp).toContain("default-src 'self'")
      expect(csp).toContain("frame-ancestors 'none'")
      expect(response.headers.get("X-Frame-Options")).toBe("DENY")
      expect(response.headers.get("Cache-Control")).toBe("no-store")
      expect(response.headers.get("Referrer-Policy")).toBe("no-referrer")
    })

    it("shows consent every time, even with an existing grant", async () => {
      const { t, clientId, challenge } = await setup()
      await answerConsent(
        t,
        await authorize(t, authorizeParams(clientId, challenge)).then(
          () => t.prompts[0]!,
        ),
      )
      const again = await authorize(t, authorizeParams(clientId, challenge))
      expect(again.status).toBe(200)
      expect(again.headers.get("Location")).toBeNull()
      expect(t.prompts).toHaveLength(2)
    })

    it("answers other methods with 405", async () => {
      const { t } = await setup()
      const response = await t.server.handleAuthorization(
        new Request(`${ISSUER}/oauth/authorize`, { method: "PUT" }),
        { userId: USER },
      )
      expect(response.status).toBe(405)
    })
  })

  describe("consent POST", () => {
    async function prompted(scope = "files:read") {
      const { t, clientId, challenge } = await setup()
      await authorize(t, authorizeParams(clientId, challenge, { scope }))
      return { t, clientId, prompt: t.prompts[0]! }
    }

    /** RFC 6749 §4.1.2 and RFC 9207 §2. */
    it("redirects an approval with code, state and iss using 303", async () => {
      const { t, prompt } = await prompted()
      const response = await answerConsent(t, prompt)
      expect(response.status).toBe(303)
      const params = locationParams(response)
      expect(params.get("code")).toMatch(/^[A-Za-z0-9_-]{43}$/)
      expect(params.get("state")).toBe("state-123")
      expect(params.get("iss")).toBe(ISSUER)
    })

    it("redirects a denial with access_denied, state and iss to the stored redirect URI", async () => {
      const { t, prompt } = await prompted()
      const response = await t.server.handleAuthorization(
        consentRequest({
          ...prompt.fields,
          decision: "deny",
          redirect_uri: "https://evil.example/steal",
        }),
        { userId: USER },
      )
      expect(response.status).toBe(303)
      const location = new URL(response.headers.get("Location")!)
      expect(`${location.origin}${location.pathname}`).toBe(WEB_REDIRECT)
      expect(location.searchParams.get("error")).toBe("access_denied")
      expect(location.searchParams.get("state")).toBe("state-123")
      expect(location.searchParams.get("iss")).toBe(ISSUER)
    })

    it("treats anything but an explicit approve as a denial", async () => {
      const { t, prompt } = await prompted()
      const response = await answerConsent(t, prompt, { decision: "yes" })
      expect(locationParams(response).get("error")).toBe("access_denied")
    })

    it("ignores hidden fields that try to change the request", async () => {
      const { t, prompt } = await prompted()
      const response = await t.server.handleAuthorization(
        consentRequest({
          ...prompt.fields,
          decision: "approve",
          client_id: "dyn_other",
          redirect_uri: "https://evil.example/steal",
          state: "forged",
          code_challenge: "A".repeat(43),
        }),
        { userId: USER },
      )
      const location = new URL(response.headers.get("Location")!)
      expect(`${location.origin}${location.pathname}`).toBe(WEB_REDIRECT)
      expect(location.searchParams.get("state")).toBe("state-123")
      const code = [...t.store.codes.values()][0]!
      expect(code.codeChallenge).not.toBe("A".repeat(43))
    })

    it("refuses a wrong CSRF token with an error page", async () => {
      const { t, prompt } = await prompted()
      const response = await t.server.handleAuthorization(
        consentRequest({
          request_id: prompt.fields.request_id,
          csrf_token: "wrong",
          decision: "approve",
        }),
        { userId: USER },
      )
      expect(response.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("invalid_request")
      expect(t.store.codes.size).toBe(0)
    })

    it("refuses another user's request, so user B cannot steer user A", async () => {
      const { t, prompt } = await prompted()
      const response = await answerConsent(t, prompt, { userId: "user-2" })
      expect(response.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("request_expired")
      expect(t.store.codes.size).toBe(0)
    })

    it("is single use", async () => {
      const { t, prompt } = await prompted()
      expect((await answerConsent(t, prompt)).status).toBe(303)
      const second = await answerConsent(t, prompt)
      expect(second.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("request_expired")
    })

    it("expires after 10 minutes", async () => {
      const { t, prompt } = await prompted()
      t.clock.advance(10 * 60)
      const response = await answerConsent(t, prompt)
      expect(response.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("request_expired")
    })

    it("refuses a form missing its request fields", async () => {
      const { t } = await prompted()
      const response = await t.server.handleAuthorization(
        consentRequest({ decision: "approve" }),
        { userId: USER },
      )
      expect(response.headers.get("Location")).toBeNull()
    })

    it("refuses a JSON consent body", async () => {
      const { t, prompt } = await prompted()
      const response = await t.server.handleAuthorization(
        new Request(`${ISSUER}/oauth/authorize`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ...prompt.fields, decision: "approve" }),
        }),
        { userId: USER },
      )
      expect(response.headers.get("Location")).toBeNull()
    })

    it("grants an optional scope only when the user ticks it", async () => {
      const unticked = await prompted("files:read files:write")
      await answerConsent(unticked.t, unticked.prompt)
      expect([...unticked.t.store.codes.values()][0]!.scopes).toEqual([
        "files:read",
      ])

      const ticked = await prompted("files:read files:write")
      await answerConsent(ticked.t, ticked.prompt, { scopes: ["files:write"] })
      expect([...ticked.t.store.codes.values()][0]!.scopes).toEqual([
        "files:read",
        "files:write",
      ])
    })

    it("never grants a ticked scope the client did not request", async () => {
      const { t, prompt } = await prompted("files:read")
      await answerConsent(t, prompt, { scopes: ["files:write"] })
      expect([...t.store.codes.values()][0]!.scopes).toEqual(["files:read"])
    })

    it("denies when the only requested scope is left unticked", async () => {
      const { t, prompt } = await prompted("files:write")
      const response = await answerConsent(t, prompt)
      expect(locationParams(response).get("error")).toBe("access_denied")
    })

    it("refuses approval once the user is blocked", async () => {
      const { t, prompt } = await prompted()
      t.blockedUsers.add(USER)
      const response = await answerConsent(t, prompt)
      expect(locationParams(response).get("error")).toBe("access_denied")
      expect(t.store.codes.size).toBe(0)
    })

    it("stores the code hashed with a 10 minute expiry", async () => {
      const { t, prompt } = await prompted()
      const response = await answerConsent(t, prompt)
      const code = locationParams(response).get("code")!
      const stored = [...t.store.codes.values()][0]!
      expect(stored.codeHash).not.toBe(code)
      expect(JSON.stringify([...t.store.codes.values()])).not.toContain(code)
      expect(stored.expiresAt.getTime() - stored.createdAt.getTime()).toBe(
        10 * 60 * 1000,
      )
    })
  })
})

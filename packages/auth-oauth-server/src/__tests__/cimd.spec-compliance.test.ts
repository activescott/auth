/**
 * Client ID Metadata Document spec compliance:
 * - draft-ietf-oauth-client-id-metadata-document §3 (client_id URL), §4
 *   (document), §5 (fetching and caching)
 * - MCP authorization (2026-07-28): CIMD before DCR
 * - Own-host rule: a CIMD client_id on the app's own host is refused
 */
import { describe, expect, it } from "vitest"
import {
  authorizeParams,
  authorizeRequest,
  CIMD_CLIENT_ID,
  createTestServer,
  pkcePair,
  tokenRequest,
  USER,
  WEB_REDIRECT,
  type TestServer,
} from "./helpers.js"

function cimdDocument(overrides: Record<string, unknown> = {}) {
  return {
    client_id: CIMD_CLIENT_ID,
    client_name: "Example Agent",
    redirect_uris: [WEB_REDIRECT],
    token_endpoint_auth_method: "none",
    ...overrides,
  }
}

async function authorizeCimd(
  t: TestServer,
  clientId = CIMD_CLIENT_ID,
  overrides: Record<string, string | undefined> = {},
): Promise<Response> {
  const { challenge } = await pkcePair()
  return t.server.handleAuthorization(
    authorizeRequest(authorizeParams(clientId, challenge, overrides)),
    { userId: USER },
  )
}

function serve(
  t: TestServer,
  document: unknown,
  maxAgeSeconds: number | null = 3600,
) {
  t.fetchClientMetadata.mockResolvedValue({ document, maxAgeSeconds })
}

describe("Client ID Metadata Documents", () => {
  describe("§3 client_id URL rules", () => {
    it.each([
      ["http", "http://client.example/client.json"],
      ["a non-443 port", "https://client.example:8443/client.json"],
      ["no path", "https://client.example/"],
      ["a fragment", "https://client.example/client.json#x"],
      ["a query", "https://client.example/client.json?v=1"],
      ["userinfo", "https://user@client.example/client.json"],
      ["a dot segment", "https://client.example/a/../client.json"],
      ["an encoded dot segment", "https://client.example/a/%2e%2e/client.json"],
      ["an IPv4 literal", "https://203.0.113.9/client.json"],
      ["an IPv6 literal", "https://[2001:db8::1]/client.json"],
    ])("refuses %s without fetching", async (_label, clientId) => {
      const t = createTestServer()
      serve(t, cimdDocument({ client_id: clientId }))
      const response = await authorizeCimd(t, clientId)
      expect(response.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("invalid_client")
      expect(t.fetchClientMetadata).not.toHaveBeenCalled()
    })
  })

  describe("own-host rule", () => {
    it.each([
      ["the issuer host", "https://app.example/u-raw/alice/client.json"],
      [
        "the issuer host in upper case",
        "https://APP.example/u-raw/alice/client.json",
      ],
      [
        "the issuer host with a trailing dot",
        "https://app.example./u-raw/alice/client.json",
      ],
      ["another host the app serves", "https://www.app.example/client.json"],
    ])(
      "refuses a client_id on %s without fetching",
      async (_label, clientId) => {
        const t = createTestServer({ ownHosts: ["www.app.example"] })
        serve(t, cimdDocument({ client_id: clientId }))
        const response = await authorizeCimd(t, clientId)
        expect(response.headers.get("Location")).toBeNull()
        expect(t.errors.at(-1)?.description).toMatch(/hosted on this server/)
        expect(t.fetchClientMetadata).not.toHaveBeenCalled()
      },
    )

    it("still refuses an own-host client_id that is already cached", async () => {
      const t = createTestServer()
      const clientId = "https://app.example/u-raw/alice/client.json"
      await t.store.saveClient({
        clientId,
        kind: "cimd",
        applicationType: "web",
        name: "Cached",
        redirectUris: [WEB_REDIRECT],
        tokenEndpointAuthMethod: "none",
        clientSecretHash: null,
        createdAt: t.clock.now,
        metadataFetchedAt: t.clock.now,
        metadataExpiresAt: new Date(t.clock.now.getTime() + 3600_000),
      })
      await authorizeCimd(t, clientId)
      expect(t.errors.at(-1)?.error).toBe("invalid_client")
      expect(t.prompts).toHaveLength(0)
    })
  })

  describe("§4 document validation", () => {
    it("fetches the document and shows the client_id host on consent", async () => {
      const t = createTestServer()
      serve(t, cimdDocument())
      const response = await authorizeCimd(t)
      expect(response.status).toBe(200)
      expect(t.fetchClientMetadata).toHaveBeenCalledWith(
        new URL(CIMD_CLIENT_ID),
      )
      expect(t.prompts[0]!.client).toMatchObject({
        clientId: CIMD_CLIENT_ID,
        kind: "cimd",
        name: "Example Agent",
        clientIdHost: "client.example",
        redirectHost: "client.example",
      })
      expect(t.prompts[0]!.warnings.unregisteredClient).toBe(false)
    })

    it("warns when the redirect host differs from the client_id host", async () => {
      const t = createTestServer()
      serve(
        t,
        cimdDocument({ redirect_uris: ["https://elsewhere.example/cb"] }),
      )
      await authorizeCimd(t, CIMD_CLIENT_ID, {
        redirect_uri: "https://elsewhere.example/cb",
      })
      expect(t.prompts[0]!.warnings.redirectHostDiffers).toBe(true)
    })

    it.each([
      [
        "a client_id that differs from the URL",
        { client_id: "https://other.example/client.json" },
      ],
      ["a client_secret", { client_secret: "s3cret" }],
      ["client_secret_expires_at", { client_secret_expires_at: 0 }],
      [
        "a confidential auth method",
        { token_endpoint_auth_method: "client_secret_basic" },
      ],
      ["no redirect_uris", { redirect_uris: undefined }],
      ["an http web redirect", { redirect_uris: ["http://client.example/cb"] }],
    ])("refuses a document with %s", async (_label, overrides) => {
      const t = createTestServer()
      serve(t, cimdDocument(overrides))
      const response = await authorizeCimd(t)
      expect(response.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("invalid_client")
      expect(await t.store.getClient(CIMD_CLIENT_ID)).toBeNull()
    })

    it("refuses a document that is not an object", async () => {
      const t = createTestServer()
      serve(t, ["not", "an", "object"])
      await authorizeCimd(t)
      expect(t.errors.at(-1)?.error).toBe("invalid_client")
    })

    it("requires the redirect_uri to be one the document lists", async () => {
      const t = createTestServer()
      serve(t, cimdDocument())
      const response = await authorizeCimd(t, CIMD_CLIENT_ID, {
        redirect_uri: "https://evil.example/callback",
      })
      expect(response.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("invalid_redirect_uri")
    })

    it("shows an error page when the fetch fails", async () => {
      const t = createTestServer()
      t.fetchClientMetadata.mockRejectedValue(new Error("connect refused"))
      const response = await authorizeCimd(t)
      expect(response.headers.get("Location")).toBeNull()
      expect(t.errors.at(-1)?.error).toBe("invalid_client")
    })

    it("sanitizes the document's client_name", async () => {
      const t = createTestServer()
      serve(t, cimdDocument({ client_name: "Agent\u202Etxt.exe" }))
      await authorizeCimd(t)
      expect(t.prompts[0]!.client.name).toBe("Agenttxt.exe")
    })
  })

  describe("§5 caching", () => {
    it("uses the cached document within its lifetime", async () => {
      const t = createTestServer()
      serve(t, cimdDocument(), 3600)
      await authorizeCimd(t)
      t.clock.advance(3599)
      await authorizeCimd(t)
      expect(t.fetchClientMetadata).toHaveBeenCalledTimes(1)
      t.clock.advance(2)
      await authorizeCimd(t)
      expect(t.fetchClientMetadata).toHaveBeenCalledTimes(2)
    })

    it("caches for at least 5 minutes even when the response says no-store", async () => {
      const t = createTestServer()
      serve(t, cimdDocument(), 0)
      await authorizeCimd(t)
      t.clock.advance(299)
      await authorizeCimd(t)
      expect(t.fetchClientMetadata).toHaveBeenCalledTimes(1)
      t.clock.advance(2)
      await authorizeCimd(t)
      expect(t.fetchClientMetadata).toHaveBeenCalledTimes(2)
    })

    it("caches for at most 24 hours whatever max-age says", async () => {
      const t = createTestServer()
      serve(t, cimdDocument(), 10 * 365 * 86_400)
      await authorizeCimd(t)
      const stored = await t.store.getClient(CIMD_CLIENT_ID)
      expect(stored!.metadataExpiresAt!.getTime() - t.clock.now.getTime()).toBe(
        86_400_000,
      )
    })

    it("picks up changed redirect URIs after the cache expires", async () => {
      const t = createTestServer()
      serve(t, cimdDocument(), 300)
      await authorizeCimd(t)
      serve(
        t,
        cimdDocument({ redirect_uris: ["https://client.example/new"] }),
        300,
      )
      t.clock.advance(301)
      await authorizeCimd(t)
      expect(t.errors.at(-1)?.error).toBe("invalid_redirect_uri")
    })
  })

  describe("fetch limits", () => {
    it("rate-limits fetches per user", async () => {
      const t = createTestServer({
        rateLimits: { metadataFetchPerUser: [{ windowSeconds: 60, max: 2 }] },
      })
      t.fetchClientMetadata.mockImplementation(async (url) => ({
        document: cimdDocument({ client_id: url.toString() }),
        maxAgeSeconds: 3600,
      }))
      for (const index of [1, 2]) {
        await authorizeCimd(t, `https://c${index}.example/client.json`)
      }
      await authorizeCimd(t, "https://c3.example/client.json")
      expect(t.fetchClientMetadata).toHaveBeenCalledTimes(2)
      expect(t.errors.at(-1)?.error).toBe("temporarily_unavailable")
    })

    it("rate-limits fetches globally", async () => {
      const t = createTestServer({
        rateLimits: { metadataFetchGlobal: [{ windowSeconds: 60, max: 1 }] },
      })
      serve(t, cimdDocument())
      await authorizeCimd(t)
      await t.server.handleAuthorization(
        authorizeRequest(
          authorizeParams("https://c2.example/client.json", "x".repeat(43)),
        ),
        { userId: "user-2" },
      )
      expect(t.fetchClientMetadata).toHaveBeenCalledTimes(1)
      expect(t.errors.at(-1)?.error).toBe("temporarily_unavailable")
    })

    it("treats an https client_id as unknown when CIMD is not configured", async () => {
      const t = createTestServer({ fetchClientMetadata: undefined })
      await authorizeCimd(t)
      expect(t.errors.at(-1)?.error).toBe("invalid_client")
    })

    it("never fetches at the token endpoint: an unstored client_id is invalid_client", async () => {
      const t = createTestServer()
      serve(t, cimdDocument())
      const response = await t.server.handleToken(
        tokenRequest({
          grant_type: "authorization_code",
          client_id: CIMD_CLIENT_ID,
          code: "anything",
          code_verifier: "v".repeat(43),
          redirect_uri: WEB_REDIRECT,
        }),
      )
      expect(response.status).toBe(401)
      expect(((await response.json()) as { error: string }).error).toBe(
        "invalid_client",
      )
      expect(t.fetchClientMetadata).not.toHaveBeenCalled()
    })
  })
})

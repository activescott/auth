/**
 * Dynamic Client Registration spec compliance:
 * - RFC 7591 OAuth 2.0 Dynamic Client Registration
 * - MCP authorization (2026-07-28): `application_type` decides redirects
 * - Own-host rule: a redirect URI on the app's own host or a subdomain of it
 *   is refused
 */
import { describe, expect, it } from "vitest"
import { sha256Hex } from "../crypto.js"
import {
  createTestServer,
  registerClient,
  registrationRequest,
  WEB_REDIRECT,
} from "./helpers.js"

const IP = { clientIp: "203.0.113.7" }

async function register(body: unknown, t = createTestServer()) {
  const response = await t.server.handleRegistration(
    registrationRequest(body),
    IP,
  )
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
    t,
  }
}

describe("Dynamic Client Registration (RFC 7591)", () => {
  describe("§3.2.1 successful response", () => {
    it("returns 201 with a generated client_id and the registered metadata", async () => {
      const { status, body } = await register({
        redirect_uris: [WEB_REDIRECT],
        client_name: "Notes Agent",
        token_endpoint_auth_method: "none",
      })
      expect(status).toBe(201)
      expect(body.client_id).toMatch(/^dyn_[A-Za-z0-9_-]{43}$/)
      expect(body.client_id_issued_at).toBeTypeOf("number")
      expect(body.redirect_uris).toEqual([WEB_REDIRECT])
      expect(body.client_name).toBe("Notes Agent")
      expect(body.token_endpoint_auth_method).toBe("none")
      expect(body.application_type).toBe("web")
    })

    it("uses the configured client_id prefix", async () => {
      const { body } = await register(
        { redirect_uris: [WEB_REDIRECT], token_endpoint_auth_method: "none" },
        createTestServer({ dynamicClientIdPrefix: "ff_dyn_" }),
      )
      expect(body.client_id).toMatch(/^ff_dyn_/)
    })

    it("allows public clients and gives them no secret", async () => {
      const { body } = await register({
        redirect_uris: [WEB_REDIRECT],
        token_endpoint_auth_method: "none",
      })
      expect(body).not.toHaveProperty("client_secret")
    })

    /** RFC 7591 §2: token_endpoint_auth_method defaults to client_secret_basic. */
    it("issues a secret to confidential clients and stores only its hash", async () => {
      const { body, t } = await register({ redirect_uris: [WEB_REDIRECT] })
      expect(body.token_endpoint_auth_method).toBe("client_secret_basic")
      expect(body.client_secret).toBeTypeOf("string")
      expect(body.client_secret_expires_at).toBe(0)
      const stored = await t.store.getClient(body.client_id as string)
      expect(stored?.clientSecretHash).toBe(
        await sha256Hex(body.client_secret as string),
      )
      expect(JSON.stringify(stored)).not.toContain(body.client_secret)
    })

    it("never stores or returns logo_uri", async () => {
      const { body, t } = await register({
        redirect_uris: [WEB_REDIRECT],
        token_endpoint_auth_method: "none",
        logo_uri: "https://evil.example/logo.png",
      })
      expect(body).not.toHaveProperty("logo_uri")
      const stored = await t.store.getClient(body.client_id as string)
      expect(JSON.stringify(stored)).not.toContain("logo")
    })
  })

  describe("application_type and redirect URIs", () => {
    it("lets a native client register loopback http redirects", async () => {
      const { status, body } = await register({
        application_type: "native",
        redirect_uris: [
          "http://127.0.0.1/callback",
          "http://[::1]/callback",
          "http://localhost:33418/callback",
        ],
        token_endpoint_auth_method: "none",
      })
      expect(status).toBe(201)
      expect(body.application_type).toBe("native")
    })

    it.each([
      ["https loopback", "https://127.0.0.1/callback"],
      ["a non-loopback host", "http://client.example/callback"],
      ["a custom scheme", "com.example.app:/callback"],
    ])("refuses a native client with %s", async (_label, uri) => {
      const { status, body } = await register({
        application_type: "native",
        redirect_uris: [uri],
      })
      expect(status).toBe(400)
      expect(body.error).toBe("invalid_redirect_uri")
    })

    it.each([
      ["http", "http://client.example/callback"],
      ["a loopback host", "https://localhost/callback"],
    ])("refuses a web client with %s", async (_label, uri) => {
      const { status, body } = await register({
        application_type: "web",
        redirect_uris: [uri],
      })
      expect(status).toBe(400)
      expect(body.error).toBe("invalid_redirect_uri")
    })

    it("infers native when every redirect is loopback", async () => {
      const { body } = await register({
        redirect_uris: ["http://localhost/callback"],
        token_endpoint_auth_method: "none",
      })
      expect(body.application_type).toBe("native")
    })

    it("infers web when every redirect is https", async () => {
      const { body } = await register({
        redirect_uris: [WEB_REDIRECT, "https://other.example/cb"],
        token_endpoint_auth_method: "none",
      })
      expect(body.application_type).toBe("web")
    })

    it("refuses a mix of loopback and https without application_type", async () => {
      const { status, body } = await register({
        redirect_uris: [WEB_REDIRECT, "http://127.0.0.1/callback"],
      })
      expect(status).toBe(400)
      expect(body.error).toBe("invalid_redirect_uri")
    })

    it("refuses an unknown application_type", async () => {
      const { status, body } = await register({
        application_type: "desktop",
        redirect_uris: [WEB_REDIRECT],
      })
      expect(status).toBe(400)
      expect(body.error).toBe("invalid_client_metadata")
    })

    /** RFC 6749 §3.1.2: the redirection endpoint URI MUST NOT include a fragment. */
    it("refuses a redirect URI with a fragment", async () => {
      const { status } = await register({
        redirect_uris: ["https://client.example/callback#frag"],
      })
      expect(status).toBe(400)
    })

    it("refuses a redirect URI with userinfo", async () => {
      const { status } = await register({
        redirect_uris: ["https://user:pass@client.example/callback"],
      })
      expect(status).toBe(400)
    })

    it("refuses missing, empty, or non-string redirect_uris", async () => {
      for (const redirectUris of [
        undefined,
        [],
        [42],
        "https://a.example/cb",
      ]) {
        const { status, body } = await register({ redirect_uris: redirectUris })
        expect(status).toBe(400)
        expect(body.error).toBe("invalid_redirect_uri")
      }
    })

    it("refuses more than 10 redirect URIs", async () => {
      const { status } = await register({
        redirect_uris: Array.from(
          { length: 11 },
          (_, index) => `https://client.example/cb${index}`,
        ),
      })
      expect(status).toBe(400)
    })
  })

  describe("own-host rule", () => {
    /**
     * The attack: a client registers a redirect on the issuer's host under
     * the app's name, so the consent page shows the app's own host as the
     * destination, and the code lands on a page the attacker controls there.
     */
    it("refuses a redirect URI on the issuer host posing as the app", async () => {
      const { status, body } = await register({
        redirect_uris: ["https://app.example/u/attacker/page.html"],
        client_name: "Fernfiles",
        token_endpoint_auth_method: "none",
      })
      expect(status).toBe(400)
      expect(body.error).toBe("invalid_redirect_uri")
    })

    it.each([
      ["the issuer host in upper case", "https://APP.example/cb"],
      ["the issuer host with a trailing dot", "https://app.example./cb"],
      ["the issuer host on another port", "https://app.example:8443/cb"],
      ["a subdomain of the issuer host", "https://pages.app.example/x/cb"],
      ["another host the app serves", "https://www.app.example/cb"],
      ["a subdomain of another own host", "https://u.files.example/cb"],
    ])("refuses a redirect URI on %s", async (_label, uri) => {
      const { status, body } = await register(
        { redirect_uris: [WEB_REDIRECT, uri] },
        createTestServer({ ownHosts: ["files.example"] }),
      )
      expect(status).toBe(400)
      expect(body.error).toBe("invalid_redirect_uri")
    })

    it("accepts a host that only ends with the issuer host's name", async () => {
      const { status } = await register({
        redirect_uris: ["https://notapp.example/cb"],
        token_endpoint_auth_method: "none",
      })
      expect(status).toBe(201)
    })

    it("lets a native client use loopback when the issuer is on localhost", async () => {
      const { status } = await register(
        {
          redirect_uris: ["http://localhost/callback"],
          token_endpoint_auth_method: "none",
        },
        createTestServer({ issuer: "http://localhost:5173" }),
      )
      expect(status).toBe(201)
    })
  })

  describe("§3.2.2 invalid metadata", () => {
    it.each([
      [
        "an unsupported auth method",
        { token_endpoint_auth_method: "private_key_jwt" },
      ],
      ["an unsupported grant type", { grant_types: ["client_credentials"] }],
      ["an unsupported response type", { response_types: ["token"] }],
      ["a non-string client_name", { client_name: 7 }],
    ])("refuses %s", async (_label, extra) => {
      const { status, body } = await register({
        redirect_uris: [WEB_REDIRECT],
        ...extra,
      })
      expect(status).toBe(400)
      expect(body.error).toBe("invalid_client_metadata")
    })

    it("refuses a body that is not JSON", async () => {
      const t = createTestServer()
      const response = await t.server.handleRegistration(
        new Request("https://app.example/oauth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{not json",
        }),
        IP,
      )
      expect(response.status).toBe(400)
    })

    it("refuses a non-JSON content type", async () => {
      const t = createTestServer()
      const response = await t.server.handleRegistration(
        new Request("https://app.example/oauth/register", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: "redirect_uris=https://client.example/cb",
        }),
        IP,
      )
      expect(response.status).toBe(400)
    })

    it("refuses a body over 16 KiB", async () => {
      const { status } = await register({
        redirect_uris: [WEB_REDIRECT],
        padding: "x".repeat(17 * 1024),
      })
      expect(status).toBe(400)
    })

    it("answers GET with 405", async () => {
      const t = createTestServer()
      const response = await t.server.handleRegistration(
        new Request("https://app.example/oauth/register"),
        IP,
      )
      expect(response.status).toBe(405)
    })
  })

  describe("client names", () => {
    it.each(["Claude", "claude", "Claude Desktop", "My ChatGPT helper"])(
      "refuses the reserved name %j",
      async (name) => {
        const { status, body } = await register({
          redirect_uris: [WEB_REDIRECT],
          client_name: name,
        })
        expect(status).toBe(400)
        expect(body.error).toBe("invalid_client_metadata")
      },
    )

    it("refuses a reserved name disguised with bidi and zero-width characters", async () => {
      const { status } = await register({
        redirect_uris: [WEB_REDIRECT],
        client_name: "Cl\u200Baude\u202E",
      })
      expect(status).toBe(400)
    })

    it("allows a name that only contains a reserved name inside a word", async () => {
      const { status } = await register({
        redirect_uris: [WEB_REDIRECT],
        client_name: "Claudette",
        token_endpoint_auth_method: "none",
      })
      expect(status).toBe(201)
    })

    it("strips control and bidi characters and caps the length", async () => {
      const { body } = await register({
        redirect_uris: [WEB_REDIRECT],
        token_endpoint_auth_method: "none",
        client_name: `Good\u202Egnp.exe\u0007 ${"x".repeat(200)}`,
      })
      const name = body.client_name as string
      expect(name.startsWith("Goodgnp.exe ")).toBe(true)
      expect(Array.from(name)).toHaveLength(64)
    })
  })

  describe("abuse limits", () => {
    it("rate-limits registrations per client IP", async () => {
      const t = createTestServer({
        rateLimits: { registrationPerIp: [{ windowSeconds: 60, max: 2 }] },
      })
      const body = {
        redirect_uris: [WEB_REDIRECT],
        token_endpoint_auth_method: "none",
      }
      for (let attempt = 0; attempt < 2; attempt++) {
        const ok = await t.server.handleRegistration(
          registrationRequest(body),
          IP,
        )
        expect(ok.status).toBe(201)
      }
      const blocked = await t.server.handleRegistration(
        registrationRequest(body),
        IP,
      )
      expect(blocked.status).toBe(429)
      expect(blocked.headers.get("Retry-After")).toMatch(/^\d+$/)
      const otherIp = await t.server.handleRegistration(
        registrationRequest(body),
        {
          clientIp: "198.51.100.1",
        },
      )
      expect(otherIp.status).toBe(201)
    })

    it("ignores X-Forwarded-For; only the clientIp the app passes counts", async () => {
      const t = createTestServer({
        rateLimits: { registrationPerIp: [{ windowSeconds: 60, max: 1 }] },
      })
      const body = {
        redirect_uris: [WEB_REDIRECT],
        token_endpoint_auth_method: "none",
      }
      await t.server.handleRegistration(registrationRequest(body), IP)
      const spoofed = await t.server.handleRegistration(
        registrationRequest(body, { "X-Forwarded-For": "192.0.2.99" }),
        IP,
      )
      expect(spoofed.status).toBe(429)
    })

    it("returns 404 when dynamic registration is off", async () => {
      const { status } = await register(
        { redirect_uris: [WEB_REDIRECT] },
        createTestServer({ dynamicRegistration: false }),
      )
      expect(status).toBe(404)
    })

    it("prunes dynamic clients with no grant after 24 hours, keeping granted ones", async () => {
      const t = createTestServer()
      const unused = await registerClient(t)
      const used = await registerClient(t)
      await t.store.upsertGrant(
        {
          userId: "user-1",
          clientId: used.client_id!,
          scopes: ["files:read"],
          resource: "https://app.example/mcp",
        },
        t.clock.now,
      )
      t.clock.advance(23 * 3600)
      expect(await t.server.pruneDynamicClients()).toBe(0)
      t.clock.advance(2 * 3600)
      expect(await t.server.pruneDynamicClients()).toBe(1)
      expect(await t.store.getClient(unused.client_id!)).toBeNull()
      expect(await t.store.getClient(used.client_id!)).not.toBeNull()
    })
  })
})

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import type { AuthUser, InitiateGate } from "@activescott/auth"
import { OidcProvider } from "../oidc-provider.js"
import {
  MOCK_CLIENT_ID,
  MOCK_CLIENT_SECRET,
  MOCK_ISSUER,
  MockIdp,
} from "./mock-idp.js"
import { createMemoryStores } from "./memory-stores.js"

const APP = "https://app.example"
const COOKIE = "auth_okta_oidc"
const IDENTIFIER = `${MOCK_ISSUER}|subject-1`

let idp: MockIdp
let challengeStore: InMemoryChallengeStore
let stores: ReturnType<typeof createMemoryStores>
let auth: Auth

function createAuth(gate?: InitiateGate): Auth {
  return new Auth({
    session: {
      secret: "test-secret-that-is-at-least-32-characters",
      maxAge: "1d",
      cookieName: "session",
      cookie: { secure: true, sameSite: "lax" },
      cacheTtlMs: 0,
    },
    identityStore: stores.identityStore,
    userStore: stores.userStore,
    challengeStore,
    providers: [
      new OidcProvider({
        id: "okta",
        name: "Okta",
        issuer: MOCK_ISSUER,
        clientId: MOCK_CLIENT_ID,
        clientSecret: MOCK_CLIENT_SECRET,
        scopes: ["openid", "email"],
        fetch: idp.fetch,
      }),
    ],
    ...(gate ? { gate } : {}),
  })
}

beforeEach(async () => {
  idp = await MockIdp.create()
  challengeStore = new InMemoryChallengeStore()
  stores = createMemoryStores()
  auth = createAuth()
})

afterEach(() => {
  auth.destroy()
  challengeStore.destroy()
})

function cookieValue(setCookie: string): string {
  return setCookie.split(";")[0] ?? ""
}

/** GET /auth/okta/start and return where it sends the browser */
async function start(
  query: Record<string, string> = {},
  cookie?: string,
): Promise<{ response: Response; location: string; challengeCookie: string }> {
  const url = new URL(`${APP}/auth/okta/start`)
  for (const [name, value] of Object.entries(query)) {
    url.searchParams.set(name, value)
  }
  const response = await auth.handleRequest(
    new Request(url, { headers: cookie ? { Cookie: cookie } : {} }),
  )
  const challengeCookie =
    response.headers.getSetCookie().find((c) => c.startsWith(`${COOKIE}=`)) ??
    ""
  return {
    response,
    location: response.headers.get("location") ?? "",
    challengeCookie: cookieValue(challengeCookie),
  }
}

async function callback(url: string, cookie: string): Promise<Response> {
  return auth.handleRequest(new Request(url, { headers: { Cookie: cookie } }))
}

/** Start, approve at the mock IdP, and return the callback response */
async function signIn(
  claims = {},
  cookie?: string,
  query: Record<string, string> = {},
): Promise<Response> {
  const started = await start(query, cookie)
  const callbackUrl = idp.authorize(started.location, claims)
  return callback(
    callbackUrl,
    [started.challengeCookie, cookie].filter(Boolean).join("; "),
  )
}

async function errorOf(
  response: Response,
): Promise<{ code: string; details?: Record<string, unknown> }> {
  const body = (await response.json()) as {
    error: { code: string; details?: Record<string, unknown> }
  }
  return body.error
}

describe("OidcProvider start", () => {
  it("redirects to the authorization endpoint with PKCE, state and nonce", async () => {
    const { response, location, challengeCookie } = await start()

    expect(response.status).toBe(302)
    const url = new URL(location)
    expect(`${url.origin}${url.pathname}`).toBe(`${MOCK_ISSUER}/authorize`)
    expect(url.searchParams.get("response_type")).toBe("code")
    expect(url.searchParams.get("client_id")).toBe(MOCK_CLIENT_ID)
    expect(url.searchParams.get("redirect_uri")).toBe(
      `${APP}/auth/okta/callback`,
    )
    expect(url.searchParams.get("scope")).toBe("openid email")
    expect(url.searchParams.get("code_challenge_method")).toBe("S256")
    expect(url.searchParams.get("code_challenge")).toMatch(/^[\w-]{43}$/)

    const challengeId = challengeCookie.split("=")[1] ?? ""
    const challenge = await challengeStore.findById(challengeId)
    expect(challenge?.type).toBe("oidc")
    expect(challenge?.data?.state).toBe(url.searchParams.get("state"))
    expect(challenge?.data?.nonce).toBe(url.searchParams.get("nonce"))
    // The verifier stays server-side; only its hash goes to the IdP
    expect(challenge?.data?.codeVerifier).toBeTypeOf("string")
    expect(location).not.toContain(String(challenge?.data?.codeVerifier))
  })

  it("refuses a discovery document naming another issuer", async () => {
    idp.discoveryOverrides = { issuer: "https://evil.example" }
    const { response, location, challengeCookie } = await start()

    expect(response.status).toBe(302)
    expect(new URL(location).searchParams.get("error")).toBe("PROVIDER_ERROR")
    expect(challengeCookie).toBe("")
  })

  it("refuses to start a link without a session", async () => {
    const { location, challengeCookie } = await start({ mode: "link" })

    expect(new URL(location).searchParams.get("error")).toBe("SESSION_INVALID")
    expect(challengeCookie).toBe("")
  })
})

describe("OidcProvider sign-in", () => {
  it("creates a user keyed on issuer and subject", async () => {
    const response = await signIn()

    expect(response.status).toBe(200)
    expect(stores.users).toHaveLength(1)
    expect(stores.identities).toMatchObject([
      {
        userId: "user-1",
        provider: "okta",
        identifier: IDENTIFIER,
        providerState: { iss: MOCK_ISSUER, sub: "subject-1" },
      },
    ])
    expect(response.headers.getSetCookie()).toContainEqual(
      expect.stringMatching(new RegExp(`^${COOKIE}=;.*Max-Age=0`)),
    )
  })

  it("sends client_secret_basic and the PKCE verifier to the token endpoint", async () => {
    await signIn()

    const [request] = idp.tokenRequests
    expect(request?.headers.get("authorization")).toMatch(/^Basic /)
    expect(request?.body.get("client_secret")).toBeNull()
    expect(request?.body.get("code_verifier")).toMatch(/^[\w-]{43}$/)
  })

  it("falls back to client_secret_post when basic is not offered", async () => {
    idp.discoveryOverrides = {
      token_endpoint_auth_methods_supported: ["client_secret_post"],
    }
    const response = await signIn()

    expect(response.status).toBe(200)
    expect(idp.tokenRequests[0]?.body.get("client_secret")).toBe(
      MOCK_CLIENT_SECRET,
    )
  })

  it("signs a returning user in to the same account", async () => {
    await signIn()
    const response = await signIn()

    expect(response.status).toBe(200)
    expect(stores.users).toHaveLength(1)
    expect(stores.identities).toHaveLength(1)
  })

  it("consults the gate with the verified identifier before creating a user", async () => {
    const gate: InitiateGate = {
      onInitiate: vi.fn().mockResolvedValue({
        error: { code: "INVALID_CREDENTIALS", message: "Not invited" },
      }),
    }
    auth.destroy()
    auth = createAuth(gate)

    const response = await signIn()

    expect(response.status).toBe(401)
    expect(gate.onInitiate).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "okta",
        identifier: IDENTIFIER,
        mode: "signin",
      }),
    )
    expect(stores.users).toHaveLength(0)
  })
})

describe("OidcProvider callback rejections", () => {
  const now = () => Math.floor(Date.now() / 1000)

  it.each([
    ["wrong issuer", { iss: "https://evil.example" }, "issuer"],
    ["wrong audience", { aud: "someone-else" }, "audience"],
    [
      "an additional audience",
      { aud: [MOCK_CLIENT_ID, "someone-else"] },
      "audience",
    ],
    ["azp naming another client", { azp: "someone-else" }, "azp"],
    ["an expired token", { iat: now() - 400, exp: now() - 120 }, "expired"],
    ["iat in the future", { iat: now() + 3600, exp: now() + 7200 }, "iat"],
    ["iat too long ago", { iat: now() - 3600, exp: now() + 300 }, "iat"],
    ["a bad nonce", { nonce: "not-the-nonce" }, "nonce"],
  ])("rejects %s", async (_label, claims, check) => {
    idp.tamper = { claims }
    const response = await signIn()

    expect(response.status).toBe(401)
    expect(await errorOf(response)).toMatchObject({
      code: "INVALID_TOKEN",
      details: { check },
    })
    expect(stores.users).toHaveLength(0)
  })

  it("rejects a token signed with a key not in the JWKS", async () => {
    idp.tamper = { signWithForeignKey: true }
    const response = await signIn()

    expect(response.status).toBe(401)
    expect(await errorOf(response)).toMatchObject({
      code: "INVALID_TOKEN",
      details: { check: "signature" },
    })
    expect(stores.users).toHaveLength(0)
  })

  it("rejects a state that does not match the challenge", async () => {
    const started = await start()
    const callbackUrl = new URL(idp.authorize(started.location))
    callbackUrl.searchParams.set("state", "forged-state")

    const response = await callback(
      callbackUrl.toString(),
      started.challengeCookie,
    )

    expect(response.status).toBe(401)
    expect(await errorOf(response)).toMatchObject({
      code: "INVALID_TOKEN",
      details: { reason: "State mismatch" },
    })
    expect(idp.tokenRequests).toHaveLength(0)
  })

  it("fails when the PKCE verifier does not match the challenge", async () => {
    const started = await start()
    const callbackUrl = idp.authorize(started.location)
    const challenge = await challengeStore.findById(
      started.challengeCookie.split("=")[1] ?? "",
    )
    if (!challenge?.data) throw new Error("challenge not stored")
    challenge.data.codeVerifier = "a-different-verifier-of-sufficient-length-00"

    const response = await callback(callbackUrl, started.challengeCookie)

    expect(response.status).toBe(401)
    expect(await errorOf(response)).toMatchObject({
      code: "INVALID_CREDENTIALS",
      details: { check: "token_request" },
    })
    expect(stores.users).toHaveLength(0)
  })

  it("rejects a callback replayed after it was used", async () => {
    const started = await start()
    const callbackUrl = idp.authorize(started.location)
    expect((await callback(callbackUrl, started.challengeCookie)).status).toBe(
      200,
    )

    const replay = await callback(callbackUrl, started.challengeCookie)

    expect(replay.status).toBe(401)
    expect(await errorOf(replay)).toMatchObject({ code: "INVALID_CREDENTIALS" })
  })

  it("rejects a callback from a browser that did not start the flow", async () => {
    const started = await start()
    const response = await callback(idp.authorize(started.location), "")

    expect(response.status).toBe(401)
    expect(idp.tokenRequests).toHaveLength(0)
  })

  it("reports an error the IdP sent back instead of a code", async () => {
    const started = await start()
    const state = new URL(started.location).searchParams.get("state") ?? ""
    const response = await callback(
      `${APP}/auth/okta/callback?error=access_denied&state=${state}`,
      started.challengeCookie,
    )

    expect(response.status).toBe(401)
    expect(await errorOf(response)).toMatchObject({
      code: "INVALID_CREDENTIALS",
      details: { reason: "Okta returned access_denied" },
    })
  })
})

describe("OidcProvider link", () => {
  let sessionCookie: string

  beforeEach(async () => {
    const user: AuthUser = { id: "user-1" }
    stores.users.push(user)
    const email = await stores.identityStore.create({
      userId: user.id,
      provider: "email",
      identifier: "a@example.com",
      providerState: {},
    })
    sessionCookie = cookieValue(await auth.createSessionCookie(user, email))
  })

  it("attaches the identity to the signed-in user without a session cookie", async () => {
    const response = await signIn({}, sessionCookie, {
      mode: "link",
      redirectTo: "/settings",
    })

    expect(response.status).toBe(302)
    expect(response.headers.get("location")).toBe("/settings")
    const cookies = response.headers.getSetCookie()
    expect(cookies.some((c) => c.startsWith("session="))).toBe(false)
    expect(cookies).toContainEqual(expect.stringMatching(`^${COOKIE}=;`))

    const identity = stores.identities.find((i) => i.provider === "okta")
    expect(identity).toMatchObject({
      userId: "user-1",
      identifier: IDENTIFIER,
      providerState: { iss: MOCK_ISSUER, sub: "subject-1" },
    })
    expect(stores.users).toHaveLength(1)
    expect(stores.linked).toHaveLength(1)
  })

  it("lands on linkRedirect when the start named no destination", async () => {
    const response = await signIn({}, sessionCookie, { mode: "link" })

    expect(response.headers.get("location")).toBe("/")
  })

  it("does not follow a redirectTo on another origin", async () => {
    const response = await signIn({}, sessionCookie, {
      mode: "link",
      redirectTo: "https://evil.example/",
    })

    expect(response.headers.get("location")).toBe("/")
  })

  it("refuses to finish when the session is gone", async () => {
    const started = await start({ mode: "link" }, sessionCookie)
    const response = await callback(
      idp.authorize(started.location),
      started.challengeCookie,
    )

    expect(response.status).toBe(401)
    expect(await errorOf(response)).toMatchObject({ code: "SESSION_INVALID" })
    expect(stores.identities.some((i) => i.provider === "okta")).toBe(false)
  })

  it("answers IDENTITY_CONFLICT with a merge ticket when another user has the identity", async () => {
    stores.users.push({ id: "user-2" })
    await stores.identityStore.create({
      userId: "user-2",
      provider: "okta",
      identifier: IDENTIFIER,
      providerState: {},
    })

    const response = await signIn({}, sessionCookie, { mode: "link" })

    expect(response.status).toBe(409)
    expect(await errorOf(response)).toMatchObject({ code: "IDENTITY_CONFLICT" })
    expect(response.headers.getSetCookie()).toContainEqual(
      expect.stringMatching(/^auth_merge_ticket=[\w-]+;/),
    )
  })
})

describe("OidcProvider describe", () => {
  it("never reports the client secret", () => {
    const settings = auth.getProvider("okta")?.describe().settings ?? {}

    expect(settings).toMatchObject({
      issuer: MOCK_ISSUER,
      clientId: MOCK_CLIENT_ID,
    })
    expect(JSON.stringify(settings)).not.toContain(MOCK_CLIENT_SECRET)
  })
})

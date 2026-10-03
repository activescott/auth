import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import type { AuthUser } from "@activescott/auth"
import {
  createSlackProvider,
  slackIdentityState,
  SLACK_ISSUER,
  SLACK_TEAM_ID_CLAIM,
  SLACK_USER_ID_CLAIM,
} from "../slack.js"
import { MOCK_CLIENT_ID, MOCK_CLIENT_SECRET, MockIdp } from "./mock-idp.js"
import { createMemoryStores } from "./memory-stores.js"

const APP = "https://app.example"
const SLACK_CLAIMS = {
  sub: "U0123",
  [SLACK_USER_ID_CLAIM]: "U0123",
  [SLACK_TEAM_ID_CLAIM]: "T0456",
  email: "someone@example.com",
  email_verified: true,
}

let idp: MockIdp
let challengeStore: InMemoryChallengeStore
let stores: ReturnType<typeof createMemoryStores>
let auth: Auth
let tokenFetch: typeof fetch | undefined

beforeEach(async () => {
  idp = await MockIdp.create(SLACK_ISSUER)
  tokenFetch = undefined
  challengeStore = new InMemoryChallengeStore()
  stores = createMemoryStores()
  auth = new Auth({
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
      createSlackProvider({
        clientId: MOCK_CLIENT_ID,
        clientSecret: MOCK_CLIENT_SECRET,
        fetch: (input, init) =>
          tokenFetch && String(input).endsWith("/token")
            ? tokenFetch(input, init)
            : idp.fetch(input, init),
      }),
    ],
  })
})

afterEach(() => {
  auth.destroy()
  challengeStore.destroy()
})

async function flow(
  claims: Record<string, unknown>,
  cookie = "",
  query = "",
): Promise<{ authorizationUrl: string; response: Response }> {
  const started = await auth.handleRequest(
    new Request(`${APP}/auth/slack/start${query}`, {
      headers: { Cookie: cookie },
    }),
  )
  const authorizationUrl = started.headers.get("location") ?? ""
  const challengeCookie = started.headers.getSetCookie()[0]?.split(";")[0] ?? ""
  const response = await auth.handleRequest(
    new Request(idp.authorize(authorizationUrl, claims), {
      headers: { Cookie: [challengeCookie, cookie].filter(Boolean).join("; ") },
    }),
  )
  return { authorizationUrl, response }
}

describe("createSlackProvider", () => {
  it("requests openid profile email from Slack's discovery endpoints", async () => {
    const { authorizationUrl } = await flow(SLACK_CLAIMS)

    const url = new URL(authorizationUrl)
    expect(`${url.origin}${url.pathname}`).toBe(`${SLACK_ISSUER}/authorize`)
    expect(url.searchParams.get("scope")).toBe("openid profile email")
    expect(url.searchParams.get("redirect_uri")).toBe(
      `${APP}/auth/slack/callback`,
    )
  })

  it("keys the identity on team and user and stores both", async () => {
    const { response } = await flow(SLACK_CLAIMS)

    expect(response.status).toBe(200)
    const [identity] = stores.identities
    expect(identity).toMatchObject({
      provider: "slack",
      identifier: "T0456:U0123",
    })
    expect(identity && slackIdentityState(identity)).toEqual({
      teamId: "T0456",
      userId: "U0123",
    })
  })

  it("links a Slack identity to the signed-in user", async () => {
    const user: AuthUser = { id: "user-1" }
    stores.users.push(user)
    const email = await stores.identityStore.create({
      userId: user.id,
      provider: "email",
      identifier: "a@example.com",
      providerState: {},
    })
    const session =
      (await auth.createSessionCookie(user, email)).split(";")[0] ?? ""

    const { response } = await flow(
      SLACK_CLAIMS,
      session,
      "?mode=link&redirectTo=/agents/1",
    )

    expect(response.status).toBe(302)
    expect(response.headers.get("location")).toBe("/agents/1")
    expect(
      response.headers.getSetCookie().some((c) => c.startsWith("session=")),
    ).toBe(false)
    const slack = stores.identities.find((i) => i.provider === "slack")
    expect(slack?.userId).toBe("user-1")
    expect(slack && slackIdentityState(slack)).toEqual({
      teamId: "T0456",
      userId: "U0123",
    })
  })

  it("rejects an ID token without a team ID", async () => {
    const { response } = await flow({
      ...SLACK_CLAIMS,
      [SLACK_TEAM_ID_CLAIM]: undefined,
    })

    expect(response.status).toBe(401)
    const body = (await response.json()) as { error: unknown }
    expect(body.error).toMatchObject({
      code: "INVALID_TOKEN",
      details: { check: "claims" },
    })
    expect(stores.users).toHaveLength(0)
  })

  it("treats Slack's ok: false token response as a refused code", async () => {
    tokenFetch = async () => Response.json({ ok: false, error: "invalid_code" })

    const { response } = await flow(SLACK_CLAIMS)

    expect(response.status).toBe(401)
    const body = (await response.json()) as { error: unknown }
    expect(body.error).toMatchObject({
      code: "INVALID_CREDENTIALS",
      details: { check: "token_request" },
    })
  })
})

describe("slackIdentityState", () => {
  it("returns undefined for an identity from another provider", () => {
    expect(slackIdentityState({ providerState: {} })).toBeUndefined()
  })
})

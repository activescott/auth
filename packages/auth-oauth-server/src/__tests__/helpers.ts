import { afterEach, vi } from "vitest"
import { s256Challenge, randomToken } from "../crypto.js"
import { OAuthServer } from "../oauth-server.js"
import { InMemoryOAuthStore } from "../stores/in-memory-oauth-store.js"
import type {
  AuthorizeErrorPage,
  ClientMetadataFetcher,
  ConsentPrompt,
  OAuthServerConfig,
} from "../types.js"

export const ISSUER = "https://app.example"
export const RESOURCE = "https://app.example/mcp"
export const USER = "user-1"
export const WEB_REDIRECT = "https://client.example/callback"
export const LOOPBACK_REDIRECT = "http://127.0.0.1/callback"
export const CIMD_CLIENT_ID = "https://client.example/oauth/client.json"

const servers: OAuthServer[] = []
afterEach(() => {
  for (const server of servers.splice(0)) server.destroy()
})

/** A clock tests move by hand. */
export class TestClock {
  public now = new Date("2026-10-01T12:00:00Z")

  public advance(seconds: number): void {
    this.now = new Date(this.now.getTime() + seconds * 1000)
  }
}

export type TestServer = ReturnType<typeof createTestServer>

/**
 * An OAuthServer over an in-memory store, with a fake clock, a mock CIMD
 * fetcher, and consent and error renderers that record what they were given.
 */
export function createTestServer(overrides: Partial<OAuthServerConfig> = {}) {
  const store = new InMemoryOAuthStore()
  const clock = new TestClock()
  const fetchClientMetadata = vi.fn<ClientMetadataFetcher>()
  const prompts: ConsentPrompt[] = []
  const errors: AuthorizeErrorPage[] = []
  const blockedUsers = new Set<string>()
  const server = new OAuthServer({
    issuer: ISSUER,
    store,
    resource: {
      uri: RESOURCE,
      scopes: ["files:read", "files:write"],
      defaultScopes: ["files:read"],
      optionalScopes: ["files:write"],
    },
    renderConsent: (prompt) => {
      prompts.push(prompt)
      return new Response("<form>consent</form>", {
        headers: { "Content-Type": "text/html" },
      })
    },
    renderError: (error) => {
      errors.push(error)
      return new Response(error.description, { status: 400 })
    },
    fetchClientMetadata,
    reservedClientNames: ["Claude", "ChatGPT"],
    isUserActive: (userId) => !blockedUsers.has(userId),
    now: () => clock.now,
    ...overrides,
  })
  servers.push(server)
  return {
    server,
    store,
    clock,
    fetchClientMetadata,
    prompts,
    errors,
    blockedUsers,
  }
}

/** POST a JSON registration request. */
export function registrationRequest(
  body: unknown,
  headers: Record<string, string> = {},
): Request {
  return new Request(`${ISSUER}/oauth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  })
}

/** Register a client by DCR and return the response body. */
export async function registerClient(
  t: TestServer,
  body: Record<string, unknown> = {
    redirect_uris: [WEB_REDIRECT],
    client_name: "Test Client",
    token_endpoint_auth_method: "none",
  },
): Promise<Record<string, string>> {
  const response = await t.server.handleRegistration(
    registrationRequest(body),
    {
      clientIp: "203.0.113.7",
    },
  )
  if (response.status !== 201) {
    throw new Error(`registration failed: ${await response.text()}`)
  }
  return (await response.json()) as Record<string, string>
}

/** A PKCE verifier and its S256 challenge. */
export async function pkcePair(): Promise<{
  verifier: string
  challenge: string
}> {
  const verifier = randomToken()
  return { verifier, challenge: await s256Challenge(verifier) }
}

/** GET the authorization endpoint with these query parameters. */
export function authorizeRequest(params: Record<string, string>): Request {
  return new Request(
    `${ISSUER}/oauth/authorize?${new URLSearchParams(params).toString()}`,
  )
}

/** Valid authorization request parameters, overridable. */
export function authorizeParams(
  clientId: string,
  challenge: string,
  overrides: Record<string, string | undefined> = {},
): Record<string, string> {
  const params: Record<string, string | undefined> = {
    response_type: "code",
    client_id: clientId,
    redirect_uri: WEB_REDIRECT,
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: RESOURCE,
    scope: "files:read",
    state: "state-123",
    ...overrides,
  }
  return Object.fromEntries(
    Object.entries(params).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  )
}

/** POST the consent form. */
export function consentRequest(
  fields: Record<string, string | string[]>,
): Request {
  const body = new URLSearchParams()
  for (const [name, value] of Object.entries(fields)) {
    for (const item of Array.isArray(value) ? value : [value]) {
      body.append(name, item)
    }
  }
  return new Request(`${ISSUER}/oauth/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  })
}

/** Approve or deny a rendered consent prompt. */
export function answerConsent(
  t: TestServer,
  prompt: ConsentPrompt,
  options: { decision?: string; scopes?: string[]; userId?: string } = {},
): Promise<Response> {
  return t.server.handleAuthorization(
    consentRequest({
      ...prompt.fields,
      decision: options.decision ?? "approve",
      scope: options.scopes ?? [],
    }),
    { userId: options.userId ?? USER },
  )
}

/** Query parameters of a redirect response's Location. */
export function locationParams(response: Response): URLSearchParams {
  const location = response.headers.get("Location")
  if (!location) throw new Error(`no Location (status ${response.status})`)
  return new URL(location).searchParams
}

/**
 * Run authorize and consent for a client and return the code with what the
 * token request needs.
 */
export async function obtainCode(
  t: TestServer,
  options: {
    clientId: string
    redirectUri?: string
    scope?: string
    scopes?: string[]
    userId?: string
  },
): Promise<{ code: string; verifier: string; redirectUri: string }> {
  const { verifier, challenge } = await pkcePair()
  const redirectUri = options.redirectUri ?? WEB_REDIRECT
  const response = await t.server.handleAuthorization(
    authorizeRequest(
      authorizeParams(options.clientId, challenge, {
        redirect_uri: redirectUri,
        scope: options.scope ?? "files:read",
      }),
    ),
    { userId: options.userId ?? USER },
  )
  if (response.status !== 200) {
    throw new Error(`authorize failed: ${response.status}`)
  }
  const prompt = t.prompts.at(-1)!
  const answer = await answerConsent(t, prompt, {
    scopes: options.scopes,
    userId: options.userId,
  })
  const code = locationParams(answer).get("code")
  if (!code) throw new Error("no code in redirect")
  return { code, verifier, redirectUri }
}

/** POST a URL-encoded body to the token endpoint. */
export function tokenRequest(
  params: Record<string, string>,
  headers: Record<string, string> = {},
): Request {
  return new Request(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams(params).toString(),
  })
}

/** Register a public client, authorize, and redeem the code. */
export async function obtainTokens(
  t: TestServer,
  options: { scope?: string; scopes?: string[] } = {},
): Promise<{
  clientId: string
  accessToken: string
  refreshToken: string
  body: Record<string, unknown>
}> {
  const { client_id: clientId } = await registerClient(t)
  const { code, verifier, redirectUri } = await obtainCode(t, {
    clientId: clientId!,
    ...options,
  })
  const response = await t.server.handleToken(
    tokenRequest({
      grant_type: "authorization_code",
      client_id: clientId!,
      code,
      code_verifier: verifier,
      redirect_uri: redirectUri,
      resource: RESOURCE,
    }),
  )
  const body = (await response.json()) as Record<string, unknown>
  if (response.status !== 200) {
    throw new Error(`token failed: ${JSON.stringify(body)}`)
  }
  return {
    clientId: clientId!,
    accessToken: body.access_token as string,
    refreshToken: body.refresh_token as string,
    body,
  }
}

/** Exchange a refresh token. */
export function refreshRequest(
  clientId: string,
  refreshToken: string,
  extra: Record<string, string> = {},
): Request {
  return tokenRequest({
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: refreshToken,
    ...extra,
  })
}

/** A request to the protected resource with a bearer token. */
export function resourceRequest(accessToken?: string): Request {
  return new Request(RESOURCE, {
    method: "POST",
    headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
  })
}

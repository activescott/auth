import { describe, it, expect, vi, afterEach } from "vitest"
import type {
  AuthContext,
  Identity,
  IdentityStore,
  UserStore,
} from "@activescott/auth"
import { InMemoryChallengeStore } from "@activescott/auth"
import { PasskeyProvider } from "../passkey-provider.js"
import type { PasskeyProviderConfig, WebAuthnServer } from "../types.js"

const BASE_URL = "https://example.com"
const CHALLENGE_SECRET = "test-challenge-secret"
const COOKIE_NAME = "auth_passkey_challenge"

const REG_OPTIONS = {
  challenge: "reg-challenge",
  rp: { name: "Test App", id: "example.com" },
  user: {
    id: "dXNlci0x",
    name: "user@example.com",
    displayName: "user@example.com",
  },
  pubKeyCredParams: [],
}

const AUTH_OPTIONS = {
  challenge: "auth-challenge",
  rpId: "example.com",
  allowCredentials: [],
}

const VERIFIED_REGISTRATION = {
  verified: true,
  registrationInfo: {
    fmt: "none" as const,
    aaguid: "00000000-0000-0000-0000-000000000000",
    credential: {
      id: "cred-1",
      publicKey: new Uint8Array([1, 2, 3]),
      counter: 0,
      transports: ["internal" as const],
    },
    credentialType: "public-key" as const,
    attestationObject: new Uint8Array([4, 5, 6]),
    userVerified: true,
    credentialDeviceType: "multiDevice" as const,
    credentialBackedUp: true,
    origin: BASE_URL,
    rpID: "example.com",
  },
}

const VERIFIED_AUTHENTICATION = {
  verified: true,
  authenticationInfo: {
    newCounter: 1,
    credentialID: "cred-1",
    userVerified: true,
    credentialDeviceType: "multiDevice" as const,
    credentialBackedUp: true,
    origin: BASE_URL,
    rpID: "example.com",
  },
}

/** Credential state as stored in Identity.metadata by the provider */
function credentialMetadata(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    publicKey: "AQID",
    counter: 0,
    deviceType: "multiDevice",
    backedUp: true,
    ...overrides,
  }
}

function createFakeWebAuthn(): WebAuthnServer {
  return {
    generateRegistrationOptions: vi.fn(async () => REG_OPTIONS),
    verifyRegistrationResponse: vi.fn(async () => VERIFIED_REGISTRATION),
    generateAuthenticationOptions: vi.fn(async () => AUTH_OPTIONS),
    verifyAuthenticationResponse: vi.fn(async () => VERIFIED_AUTHENTICATION),
  }
}

/**
 * Real (stateful) in-memory IdentityStore so tests exercise the actual
 * create/find/update round trip the provider depends on
 */
class TestIdentityStore implements IdentityStore {
  public identities = new Map<string, Identity>()
  private nextId = 1

  public async findByProviderAndIdentifier(
    provider: string,
    identifier: string,
  ): Promise<Identity | null> {
    for (const identity of this.identities.values()) {
      if (identity.provider === provider && identity.identifier === identifier)
        return identity
    }
    return null
  }

  public async findByUserId(userId: string): Promise<Identity[]> {
    return [...this.identities.values()].filter(
      (identity) => identity.userId === userId,
    )
  }

  public async create(data: {
    userId: string
    provider: string
    identifier: string
    metadata: Record<string, unknown>
  }): Promise<Identity> {
    const identity: Identity = {
      id: `identity-${this.nextId++}`,
      createdAt: new Date(),
      ...data,
    }
    this.identities.set(identity.id, identity)
    return identity
  }

  public async update(
    id: string,
    data: Partial<Pick<Identity, "metadata" | "verifiedAt">>,
  ): Promise<Identity> {
    const existing = this.identities.get(id)
    if (!existing) throw new Error(`Identity ${id} not found`)
    const updated = { ...existing, ...data }
    this.identities.set(id, updated)
    return updated
  }
}

function createContext(overrides: Partial<AuthContext> = {}): AuthContext {
  const userStore: UserStore = {
    findById: vi.fn().mockResolvedValue({ id: "user-1" }),
    create: vi.fn().mockResolvedValue({ id: "user-1" }),
  }
  return {
    identityStore: new TestIdentityStore(),
    userStore,
    // Real store: challenges are recorded on options and consumed on
    // verify, so mocks would break every verify path
    challengeStore: new InMemoryChallengeStore(),
    baseUrl: BASE_URL,
    createSession: vi
      .fn()
      .mockResolvedValue("auth_session=session-token; Path=/; HttpOnly"),
    getSession: vi.fn().mockResolvedValue({
      user: { id: "user-1" },
      identity: {
        id: "identity-email",
        userId: "user-1",
        provider: "email",
        identifier: "user@example.com",
        metadata: {},
        createdAt: new Date(),
      },
    }),
    ...overrides,
  }
}

function createProvider(
  configOverrides: Partial<PasskeyProviderConfig> = {},
  webauthn: WebAuthnServer = createFakeWebAuthn(),
): {
  provider: PasskeyProvider
  webauthn: WebAuthnServer
  config: PasskeyProviderConfig
} {
  const config: PasskeyProviderConfig = {
    rpName: "Test App",
    challengeSecret: CHALLENGE_SECRET,
    ...configOverrides,
  }
  return { provider: new PasskeyProvider(config, webauthn), webauthn, config }
}

function postRequest(action: string, body: object, cookie?: string): Request {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  }
  if (cookie) headers.Cookie = cookie
  return new Request(`${BASE_URL}/auth/passkey/${action}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  })
}

/** Extract the challenge cookie pair ("name=jwt") from an options response */
function challengeCookieFrom(response: Response): string {
  const setCookie = response.headers
    .getSetCookie()
    .find((value) => value.startsWith(`${COOKIE_NAME}=`))
  expect(setCookie).toBeDefined()
  return (setCookie ?? "").split(";")[0] ?? ""
}

function registrationBody(overrides: Record<string, unknown> = {}): object {
  return {
    id: "cred-1",
    rawId: "cred-1",
    response: { clientDataJSON: "e30", attestationObject: "e30" },
    type: "public-key",
    clientExtensionResults: {},
    ...overrides,
  }
}

function authenticationBody(overrides: Record<string, unknown> = {}): object {
  return {
    id: "cred-1",
    rawId: "cred-1",
    response: {
      clientDataJSON: "e30",
      authenticatorData: "e30",
      signature: "e30",
    },
    type: "public-key",
    clientExtensionResults: {},
    ...overrides,
  }
}

async function seedPasskeyIdentity(
  context: AuthContext,
  metadata: Record<string, unknown> = credentialMetadata(),
): Promise<Identity> {
  return context.identityStore.create({
    userId: "user-1",
    provider: "passkey",
    identifier: "cred-1",
    metadata,
  })
}

async function registeredCredentialSetup(
  configOverrides: Partial<PasskeyProviderConfig> = {},
): Promise<{
  provider: PasskeyProvider
  webauthn: WebAuthnServer
  config: PasskeyProviderConfig
  context: AuthContext
  authCookie: string
}> {
  const { provider, webauthn, config } = createProvider(configOverrides)
  const context = createContext()

  await seedPasskeyIdentity(context)

  const optionsResponse = await provider.handleAction(
    "authenticate-options",
    postRequest("authenticate-options", {}),
    context,
  )
  const authCookie = challengeCookieFrom(optionsResponse)

  return { provider, webauthn, config, context, authCookie }
}

async function findPasskeyIdentity(
  context: AuthContext,
): Promise<Identity | null> {
  return context.identityStore.findByProviderAndIdentifier("passkey", "cred-1")
}

describe("PasskeyProvider", () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe("handleAction dispatch", () => {
    it("should return 404 for unknown actions", async () => {
      const { provider } = createProvider()
      const response = await provider.handleAction(
        "unknown",
        postRequest("unknown", {}),
        createContext(),
      )
      expect(response.status).toBe(404)
    })

    it("should return 405 for non-POST requests", async () => {
      const { provider } = createProvider()
      const response = await provider.handleAction(
        "register-options",
        new Request(`${BASE_URL}/auth/passkey/register-options`),
        createContext(),
      )
      expect(response.status).toBe(405)
    })
  })

  describe("register-options", () => {
    it("should return 401 without a session", async () => {
      const { provider } = createProvider()
      const context = createContext({
        getSession: vi.fn().mockResolvedValue(null),
      })

      const response = await provider.handleAction(
        "register-options",
        postRequest("register-options", {}),
        context,
      )

      expect(response.status).toBe(401)
      const body = await response.json()
      expect(body.error.code).toBe("SESSION_INVALID")
    })

    it("should return a configuration error when the context lacks getSession", async () => {
      const { provider } = createProvider()
      const context = createContext({ getSession: undefined })

      const response = await provider.handleAction(
        "register-options",
        postRequest("register-options", {}),
        context,
      )

      expect(response.status).toBe(500)
      const body = await response.json()
      expect(body.error.code).toBe("CONFIGURATION_ERROR")
    })

    it("should return options and set the challenge cookie", async () => {
      const { provider, webauthn } = createProvider()

      const response = await provider.handleAction(
        "register-options",
        postRequest("register-options", {}),
        createContext(),
      )

      expect(response.status).toBe(200)
      expect(await response.json()).toEqual(REG_OPTIONS)
      const cookie = challengeCookieFrom(response)
      expect(cookie.length).toBeGreaterThan(COOKIE_NAME.length + 1)
      expect(webauthn.generateRegistrationOptions).toHaveBeenCalledWith(
        expect.objectContaining({
          rpName: "Test App",
          rpID: "example.com",
          userName: "user@example.com",
          attestationType: "none",
          authenticatorSelection: {
            residentKey: "preferred",
            userVerification: "preferred",
          },
          supportedAlgorithmIDs: [-7, -257],
        }),
      )
    })

    it("should exclude already-registered credentials", async () => {
      const { provider, webauthn } = createProvider()
      const context = createContext()
      await context.identityStore.create({
        userId: "user-1",
        provider: "passkey",
        identifier: "existing-cred",
        metadata: credentialMetadata({ transports: ["internal"] }),
      })
      // A non-passkey identity and a corrupt passkey row are both skipped
      await context.identityStore.create({
        userId: "user-1",
        provider: "email",
        identifier: "user@example.com",
        metadata: {},
      })
      await context.identityStore.create({
        userId: "user-1",
        provider: "passkey",
        identifier: "corrupt-cred",
        metadata: { not: "a credential" },
      })

      await provider.handleAction(
        "register-options",
        postRequest("register-options", {}),
        context,
      )

      expect(webauthn.generateRegistrationOptions).toHaveBeenCalledWith(
        expect.objectContaining({
          excludeCredentials: [
            { id: "existing-cred", transports: ["internal"] },
          ],
        }),
      )
    })
  })

  describe("register-verify", () => {
    async function registrationCookie(
      provider: PasskeyProvider,
      context: AuthContext,
    ): Promise<string> {
      const response = await provider.handleAction(
        "register-options",
        postRequest("register-options", {}),
        context,
      )
      return challengeCookieFrom(response)
    }

    it("should return 401 without a challenge cookie", async () => {
      const { provider } = createProvider()

      const response = await provider.handleAction(
        "register-verify",
        postRequest("register-verify", registrationBody()),
        createContext(),
      )

      expect(response.status).toBe(401)
      const body = await response.json()
      expect(body.error.code).toBe("INVALID_TOKEN")
    })

    it("should reject an authentication challenge used for registration", async () => {
      const { provider } = createProvider()
      const context = createContext()
      const optionsResponse = await provider.handleAction(
        "authenticate-options",
        postRequest("authenticate-options", {}),
        context,
      )
      const cookie = challengeCookieFrom(optionsResponse)

      const response = await provider.handleAction(
        "register-verify",
        postRequest("register-verify", registrationBody(), cookie),
        context,
      )

      expect(response.status).toBe(401)
    })

    it("should reject a challenge issued to a different user", async () => {
      const { provider } = createProvider()
      const context = createContext()
      const cookie = await registrationCookie(provider, context)

      const otherUserContext = createContext({
        getSession: vi.fn().mockResolvedValue({
          user: { id: "user-2" },
          identity: {
            id: "identity-2",
            userId: "user-2",
            provider: "email",
            identifier: "other@example.com",
            metadata: {},
            createdAt: new Date(),
          },
        }),
      })
      const response = await provider.handleAction(
        "register-verify",
        postRequest("register-verify", registrationBody(), cookie),
        otherUserContext,
      )

      expect(response.status).toBe(401)
    })

    it("should reject a malformed registration response", async () => {
      const { provider } = createProvider()
      const context = createContext()
      const cookie = await registrationCookie(provider, context)

      const response = await provider.handleAction(
        "register-verify",
        postRequest("register-verify", { not: "a webauthn response" }, cookie),
        context,
      )

      expect(response.status).toBe(401)
      const body = await response.json()
      expect(body.error.code).toBe("INVALID_CREDENTIALS")
    })

    it("should return 401 when verification fails", async () => {
      const webauthn = createFakeWebAuthn()
      vi.mocked(webauthn.verifyRegistrationResponse).mockResolvedValue({
        verified: false,
      })
      const { provider } = createProvider({}, webauthn)
      const context = createContext()
      const cookie = await registrationCookie(provider, context)

      const response = await provider.handleAction(
        "register-verify",
        postRequest("register-verify", registrationBody(), cookie),
        context,
      )

      expect(response.status).toBe(401)
    })

    it("should create a passkey identity carrying the credential metadata", async () => {
      const { provider, webauthn } = createProvider()
      const context = createContext()
      const cookie = await registrationCookie(provider, context)

      const response = await provider.handleAction(
        "register-verify",
        postRequest(
          "register-verify",
          registrationBody({ nickname: "MacBook Touch ID" }),
          cookie,
        ),
        context,
      )

      expect(response.status).toBe(200)
      expect(await response.json()).toEqual({
        success: true,
        verified: true,
        credentialId: "cred-1",
      })
      expect(webauthn.verifyRegistrationResponse).toHaveBeenCalledWith(
        expect.objectContaining({
          expectedChallenge: "reg-challenge",
          expectedOrigin: BASE_URL,
          expectedRPID: "example.com",
        }),
      )

      const identity = await findPasskeyIdentity(context)
      expect(identity).not.toBeNull()
      expect(identity?.userId).toBe("user-1")
      expect(identity?.metadata).toMatchObject({
        publicKey: "AQID",
        counter: 0,
        transports: ["internal"],
        deviceType: "multiDevice",
        backedUp: true,
        nickname: "MacBook Touch ID",
      })

      const clearing = response.headers
        .getSetCookie()
        .find((value) => value.startsWith(`${COOKIE_NAME}=;`))
      expect(clearing).toContain("Max-Age=0")
    })
  })

  describe("authenticate-options", () => {
    it("should return options with empty allowCredentials and set the challenge cookie", async () => {
      const { provider, webauthn } = createProvider()

      const response = await provider.handleAction(
        "authenticate-options",
        postRequest("authenticate-options", {}),
        createContext(),
      )

      expect(response.status).toBe(200)
      expect(await response.json()).toEqual(AUTH_OPTIONS)
      challengeCookieFrom(response)
      expect(webauthn.generateAuthenticationOptions).toHaveBeenCalledWith({
        rpID: "example.com",
        allowCredentials: [],
        userVerification: "preferred",
      })
    })
  })

  describe("authenticate-verify", () => {
    it("should return 401 without a challenge cookie", async () => {
      const { provider } = createProvider()

      const response = await provider.handleAction(
        "authenticate-verify",
        postRequest("authenticate-verify", authenticationBody()),
        createContext(),
      )

      expect(response.status).toBe(401)
    })

    it("should return 401 for an unknown credential", async () => {
      const { provider, context, authCookie } =
        await registeredCredentialSetup()

      const response = await provider.handleAction(
        "authenticate-verify",
        postRequest(
          "authenticate-verify",
          authenticationBody({ id: "unknown-cred" }),
          authCookie,
        ),
        context,
      )

      expect(response.status).toBe(401)
      const body = await response.json()
      expect(body.error.code).toBe("INVALID_CREDENTIALS")
    })

    it("should return 500 when the stored metadata is corrupt", async () => {
      const { provider } = createProvider()
      const context = createContext()
      await seedPasskeyIdentity(context, { not: "a credential" })
      const optionsResponse = await provider.handleAction(
        "authenticate-options",
        postRequest("authenticate-options", {}),
        context,
      )
      const cookie = challengeCookieFrom(optionsResponse)

      const response = await provider.handleAction(
        "authenticate-verify",
        postRequest("authenticate-verify", authenticationBody(), cookie),
        context,
      )

      expect(response.status).toBe(500)
      const body = await response.json()
      expect(body.error.code).toBe("PROVIDER_ERROR")
    })

    it("should return 401 when assertion verification fails", async () => {
      const { provider, webauthn, context, authCookie } =
        await registeredCredentialSetup()
      vi.mocked(webauthn.verifyAuthenticationResponse).mockResolvedValue({
        ...VERIFIED_AUTHENTICATION,
        verified: false,
      })

      const response = await provider.handleAction(
        "authenticate-verify",
        postRequest("authenticate-verify", authenticationBody(), authCookie),
        context,
      )

      expect(response.status).toBe(401)
    })

    it("should create a session and update counter, lastUsedAt, and verifiedAt", async () => {
      const { provider, context, authCookie } =
        await registeredCredentialSetup()

      const response = await provider.handleAction(
        "authenticate-verify",
        postRequest("authenticate-verify", authenticationBody(), authCookie),
        context,
      )

      expect(response.status).toBe(200)
      expect(await response.json()).toEqual({
        success: true,
        verified: true,
        user: { id: "user-1" },
      })

      const cookies = response.headers.getSetCookie()
      expect(cookies.some((value) => value.startsWith("auth_session="))).toBe(
        true,
      )
      expect(
        cookies.some(
          (value) =>
            value.startsWith(`${COOKIE_NAME}=;`) && value.includes("Max-Age=0"),
        ),
      ).toBe(true)

      expect(context.createSession).toHaveBeenCalledTimes(1)

      const identity = await findPasskeyIdentity(context)
      expect(identity?.metadata.counter).toBe(1)
      expect(typeof identity?.metadata.lastUsedAt).toBe("string")
      expect(identity?.verifiedAt).toBeInstanceOf(Date)
    })

    it("should warn but not fail on a counter regression", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {})
      const { provider, webauthn } = createProvider()
      const testContext = createContext()
      await seedPasskeyIdentity(
        testContext,
        credentialMetadata({ counter: 10 }),
      )
      const optionsResponse = await provider.handleAction(
        "authenticate-options",
        postRequest("authenticate-options", {}),
        testContext,
      )
      const cookie = challengeCookieFrom(optionsResponse)
      vi.mocked(webauthn.verifyAuthenticationResponse).mockResolvedValue({
        ...VERIFIED_AUTHENTICATION,
        authenticationInfo: {
          ...VERIFIED_AUTHENTICATION.authenticationInfo,
          newCounter: 5,
        },
      })

      const response = await provider.handleAction(
        "authenticate-verify",
        postRequest("authenticate-verify", authenticationBody(), cookie),
        testContext,
      )

      expect(response.status).toBe(200)
      expect(warn).toHaveBeenCalledWith(
        expect.stringContaining("counter regression"),
      )
      const identity = await findPasskeyIdentity(testContext)
      expect(identity?.metadata.counter).toBe(5)
    })
  })

  describe("single-use challenges", () => {
    it("should consume the challenge on first redemption and reject a replay", async () => {
      const { provider, context, authCookie } =
        await registeredCredentialSetup()

      const first = await provider.handleAction(
        "authenticate-verify",
        postRequest("authenticate-verify", authenticationBody(), authCookie),
        context,
      )
      expect(first.status).toBe(200)

      const replay = await provider.handleAction(
        "authenticate-verify",
        postRequest("authenticate-verify", authenticationBody(), authCookie),
        context,
      )
      expect(replay.status).toBe(401)
    })
  })

  describe("initiate and verify aliases", () => {
    it("should serve authenticate-options from initiate", async () => {
      const { provider } = createProvider()
      const result = await provider.initiate(
        postRequest("initiate", {}),
        createContext(),
      )

      expect(result).toBeInstanceOf(Response)
      if (result instanceof Response) {
        expect(await result.json()).toEqual(AUTH_OPTIONS)
      }
    })
  })
})

describe("describe", () => {
  it("reports the non-secret settings with defaults resolved", () => {
    const { provider } = createProvider({
      rpID: "example.com",
      expectedOrigin: BASE_URL,
    })

    const settings = provider.describe().settings

    expect(settings.rpName).toBe("Test App")
    expect(settings.rpID).toBe("example.com")
    expect(settings.expectedOrigin).toBe(BASE_URL)
    expect(settings.challengeExpiry).toBe("5m")
    expect(settings.challengeCookieName).toBe(COOKIE_NAME)
  })

  it("reports null for the request-derived settings when they are unset", () => {
    const settings = createProvider().provider.describe().settings

    expect(settings.rpID).toBeNull()
    expect(settings.expectedOrigin).toBeNull()
  })

  it("omits the challenge secret", () => {
    const settings = createProvider().provider.describe().settings

    expect(Object.keys(settings)).not.toContain("challengeSecret")
    expect(JSON.stringify(settings)).not.toContain(CHALLENGE_SECRET)
  })
})

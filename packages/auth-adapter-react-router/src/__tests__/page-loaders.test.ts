import { describe, it, expect, vi } from "vitest"
import {
  AUTH_ERROR_MESSAGES,
  getAuthErrorMessage,
  verifyFormToken,
} from "@activescott/auth"
import type {
  Auth,
  AuthProvider,
  Identity,
  IdentityStore,
  ProviderRoute,
} from "@activescott/auth"
import { createAuthPageLoaders } from "../page-loaders.js"

const BASE_URL = "https://example.com"
const SECRET = "test-session-secret"

function provider(id: string, routes: ProviderRoute[]): AuthProvider {
  return { id, getRoutes: () => routes } as unknown as AuthProvider
}

const emailProvider = provider("email", [
  { method: "POST", path: "/email/initiate", handler: "initiate" },
  { method: "POST", path: "/email/verify", handler: "verify" },
])
const smsProvider = provider("sms", [
  { method: "POST", path: "/sms/initiate", handler: "initiate" },
  { method: "POST", path: "/sms/verify", handler: "verify" },
])
const passkeyProvider = provider("passkey", [
  { method: "POST", path: "/passkey/register-options", handler: "action" },
])

function identity(overrides: Partial<Identity>): Identity {
  return {
    id: "identity-1",
    userId: "user-1",
    provider: "email",
    identifier: "alice@example.com",
    providerState: {},
    createdAt: new Date("2024-01-02T03:04:05.000Z"),
    ...overrides,
  }
}

function createAuth(identities: Identity[] = []): Auth {
  const identityStore = {
    findByUserId: vi.fn(async (userId: string) =>
      identities.filter((row) => row.userId === userId),
    ),
  } as unknown as IdentityStore
  return {
    getProviders: () => [emailProvider, smsProvider, passkeyProvider],
    getStores: () => ({ identityStore }),
    getSessionConfig: () => ({ secret: SECRET }),
    getLogger: () => undefined,
  } as unknown as Auth
}

function request(path: string): Request {
  return new Request(`${BASE_URL}${path}`)
}

describe("signInLoader", () => {
  it("defaults to the first provider with an initiate route", async () => {
    const { signInLoader } = createAuthPageLoaders(createAuth())
    const data = await signInLoader(request("/login"))
    expect(data).toMatchObject({
      via: "email",
      sent: false,
      error: null,
      errorCode: null,
      redirectTo: null,
      turnstileSiteKey: null,
    })
  })

  it("takes ?via= only when it names a provider with an initiate route", async () => {
    const { signInLoader } = createAuthPageLoaders(createAuth())
    expect((await signInLoader(request("/login?via=sms"))).via).toBe("sms")
    expect((await signInLoader(request("/login?via=passkey"))).via).toBe(
      "email",
    )
    expect((await signInLoader(request("/login?via=nope"))).via).toBe("email")
  })

  it("reads ?sent=1", async () => {
    const { signInLoader } = createAuthPageLoaders(createAuth())
    expect((await signInLoader(request("/login?sent=1"))).sent).toBe(true)
    expect((await signInLoader(request("/login?sent=yes"))).sent).toBe(false)
  })

  it("mints a form token the abuse guard accepts", async () => {
    const { signInLoader } = createAuthPageLoaders(createAuth())
    const { formToken } = await signInLoader(request("/login"))
    const result = await verifyFormToken(SECRET, formToken, {
      minAgeSeconds: 0,
      maxAgeSeconds: 60,
    })
    expect(result.ok).toBe(true)
  })

  it("passes the Turnstile site key through, treating empty as off", async () => {
    const on = createAuthPageLoaders(createAuth(), {
      turnstileSiteKey: "site-key",
    })
    expect((await on.signInLoader(request("/login"))).turnstileSiteKey).toBe(
      "site-key",
    )
    const empty = createAuthPageLoaders(createAuth(), { turnstileSiteKey: "" })
    expect(
      (await empty.signInLoader(request("/login"))).turnstileSiteKey,
    ).toBeNull()
  })

  it("keeps a same-origin redirectTo and drops any other", async () => {
    const { signInLoader } = createAuthPageLoaders(createAuth())
    const local = await signInLoader(
      request(`/login?redirectTo=${encodeURIComponent("/notes?page=2")}`),
    )
    expect(local.redirectTo).toBe("/notes?page=2")

    const foreign = await signInLoader(
      request(`/login?redirectTo=${encodeURIComponent("https://evil.test/")}`),
    )
    expect(foreign.redirectTo).toBeNull()
  })

  describe("error messages", () => {
    it("resolves a library code", async () => {
      const { signInLoader } = createAuthPageLoaders(createAuth())
      const data = await signInLoader(request("/login?error=RATE_LIMITED"))
      expect(data.errorCode).toBe("RATE_LIMITED")
      expect(data.error).toBe(AUTH_ERROR_MESSAGES.RATE_LIMITED)
    })

    it("uses the app's message for its own code", async () => {
      const { signInLoader } = createAuthPageLoaders(createAuth(), {
        errorMessages: { blocked: "Your account is blocked." },
      })
      const data = await signInLoader(request("/login?error=blocked"))
      expect(data.error).toBe("Your account is blocked.")
    })

    it("lets per-call messages win over the factory's", async () => {
      const { signInLoader } = createAuthPageLoaders(createAuth(), {
        errorMessages: { blocked: "factory" },
      })
      const data = await signInLoader(request("/login?error=blocked"), {
        errorMessages: { blocked: "call" },
      })
      expect(data.error).toBe("call")
    })

    it("answers an unknown code with the default message", async () => {
      const { signInLoader } = createAuthPageLoaders(createAuth())
      const unknown = await signInLoader(request("/login?error=whatever"))
      expect(unknown.error).toBe(getAuthErrorMessage("whatever"))
    })

    it("never returns an inherited property for a code from the URL", async () => {
      const { signInLoader } = createAuthPageLoaders(createAuth())
      for (const code of ["toString", "constructor", "__proto__"]) {
        const data = await signInLoader(request(`/login?error=${code}`))
        expect(typeof data.error).toBe("string")
      }
    })
  })
})

describe("listSignInMethods", () => {
  it("lists the user's identities as JSON, passkeys excluded", async () => {
    const auth = createAuth([
      identity({ id: "i-email" }),
      identity({
        id: "i-sms",
        provider: "sms",
        identifier: "+14155550100",
        verifiedAt: new Date("2024-02-01T00:00:00.000Z"),
      }),
      identity({ id: "i-passkey", provider: "passkey", identifier: "cred" }),
      identity({ id: "i-other", userId: "user-2" }),
    ])
    const { listSignInMethods } = createAuthPageLoaders(auth)

    expect(await listSignInMethods("user-1")).toEqual([
      {
        id: "i-email",
        provider: "email",
        identifier: "alice@example.com",
        createdAt: "2024-01-02T03:04:05.000Z",
        verifiedAt: null,
      },
      {
        id: "i-sms",
        provider: "sms",
        identifier: "+14155550100",
        createdAt: "2024-01-02T03:04:05.000Z",
        verifiedAt: "2024-02-01T00:00:00.000Z",
      },
    ])
  })
})

describe("profileAuthLoader", () => {
  it("returns identities, no passkeys without listPasskeys, and an idle flow", async () => {
    const { profileAuthLoader } = createAuthPageLoaders(
      createAuth([identity({})]),
      { turnstileSiteKey: "site-key" },
    )
    const data = await profileAuthLoader("user-1", request("/profile"))
    expect(data.identities).toHaveLength(1)
    expect(data.passkeys).toEqual([])
    expect(data.linkFlow).toMatchObject({
      add: null,
      sent: false,
      linked: false,
      merged: false,
      conflict: null,
      error: null,
      errorCode: null,
      turnstileSiteKey: "site-key",
    })
    expect(data.linkFlow.formToken).toMatch(/^\d+\./)
  })

  it("fills passkeys from listPasskeys with the identity store", async () => {
    const auth = createAuth()
    const listPasskeys = vi.fn(async () => [{ credentialId: "cred-1" }])
    const { profileAuthLoader } = createAuthPageLoaders(auth, { listPasskeys })

    const data = await profileAuthLoader("user-1", request("/profile"))

    expect(data.passkeys).toEqual([{ credentialId: "cred-1" }])
    expect(listPasskeys).toHaveBeenCalledWith(
      auth.getStores().identityStore,
      "user-1",
    )
  })

  it("opens the add form named by ?add= and reports ?sent=1", async () => {
    const { profileAuthLoader } = createAuthPageLoaders(createAuth())
    const data = await profileAuthLoader(
      "user-1",
      request("/profile?add=sms&sent=1"),
    )
    expect(data.linkFlow).toMatchObject({ add: "sms", sent: true })
  })

  it("ignores ?add= for a provider that cannot link", async () => {
    const { profileAuthLoader } = createAuthPageLoaders(createAuth())
    const data = await profileAuthLoader(
      "user-1",
      request("/profile?add=passkey"),
    )
    expect(data.linkFlow.add).toBeNull()
  })

  it("closes the form once linked", async () => {
    const { profileAuthLoader } = createAuthPageLoaders(createAuth())
    const data = await profileAuthLoader(
      "user-1",
      request("/profile?add=email&linked=1"),
    )
    expect(data.linkFlow).toMatchObject({ add: null, linked: true })
  })

  it("does not report linked alongside an error", async () => {
    const { profileAuthLoader } = createAuthPageLoaders(createAuth())
    const data = await profileAuthLoader(
      "user-1",
      request("/profile?add=email&linked=1&error=INVALID_CREDENTIALS"),
    )
    expect(data.linkFlow).toMatchObject({
      add: "email",
      linked: false,
      error: AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS,
    })
  })

  it("lets a merge supersede the add flow whose params the URL still carries", async () => {
    const { profileAuthLoader } = createAuthPageLoaders(createAuth())
    // The merge redirect keeps the submitting page's query, which here
    // still says linked=1 from the verify redirectTo
    const data = await profileAuthLoader(
      "user-1",
      request("/profile?add=sms&linked=1&sent=1&merged=1"),
    )
    expect(data.linkFlow).toMatchObject({
      add: null,
      sent: false,
      linked: false,
      merged: true,
    })
  })

  it("offers a merge at the provider named by ?provider=", async () => {
    const { profileAuthLoader } = createAuthPageLoaders(createAuth())
    const data = await profileAuthLoader(
      "user-1",
      request("/profile?error=IDENTITY_CONFLICT&provider=sms"),
    )
    expect(data.linkFlow).toMatchObject({
      conflict: { provider: "sms" },
      error: null,
      errorCode: "IDENTITY_CONFLICT",
    })
  })

  it("falls back to ?add= for the conflict's provider", async () => {
    const { profileAuthLoader } = createAuthPageLoaders(createAuth())
    const data = await profileAuthLoader(
      "user-1",
      request("/profile?add=email&error=IDENTITY_CONFLICT"),
    )
    expect(data.linkFlow.conflict).toEqual({ provider: "email" })
  })

  it("shows the conflict as an error when no provider can take the merge", async () => {
    const { profileAuthLoader } = createAuthPageLoaders(createAuth())
    const data = await profileAuthLoader(
      "user-1",
      request("/profile?error=IDENTITY_CONFLICT&provider=passkey"),
    )
    expect(data.linkFlow).toMatchObject({
      conflict: null,
      error: AUTH_ERROR_MESSAGES.IDENTITY_CONFLICT,
    })
  })
})

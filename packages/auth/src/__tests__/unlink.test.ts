import { describe, it, expect, vi } from "vitest"
import { Auth } from "../auth.js"
import { InMemoryChallengeStore } from "../stores/in-memory-challenge-store.js"
import type { AuthProvider, Identity, IdentityStore } from "../types.js"

const BASE_URL = "https://example.com"

function provider(id: string): AuthProvider {
  return {
    id,
    name: id,
    initiate: vi.fn(),
    verify: vi.fn(),
    getRoutes: () => [],
    describe: () => ({ settings: {} }),
  }
}

/** A Map-backed identity store, so the guards see what a delete really left */
function createIdentityStore(seed: Omit<Identity, "createdAt">[]): {
  store: IdentityStore
  rows: Map<string, Identity>
} {
  const rows = new Map<string, Identity>(
    seed.map((row) => [row.id, { ...row, createdAt: new Date(0) }]),
  )
  let next = 0
  const store: IdentityStore = {
    findByProviderAndIdentifier: async (providerId, identifier) =>
      [...rows.values()].find(
        (row) => row.provider === providerId && row.identifier === identifier,
      ) ?? null,
    findByUserId: async (userId) =>
      [...rows.values()].filter((row) => row.userId === userId),
    create: async (data) => {
      const row = { ...data, id: `new-${next++}`, createdAt: new Date() }
      rows.set(row.id, row)
      return row
    },
    update: vi.fn(),
    delete: async (id) => {
      rows.delete(id)
    },
    reassignByUserId: vi.fn(),
  }
  return { store, rows }
}

const EMAIL = {
  id: "id-email",
  userId: "user-1",
  provider: "email",
  identifier: "me@example.com",
  providerState: {},
}
const SMS = {
  id: "id-sms",
  userId: "user-1",
  provider: "sms",
  identifier: "+14155550100",
  providerState: {},
}
const PASSKEY_A = {
  id: "id-pk-a",
  userId: "user-1",
  provider: "passkey",
  identifier: "cred-a",
  providerState: { publicKey: "pk" },
}
const PASSKEY_B = { ...PASSKEY_A, id: "id-pk-b", identifier: "cred-b" }
const SOMEONE_ELSE = {
  id: "id-other",
  userId: "user-2",
  provider: "email",
  identifier: "them@example.com",
  providerState: {},
}

function createAuth(seed: Omit<Identity, "createdAt">[]) {
  const { store, rows } = createIdentityStore(seed)
  const auth = new Auth({
    session: {
      secret: "test-secret",
      maxAge: "7d",
      cookieName: "auth_session",
      cookie: { secure: false, sameSite: "lax" },
    },
    identityStore: store,
    userStore: {
      findById: async (id) => ({ id }),
      create: vi.fn(),
      onMerge: vi.fn(),
    },
    challengeStore: new InMemoryChallengeStore(),
    providers: [provider("email"), provider("sms"), provider("passkey")],
  })
  return { auth, store, rows }
}

function remaining(rows: Map<string, Identity>): string[] {
  return [...rows.values()]
    .filter((row) => row.userId === "user-1")
    .map((row) => row.identifier)
    .sort()
}

describe("Auth.unlinkIdentity", () => {
  it("removes an identity when another way to sign in remains", async () => {
    const { auth, rows } = createAuth([EMAIL, SMS])
    const removed = await auth.unlinkIdentity("user-1", SMS)
    expect(removed.id).toBe("id-sms")
    expect(remaining(rows)).toEqual(["me@example.com"])
  })

  it("removes a passkey while an email address remains", async () => {
    const { auth, rows } = createAuth([EMAIL, PASSKEY_A])
    await auth.unlinkIdentity("user-1", PASSKEY_A)
    expect(remaining(rows)).toEqual(["me@example.com"])
  })

  it("refuses to remove the only identity", async () => {
    const { auth, rows } = createAuth([EMAIL])
    await expect(auth.unlinkIdentity("user-1", EMAIL)).rejects.toMatchObject({
      code: "LAST_SIGN_IN_METHOD",
    })
    expect(remaining(rows)).toEqual(["me@example.com"])
  })

  it("refuses to leave the account with passkeys only", async () => {
    const { auth, rows } = createAuth([EMAIL, PASSKEY_A])
    await expect(auth.unlinkIdentity("user-1", EMAIL)).rejects.toMatchObject({
      code: "LAST_SIGN_IN_METHOD",
    })
    expect(remaining(rows)).toEqual(["cred-a", "me@example.com"])
  })

  it("lets a passkey-only account remove one of several passkeys", async () => {
    const { auth, rows } = createAuth([PASSKEY_A, PASSKEY_B])
    await auth.unlinkIdentity("user-1", PASSKEY_A)
    expect(remaining(rows)).toEqual(["cred-b"])
    await expect(
      auth.unlinkIdentity("user-1", PASSKEY_B),
    ).rejects.toMatchObject({ code: "LAST_SIGN_IN_METHOD" })
  })

  it("does not count identities of providers that are not registered", async () => {
    const { auth } = createAuth([
      EMAIL,
      { ...SMS, provider: "retired-provider" },
    ])
    await expect(auth.unlinkIdentity("user-1", EMAIL)).rejects.toMatchObject({
      code: "LAST_SIGN_IN_METHOD",
    })
  })

  it("refuses the identity the current session is signed in with", async () => {
    const { auth, rows } = createAuth([EMAIL, SMS])
    await expect(
      auth.unlinkIdentity("user-1", SMS, { currentIdentity: SMS }),
    ).rejects.toMatchObject({ code: "IDENTITY_IN_USE" })
    expect(remaining(rows)).toHaveLength(2)
  })

  it("will not remove another user's identity", async () => {
    const { auth, rows } = createAuth([EMAIL, SMS, SOMEONE_ELSE])
    await expect(
      auth.unlinkIdentity("user-1", SOMEONE_ELSE),
    ).rejects.toMatchObject({ code: "IDENTITY_NOT_FOUND" })
    expect(rows.has("id-other")).toBe(true)
  })

  it("puts the identity back when a concurrent removal took the other one", async () => {
    const { auth, store, rows } = createAuth([EMAIL, SMS])
    // The other request's delete lands between this one's check and its own
    // delete, so the check passed against an SMS row that is now gone.
    const realDelete = store.delete.bind(store)
    store.delete = async (id) => {
      await realDelete("id-sms")
      await realDelete(id)
    }
    await expect(auth.unlinkIdentity("user-1", EMAIL)).rejects.toMatchObject({
      code: "LAST_SIGN_IN_METHOD",
    })
    expect(remaining(rows)).toEqual(["me@example.com"])
    const restored = [...rows.values()][0]
    expect(restored?.providerState).toEqual({})
  })
})

describe("POST /auth/{provider}/unlink", () => {
  async function sessionCookie(auth: Auth, identity: Identity) {
    const cookie = await auth.createSessionCookie({ id: "user-1" }, identity)
    return cookie.split(";")[0] as string
  }

  function asIdentity(row: Omit<Identity, "createdAt">): Identity {
    return { ...row, createdAt: new Date(0) }
  }

  function unlinkRequest(
    providerId: string,
    identifier: string,
    cookie: string | null,
    browser: boolean,
  ): Request {
    const headers: Record<string, string> = browser
      ? {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "text/html",
          Referer: `${BASE_URL}/profile?removeError=X&provider=sms`,
        }
      : { "Content-Type": "application/json" }
    if (cookie) headers.Cookie = cookie
    return new Request(`${BASE_URL}/auth/${providerId}/unlink`, {
      method: "POST",
      headers,
      body: browser
        ? new URLSearchParams({ identifier }).toString()
        : JSON.stringify({ identifier }),
    })
  }

  it("removes the signed-in user's identity and redirects back", async () => {
    const { auth, rows } = createAuth([EMAIL, PASSKEY_A])
    const cookie = await sessionCookie(auth, asIdentity(EMAIL))
    const response = await auth.handleRequest(
      unlinkRequest("passkey", "cred-a", cookie, true),
    )
    expect(response.status).toBe(302)
    const location = new URL(response.headers.get("Location") ?? "")
    expect(location.pathname).toBe("/profile")
    expect(location.searchParams.get("removed")).toBe("passkey")
    expect(location.searchParams.has("removeError")).toBe(false)
    expect(remaining(rows)).toEqual(["me@example.com"])
    auth.destroy()
  })

  it("answers fetch callers with JSON", async () => {
    const { auth } = createAuth([EMAIL, SMS])
    const cookie = await sessionCookie(auth, asIdentity(EMAIL))
    const response = await auth.handleRequest(
      unlinkRequest("sms", SMS.identifier, cookie, false),
    )
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({
      success: true,
      removed: { provider: "sms" },
    })
    auth.destroy()
  })

  it("requires a session", async () => {
    const { auth, rows } = createAuth([EMAIL, SMS])
    const response = await auth.handleRequest(
      unlinkRequest("sms", SMS.identifier, null, false),
    )
    expect(response.status).toBe(401)
    expect(remaining(rows)).toHaveLength(2)
    auth.destroy()
  })

  it("reports a refusal on the page it came from", async () => {
    const { auth } = createAuth([EMAIL, SMS])
    const cookie = await sessionCookie(auth, asIdentity(EMAIL))
    const response = await auth.handleRequest(
      unlinkRequest("email", EMAIL.identifier, cookie, true),
    )
    const location = new URL(response.headers.get("Location") ?? "")
    expect(location.searchParams.get("removeError")).toBe("IDENTITY_IN_USE")
    expect(location.searchParams.get("provider")).toBe("email")
    auth.destroy()
  })

  it("only removes an identity of the provider in the path", async () => {
    const { auth, rows } = createAuth([EMAIL, SMS])
    const cookie = await sessionCookie(auth, asIdentity(EMAIL))
    // SMS's identifier posted to the email provider's endpoint
    const response = await auth.handleRequest(
      unlinkRequest("email", SMS.identifier, cookie, false),
    )
    expect(response.status).toBe(404)
    expect(remaining(rows)).toHaveLength(2)
    auth.destroy()
  })

  it("will not remove another user's identity", async () => {
    const { auth, rows } = createAuth([EMAIL, SMS, SOMEONE_ELSE])
    const cookie = await sessionCookie(auth, asIdentity(EMAIL))
    const response = await auth.handleRequest(
      unlinkRequest("email", SOMEONE_ELSE.identifier, cookie, false),
    )
    expect(response.status).toBe(404)
    expect(rows.has("id-other")).toBe(true)
    auth.destroy()
  })

  it("ends other sessions signed in with the removed identity", async () => {
    const { auth } = createAuth([EMAIL, SMS])
    const smsCookie = await sessionCookie(auth, asIdentity(SMS))
    const smsSession = new Request(BASE_URL, { headers: { Cookie: smsCookie } })
    // Cached before the removal
    expect(await auth.verifySession(smsSession)).not.toBeNull()

    const emailCookie = await sessionCookie(auth, asIdentity(EMAIL))
    await auth.handleRequest(
      unlinkRequest("sms", SMS.identifier, emailCookie, false),
    )
    expect(await auth.verifySession(smsSession)).toBeNull()
    auth.destroy()
  })

  it("is POST only", async () => {
    const { auth } = createAuth([EMAIL, SMS])
    const response = await auth.handleRequest(
      new Request(`${BASE_URL}/auth/sms/unlink`),
    )
    expect(response.status).toBe(405)
    auth.destroy()
  })
})

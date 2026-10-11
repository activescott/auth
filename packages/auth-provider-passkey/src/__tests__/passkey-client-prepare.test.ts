import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { createPasskeyClient } from "../passkey-client.js"

// Safari shows the passkey sheet only while the tap that asked for it is
// still being handled; a fetch awaited in between fails the ceremony with
// NotAllowedError. So these tests click a real EventTarget and check
// navigator.credentials right after dispatchEvent returns, with no await.

const OPTIONS_MAX_AGE_MS = 240_000

let challenges: string[]
// The challenge in the one cookie every tab on the origin shares
let cookie: string | undefined
let fetchMock: ReturnType<typeof vi.fn>
let getCredential: ReturnType<typeof vi.fn>
let createCredential: ReturnType<typeof vi.fn>

function base64url(text: string): string {
  return Buffer.from(text).toString("base64url")
}

function optionsBody(url: string, challenge: string): unknown {
  return url.endsWith("register-options")
    ? {
        challenge: base64url(challenge),
        rp: { name: "Test", id: "localhost" },
        user: { id: base64url("user"), name: "u", displayName: "u" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      }
    : { challenge: base64url(challenge), rpId: "localhost" }
}

// Only what postJson reads; a real Response parses its body on a later tick
function respond(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body } as Response
}

function requested(mock: ReturnType<typeof vi.fn>, call: number): string {
  const { publicKey } = mock.mock.calls[call]?.[0] ?? {}
  return new TextDecoder().decode(publicKey.challenge)
}

function optionsFetches(): number {
  return fetchMock.mock.calls.filter(([url]) =>
    String(url).endsWith("-options"),
  ).length
}

/** Lets a stubbed fetch and its .json() settle */
async function settle(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve))
}

function tap(onClick: () => unknown): void {
  const button = new EventTarget()
  button.addEventListener("click", () => {
    void Promise.resolve(onClick()).catch(() => undefined)
  })
  button.dispatchEvent(new Event("click"))
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] })
  challenges = ["first", "second", "third", "fourth"]
  cookie = undefined
  fetchMock = vi.fn(async (url: string) => {
    cookie = challenges.shift() ?? "spent"
    return respond(optionsBody(url, cookie))
  })
  vi.stubGlobal("fetch", fetchMock)
  // Never settles: the passkey sheet stays open
  getCredential = vi.fn(() => new Promise<never>(() => undefined))
  createCredential = vi.fn(() => new Promise<never>(() => undefined))
  vi.stubGlobal("navigator", {
    credentials: { get: getCredential, create: createCredential },
  })
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe("prepareSignIn", () => {
  it("lets a tap call credentials.get synchronously once options are ready", async () => {
    const passkeys = createPasskeyClient()
    passkeys.prepareSignIn()
    await settle()

    tap(() => passkeys.signInWithPasskey())

    expect(getCredential).toHaveBeenCalledTimes(1)
    expect(requested(getCredential, 0)).toBe("first")
    expect(optionsFetches()).toBe(1)
  })

  it("makes a tap before options arrive wait for them instead of fetching again", async () => {
    let arrive = (): void => undefined
    fetchMock.mockImplementationOnce(
      (url: string) =>
        new Promise<Response>((resolve) => {
          arrive = () => resolve(respond(optionsBody(url, "slow")))
        }),
    )
    const passkeys = createPasskeyClient()
    passkeys.prepareSignIn()

    tap(() => passkeys.signInWithPasskey())
    expect(getCredential).not.toHaveBeenCalled()
    arrive()
    await settle()

    expect(getCredential).toHaveBeenCalledTimes(1)
    expect(requested(getCredential, 0)).toBe("slow")
    expect(optionsFetches()).toBe(1)
  })

  it("refetches after a failed attempt, so the next tap is synchronous with a new challenge", async () => {
    getCredential.mockRejectedValueOnce(
      new DOMException("The request is not allowed", "NotAllowedError"),
    )
    const passkeys = createPasskeyClient()
    passkeys.prepareSignIn()
    await settle()

    await expect(passkeys.signInWithPasskey()).rejects.toThrow(
      "The request is not allowed",
    )
    await settle()
    tap(() => passkeys.signInWithPasskey())

    expect(getCredential).toHaveBeenCalledTimes(2)
    expect(requested(getCredential, 1)).toBe("second")
    expect(optionsFetches()).toBe(2)
  })

  it("refreshes options a minute before the challenge expires", async () => {
    const passkeys = createPasskeyClient()
    passkeys.prepareSignIn()
    await settle()

    vi.advanceTimersByTime(OPTIONS_MAX_AGE_MS)
    await settle()
    tap(() => passkeys.signInWithPasskey())

    expect(optionsFetches()).toBe(2)
    expect(requested(getCredential, 0)).toBe("second")
  })

  it("does not refresh while the passkey sheet is open", async () => {
    const passkeys = createPasskeyClient()
    passkeys.prepareSignIn()
    await settle()
    tap(() => passkeys.signInWithPasskey())

    vi.advanceTimersByTime(OPTIONS_MAX_AGE_MS)
    await settle()

    expect(optionsFetches()).toBe(1)
  })

  it("stops refreshing once the returned function is called", async () => {
    const passkeys = createPasskeyClient()
    const stop = passkeys.prepareSignIn()
    await settle()

    stop()
    vi.advanceTimersByTime(OPTIONS_MAX_AGE_MS * 3)
    await settle()

    expect(optionsFetches()).toBe(1)
  })

  it("fetches once for overlapping calls, as React StrictMode makes", async () => {
    const passkeys = createPasskeyClient()
    passkeys.prepareSignIn()()
    passkeys.prepareSignIn()
    await settle()

    tap(() => passkeys.signInWithPasskey())

    expect(optionsFetches()).toBe(1)
    expect(getCredential).toHaveBeenCalledTimes(1)
  })

  it("lets a modal tap reuse the options a pending autofill request holds", async () => {
    const passkeys = createPasskeyClient()
    passkeys.prepareSignIn()
    await settle()
    void passkeys.signInWithPasskey({ conditional: true })

    tap(() => passkeys.signInWithPasskey())

    expect(getCredential).toHaveBeenCalledTimes(2)
    expect(requested(getCredential, 1)).toBe("first")
    expect(optionsFetches()).toBe(1)
  })

  it("fetches options at the tap without prepareSignIn", async () => {
    const passkeys = createPasskeyClient()

    tap(() => passkeys.signInWithPasskey())
    await settle()

    expect(getCredential).toHaveBeenCalledTimes(1)
    expect(optionsFetches()).toBe(1)
  })
})

describe("prepareRegistration", () => {
  it("lets a tap call credentials.create synchronously once options are ready", async () => {
    const passkeys = createPasskeyClient()
    passkeys.prepareRegistration()
    await settle()

    tap(() => passkeys.registerPasskey())

    expect(createCredential).toHaveBeenCalledTimes(1)
    expect(requested(createCredential, 0)).toBe("first")
    expect(optionsFetches()).toBe(1)
  })

  it("refetches after a failed attempt", async () => {
    createCredential.mockRejectedValueOnce(
      new DOMException("The request is not allowed", "NotAllowedError"),
    )
    const passkeys = createPasskeyClient()
    passkeys.prepareRegistration()
    await settle()

    await expect(passkeys.registerPasskey()).rejects.toThrow(
      "The request is not allowed",
    )
    await settle()
    tap(() => passkeys.registerPasskey())

    expect(createCredential).toHaveBeenCalledTimes(2)
    expect(requested(createCredential, 1)).toBe("second")
  })
})

describe("autofill", () => {
  it("does not replace the challenge a pending autofill request is bound to", async () => {
    const passkeys = createPasskeyClient()
    passkeys.prepareSignIn()
    await settle()
    void passkeys.signInWithPasskey({ conditional: true })

    vi.advanceTimersByTime(OPTIONS_MAX_AGE_MS)
    await settle()

    expect(optionsFetches()).toBe(1)
    expect(requested(getCredential, 0)).toBe(cookie)
  })
})

describe("hidden tabs", () => {
  let visibilityState: DocumentVisibilityState
  let page: EventTarget

  function show(state: DocumentVisibilityState): void {
    visibilityState = state
    page.dispatchEvent(new Event("visibilitychange"))
  }

  beforeEach(() => {
    visibilityState = "visible"
    page = new EventTarget()
    Object.defineProperty(page, "visibilityState", {
      get: () => visibilityState,
    })
    vi.stubGlobal("document", page)
  })

  it("does not refresh while hidden, and refetches stale options when shown", async () => {
    const passkeys = createPasskeyClient()
    passkeys.prepareSignIn()
    await settle()

    show("hidden")
    vi.advanceTimersByTime(OPTIONS_MAX_AGE_MS)
    await settle()
    expect(optionsFetches()).toBe(1)

    show("visible")
    await settle()
    tap(() => passkeys.signInWithPasskey())

    expect(optionsFetches()).toBe(2)
    expect(requested(getCredential, 0)).toBe("second")
  })

  it("does not refetch when shown while its options are fresh", async () => {
    const passkeys = createPasskeyClient()
    passkeys.prepareSignIn()
    await settle()

    show("hidden")
    show("visible")
    await settle()

    expect(optionsFetches()).toBe(1)
  })
})

// Each tab gets its own copy of the client module, as a browser tab would.
// They share fetch, and so the one challenge cookie, and talk over a
// BroadcastChannel or, without one, localStorage.
describe("two tabs", () => {
  class FakeBroadcastChannel {
    static open = new Set<FakeBroadcastChannel>()
    onmessage: ((event: MessageEvent) => void) | null = null
    constructor(readonly name: string) {
      FakeBroadcastChannel.open.add(this)
    }
    postMessage(data: unknown): void {
      for (const other of FakeBroadcastChannel.open) {
        if (other !== this && other.name === this.name) {
          setImmediate(() =>
            other.onmessage?.(new MessageEvent("message", { data })),
          )
        }
      }
    }
  }

  async function openTab(): Promise<ReturnType<typeof createPasskeyClient>> {
    vi.resetModules()
    const module = await import("../passkey-client.js")
    return module.createPasskeyClient()
  }

  beforeEach(() => {
    FakeBroadcastChannel.open.clear()
    vi.stubGlobal("BroadcastChannel", FakeBroadcastChannel)
  })

  it("does not register with a challenge another tab replaced", async () => {
    const tabA = await openTab()
    const tabB = await openTab()
    tabA.prepareRegistration()
    await settle()
    tabB.prepareRegistration()
    await settle()
    // Then the message reaches tab A
    await settle()

    tap(() => tabA.registerPasskey())
    expect(createCredential).not.toHaveBeenCalled()
    await settle()

    expect(createCredential).toHaveBeenCalledTimes(1)
    expect(requested(createCredential, 0)).toBe(cookie)
  })

  it("does not sign in with a challenge another tab replaced", async () => {
    const tabA = await openTab()
    const tabB = await openTab()
    tabA.prepareSignIn()
    await settle()
    tabB.prepareSignIn()
    await settle()
    // Then the message reaches tab A
    await settle()

    tap(() => tabA.signInWithPasskey())
    await settle()

    expect(getCredential).toHaveBeenCalledTimes(1)
    expect(requested(getCredential, 0)).toBe(cookie)
  })

  it("hears about other tabs through localStorage without BroadcastChannel", async () => {
    vi.stubGlobal("BroadcastChannel", undefined)
    const window = new EventTarget()
    vi.stubGlobal("addEventListener", window.addEventListener.bind(window))
    vi.stubGlobal("localStorage", {
      setItem(key: string, newValue: string) {
        setImmediate(() =>
          window.dispatchEvent(
            Object.assign(new Event("storage"), { key, newValue }),
          ),
        )
      },
    })
    const tabA = await openTab()
    const tabB = await openTab()
    tabA.prepareRegistration()
    await settle()
    tabB.prepareRegistration()
    await settle()
    // Then the storage event reaches tab A
    await settle()

    tap(() => tabA.registerPasskey())
    await settle()

    expect(requested(createCredential, 0)).toBe(cookie)
  })

  it("keeps options whose response arrived after the other tab's", async () => {
    let arrive = (): void => undefined
    fetchMock.mockImplementationOnce(
      (url: string) =>
        new Promise<Response>((resolve) => {
          arrive = () => {
            cookie = "slow"
            resolve(respond(optionsBody(url, "slow")))
          }
        }),
    )
    const tabA = await openTab()
    const tabB = await openTab()
    tabA.prepareSignIn()
    tabB.prepareSignIn()
    await settle()
    arrive()
    await settle()

    tap(() => tabA.signInWithPasskey())

    expect(getCredential).toHaveBeenCalledTimes(1)
    expect(requested(getCredential, 0)).toBe("slow")
    expect(cookie).toBe("slow")
  })

  it("drops registration options once sign-in options replace the cookie in the same tab", async () => {
    const passkeys = createPasskeyClient()
    passkeys.prepareRegistration()
    await settle()
    passkeys.prepareSignIn()
    await settle()

    tap(() => passkeys.registerPasskey())
    await settle()

    expect(createCredential).toHaveBeenCalledTimes(1)
    expect(requested(createCredential, 0)).toBe(cookie)
  })
})

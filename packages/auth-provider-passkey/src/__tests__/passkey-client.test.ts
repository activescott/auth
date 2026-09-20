import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { createPasskeyClient } from "../passkey-client.js"
import {
  runAuthenticationCeremony,
  runRegistrationCeremony,
} from "../webauthn-ceremony.js"

// The ceremonies need a real navigator.credentials; the client's job is the
// HTTP round trip around them, which is what these tests cover.
vi.mock("../webauthn-ceremony.js", () => ({
  runRegistrationCeremony: vi.fn(async () => ({ id: "registration" })),
  runAuthenticationCeremony: vi.fn(async () => ({ id: "assertion" })),
}))

const HTTP_OK = 200
const HTTP_UNAUTHORIZED = 401
const HTTP_BAD_GATEWAY = 502

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  })
}

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = vi.fn(async (url: string) =>
    jsonResponse(HTTP_OK, { options: `for ${url}` }),
  )
  vi.stubGlobal("fetch", fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

function postedUrls(): string[] {
  return fetchMock.mock.calls.map(([url]) => url as string)
}

describe("createPasskeyClient", () => {
  describe("registerPasskey", () => {
    it("fetches options, runs the ceremony, and posts the registration", async () => {
      await createPasskeyClient().registerPasskey()

      expect(postedUrls()).toEqual([
        "/auth/passkey/register-options",
        "/auth/passkey/register-verify",
      ])
      expect(runRegistrationCeremony).toHaveBeenCalledWith({
        options: "for /auth/passkey/register-options",
      })
      const [, init] = fetchMock.mock.calls[1] ?? []
      expect(init).toEqual({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "registration" }),
      })
    })
  })

  describe("signInWithPasskey", () => {
    it("fetches options, runs a modal ceremony by default, and posts the assertion", async () => {
      await createPasskeyClient().signInWithPasskey()

      expect(postedUrls()).toEqual([
        "/auth/passkey/authenticate-options",
        "/auth/passkey/authenticate-verify",
      ])
      expect(runAuthenticationCeremony).toHaveBeenCalledWith(
        { options: "for /auth/passkey/authenticate-options" },
        { conditional: false },
      )
      const [, init] = fetchMock.mock.calls[1] ?? []
      expect(init).toMatchObject({ body: JSON.stringify({ id: "assertion" }) })
    })

    it("passes conditional through to the ceremony", async () => {
      await createPasskeyClient().signInWithPasskey({ conditional: true })

      expect(runAuthenticationCeremony).toHaveBeenCalledWith(
        expect.anything(),
        { conditional: true },
      )
    })
  })

  describe("basePath", () => {
    it.each(["/api/auth", "/api/auth/"])("posts under %s", async (basePath) => {
      await createPasskeyClient({ basePath }).signInWithPasskey()

      expect(postedUrls()).toEqual([
        "/api/auth/passkey/authenticate-options",
        "/api/auth/passkey/authenticate-verify",
      ])
    })
  })

  describe("errors", () => {
    it("throws the error's details.reason when present", async () => {
      fetchMock.mockImplementation(async (url: string) =>
        url.endsWith("-verify")
          ? jsonResponse(HTTP_UNAUTHORIZED, {
              success: false,
              error: {
                code: "INVALID_CREDENTIALS",
                message: "Invalid credentials",
                details: { reason: "Unknown credential" },
              },
            })
          : jsonResponse(HTTP_OK, {}),
      )

      await expect(createPasskeyClient().signInWithPasskey()).rejects.toThrow(
        new Error("Unknown credential"),
      )
    })

    it("falls back to the error message without a reason", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse(HTTP_UNAUTHORIZED, {
          success: false,
          error: { code: "SESSION_INVALID", message: "Session is invalid" },
        }),
      )

      await expect(createPasskeyClient().registerPasskey()).rejects.toThrow(
        new Error("Session is invalid"),
      )
      expect(runRegistrationCeremony).not.toHaveBeenCalled()
    })

    it("falls back to the status for a non-JSON error body", async () => {
      fetchMock.mockResolvedValue(
        new Response("Bad Gateway", { status: HTTP_BAD_GATEWAY }),
      )

      await expect(createPasskeyClient().registerPasskey()).rejects.toThrow(
        new Error("Request to /auth/passkey/register-options failed (502)"),
      )
    })

    it("propagates a cancelled ceremony without posting a verify", async () => {
      vi.mocked(runAuthenticationCeremony).mockRejectedValueOnce(
        new DOMException("The operation was aborted", "NotAllowedError"),
      )

      await expect(createPasskeyClient().signInWithPasskey()).rejects.toThrow(
        "The operation was aborted",
      )
      expect(postedUrls()).toEqual(["/auth/passkey/authenticate-options"])
    })
  })
})

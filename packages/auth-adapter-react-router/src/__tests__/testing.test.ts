import { describe, it, expect, vi } from "vitest"
import {
  createCaptureReadbackLoader,
  type CaptureReadbackOptions,
} from "../testing.js"

const SECRET = "test-readback-secret"
const BASE = "https://example.com/e2e/otp-code"

const capturedEmail = {
  magicLink: "https://example.com/m?t=abc",
  code: "123456",
}
const capturedSms = { message: "Your code is: 654321", code: "654321" }

function createTransports() {
  return {
    email: {
      getCapturedEmail: vi.fn((to: string) =>
        to === "user@example.com" ? capturedEmail : null,
      ),
    },
    sms: {
      getCapturedSms: vi.fn((to: string) =>
        to === "+14155550100" ? capturedSms : null,
      ),
    },
  }
}

function createLoader(overrides: Partial<CaptureReadbackOptions> = {}) {
  return createCaptureReadbackLoader({
    transports: createTransports(),
    enabled: true,
    secret: SECRET,
    ...overrides,
  })
}

function get(query: string, secret: string | null = SECRET) {
  const headers = new Headers()
  if (secret !== null) headers.set("x-e2e-secret", secret)
  return { request: new Request(`${BASE}${query}`, { headers }) }
}

describe("createCaptureReadbackLoader", () => {
  describe("when enabled with the right secret", () => {
    it("returns the captured email for ?email=", async () => {
      const response = await createLoader()(get("?email=user%40example.com"))

      expect(response.status).toBe(200)
      expect(await response.json()).toEqual(capturedEmail)
      expect(response.headers.get("Cache-Control")).toBe("no-store")
    })

    it("returns the captured SMS for ?phone=", async () => {
      const response = await createLoader()(get("?phone=%2B14155550100"))

      expect(response.status).toBe(200)
      expect(await response.json()).toEqual(capturedSms)
    })

    it("returns 404 when nothing was captured for the recipient", async () => {
      const loader = createLoader()

      expect((await loader(get("?email=other%40example.com"))).status).toBe(404)
      expect((await loader(get("?phone=%2B14155550199"))).status).toBe(404)
    })

    it("returns 404 for a channel with no capture transport", async () => {
      const transports = createTransports()
      const loader = createLoader({
        transports: { email: transports.email, sms: null },
      })

      const response = await loader(get("?phone=%2B14155550100"))

      expect(response.status).toBe(404)
      expect(await response.text()).toMatch(/not captured/)
    })

    it("returns 400 without an email or phone param", async () => {
      expect((await createLoader()(get(""))).status).toBe(400)
    })
  })

  describe("when disabled", () => {
    it("returns a bare 404 even with the right secret", async () => {
      const transports = createTransports()
      const loader = createLoader({ transports, enabled: false })

      const response = await loader(get("?email=user%40example.com"))

      expect(response.status).toBe(404)
      expect(await response.text()).toBe("Not Found")
      expect(transports.email.getCapturedEmail).not.toHaveBeenCalled()
    })

    it("stays closed for a truthy non-boolean enabled", async () => {
      const loader = createLoader({ enabled: "false" as unknown as boolean })

      expect((await loader(get("?email=user%40example.com"))).status).toBe(404)
    })

    it("does not require a secret", async () => {
      const loader = createLoader({ enabled: false, secret: undefined })

      expect((await loader(get("?email=user%40example.com"))).status).toBe(404)
    })
  })

  describe("secret", () => {
    it.each([
      ["missing", null],
      ["empty", ""],
      ["wrong", "wrong-secret"],
      ["a prefix of the real one", SECRET.slice(0, -1)],
    ])("returns the same bare 404 when %s", async (_label, secret) => {
      const transports = createTransports()
      const loader = createLoader({ transports })

      const response = await loader(get("?email=user%40example.com", secret))

      expect(response.status).toBe(404)
      expect(await response.text()).toBe("Not Found")
      expect(transports.email.getCapturedEmail).not.toHaveBeenCalled()
    })

    it.each([undefined, ""])(
      "throws at creation when enabled with secret %j",
      (secret) => {
        expect(() => createLoader({ secret })).toThrow(/secret/)
      },
    )
  })
})

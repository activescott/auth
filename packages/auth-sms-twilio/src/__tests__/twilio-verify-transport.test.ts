import { describe, it, expect, vi } from "vitest"
import { TwilioVerifyTransport } from "../twilio-verify-transport.js"

const TEST_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
const TEST_TOKEN = "test-auth-token"
const TEST_SERVICE_SID = "VAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
const TEST_VERIFICATION_SID = "VExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
const TEST_PHONE = "+14155550100"
const TEST_CODE = "123456"

function createFetchMock(status = 201, body: unknown = {}): typeof fetch {
  return vi
    .fn()
    .mockResolvedValue(new Response(JSON.stringify(body), { status }))
}

function createTransport(fetchImpl: typeof fetch): TwilioVerifyTransport {
  return new TwilioVerifyTransport({
    accountSid: TEST_SID,
    authToken: TEST_TOKEN,
    serviceSid: TEST_SERVICE_SID,
    fetch: fetchImpl,
  })
}

function lastCall(fetchImpl: typeof fetch): {
  url: string
  init: RequestInit | undefined
} {
  const [url, init] = vi.mocked(fetchImpl).mock.calls.at(-1) ?? []
  return { url: String(url), init }
}

describe("TwilioVerifyTransport", () => {
  it("should require a Verify service SID", () => {
    expect(
      () =>
        new TwilioVerifyTransport({
          accountSid: TEST_SID,
          authToken: TEST_TOKEN,
          serviceSid: "",
        }),
    ).toThrow(/serviceSid/)
  })

  it("should POST to Verifications with Basic auth and return the sid", async () => {
    const fetchMock = createFetchMock(201, {
      sid: TEST_VERIFICATION_SID,
      status: "pending",
    })
    const transport = createTransport(fetchMock)

    const started = await transport.startVerification(TEST_PHONE)

    expect(started).toEqual({ ok: true, reference: TEST_VERIFICATION_SID })

    const { url, init } = lastCall(fetchMock)
    expect(url).toBe(
      `https://verify.twilio.com/v2/Services/${TEST_SERVICE_SID}/Verifications`,
    )
    expect(init?.method).toBe("POST")
    expect(new Headers(init?.headers).get("Authorization")).toBe(
      `Basic ${btoa(`${TEST_SID}:${TEST_TOKEN}`)}`,
    )

    const body = new URLSearchParams(String(init?.body))
    expect(body.get("To")).toBe(TEST_PHONE)
    expect(body.get("Channel")).toBe("sms")
    expect(body.get("Locale")).toBeNull()
  })

  it("should pass through the configured channel and options", async () => {
    const fetchMock = createFetchMock(201, { sid: TEST_VERIFICATION_SID })
    const transport = new TwilioVerifyTransport({
      accountSid: TEST_SID,
      authToken: TEST_TOKEN,
      serviceSid: TEST_SERVICE_SID,
      channel: "call",
      locale: "es",
      appHash: "abcd1234",
      templateSid: "HJxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      fetch: fetchMock,
    })

    await transport.startVerification(TEST_PHONE)

    const body = new URLSearchParams(String(lastCall(fetchMock).init?.body))
    expect(body.get("Channel")).toBe("call")
    expect(body.get("Locale")).toBe("es")
    expect(body.get("AppHash")).toBe("abcd1234")
    expect(body.get("TemplateSid")).toBe("HJxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
  })

  it("should report a failed send instead of throwing", async () => {
    const transport = createTransport(createFetchMock(400, { code: 60200 }))

    const started = await transport.startVerification(TEST_PHONE)

    expect(started.ok).toBe(false)
  })

  it("should report a network failure on start instead of throwing", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("ECONNRESET"))
    const transport = createTransport(fetchMock)

    const started = await transport.startVerification(TEST_PHONE)

    expect(started.ok).toBe(false)
  })

  it("should POST the code to VerificationChecks", async () => {
    const fetchMock = createFetchMock(200, { status: "approved", valid: true })
    const transport = createTransport(fetchMock)

    const result = await transport.checkVerification(
      TEST_PHONE,
      TEST_VERIFICATION_SID,
      TEST_CODE,
    )

    expect(result).toEqual({ status: "approved" })

    const { url, init } = lastCall(fetchMock)
    expect(url).toBe(
      `https://verify.twilio.com/v2/Services/${TEST_SERVICE_SID}/VerificationChecks`,
    )
    const body = new URLSearchParams(String(init?.body))
    expect(body.get("To")).toBe(TEST_PHONE)
    expect(body.get("Code")).toBe(TEST_CODE)
  })

  it.each([
    ["pending", "invalid_code"],
    ["failed", "invalid_code"],
    ["max_attempts_reached", "rate_limited"],
    ["expired", "expired"],
    ["canceled", "expired"],
  ] as const)("should map %s to %s", async (twilioStatus, expected) => {
    const transport = createTransport(
      createFetchMock(200, { status: twilioStatus }),
    )

    const result = await transport.checkVerification(
      TEST_PHONE,
      undefined,
      TEST_CODE,
    )

    expect(result.status).toBe(expected)
  })

  it("should treat a 404 from the check as an expired verification", async () => {
    const transport = createTransport(createFetchMock(404, { code: 20404 }))

    const result = await transport.checkVerification(
      TEST_PHONE,
      undefined,
      TEST_CODE,
    )

    expect(result.status).toBe("expired")
  })

  it("should report other check failures as errors, not wrong codes", async () => {
    const transport = createTransport(createFetchMock(500, { code: 20500 }))

    const result = await transport.checkVerification(
      TEST_PHONE,
      undefined,
      TEST_CODE,
    )

    expect(result.status).toBe("error")
  })
})

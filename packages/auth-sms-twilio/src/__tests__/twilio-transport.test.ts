import { describe, it, expect, vi } from "vitest"
import { TwilioTransport } from "../twilio-transport.js"

const TEST_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
const TEST_TOKEN = "test-auth-token"
const TEST_PHONE = "+14155550100"

function createFetchMock(status = 201, body = "{}"): typeof fetch {
  return vi.fn().mockResolvedValue(new Response(body, { status }))
}

describe("TwilioTransport", () => {
  it("should require a sender", () => {
    expect(
      () =>
        new TwilioTransport({ accountSid: TEST_SID, authToken: TEST_TOKEN }),
    ).toThrow(/from.*messagingServiceSid/)
  })

  it("should POST to the Messages API with Basic auth and From", async () => {
    const fetchMock = createFetchMock()
    const transport = new TwilioTransport({
      accountSid: TEST_SID,
      authToken: TEST_TOKEN,
      from: "+15005550006",
      fetch: fetchMock,
    })

    const sent = await transport.sendMessage(TEST_PHONE, "Your code is 123456")
    expect(sent).toBe(true)

    const [url, init] = vi.mocked(fetchMock).mock.calls[0] ?? []
    expect(String(url)).toBe(
      `https://api.twilio.com/2010-04-01/Accounts/${TEST_SID}/Messages.json`,
    )
    expect(init?.method).toBe("POST")

    const headers = new Headers(init?.headers)
    expect(headers.get("Authorization")).toBe(
      `Basic ${btoa(`${TEST_SID}:${TEST_TOKEN}`)}`,
    )

    const body = new URLSearchParams(String(init?.body))
    expect(body.get("To")).toBe(TEST_PHONE)
    expect(body.get("Body")).toBe("Your code is 123456")
    expect(body.get("From")).toBe("+15005550006")
    expect(body.get("MessagingServiceSid")).toBeNull()
  })

  it("should prefer MessagingServiceSid over From", async () => {
    const fetchMock = createFetchMock()
    const transport = new TwilioTransport({
      accountSid: TEST_SID,
      authToken: TEST_TOKEN,
      from: "+15005550006",
      messagingServiceSid: "MGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      fetch: fetchMock,
    })

    await transport.sendMessage(TEST_PHONE, "hi")

    const [, init] = vi.mocked(fetchMock).mock.calls[0] ?? []
    const body = new URLSearchParams(String(init?.body))
    expect(body.get("MessagingServiceSid")).toBe(
      "MGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    )
    expect(body.get("From")).toBeNull()
  })

  it("should return false on an API error response", async () => {
    const transport = new TwilioTransport({
      accountSid: TEST_SID,
      authToken: TEST_TOKEN,
      from: "+15005550006",
      fetch: createFetchMock(401, '{"message":"Authentication Error"}'),
    })

    expect(await transport.sendMessage(TEST_PHONE, "hi")).toBe(false)
  })

  it("should return false when fetch rejects", async () => {
    const transport = new TwilioTransport({
      accountSid: TEST_SID,
      authToken: TEST_TOKEN,
      from: "+15005550006",
      fetch: vi.fn().mockRejectedValue(new Error("network down")),
    })

    expect(await transport.sendMessage(TEST_PHONE, "hi")).toBe(false)
  })
})

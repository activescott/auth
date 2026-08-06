import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import type { BotCheckInput } from "@activescott/auth"
import { TurnstileBotCheck } from "../turnstile-bot-check.js"

const VERIFY_URL = "https://turnstile.test/siteverify"
const SECRET_KEY = "test-secret"

function inputWith(body: Record<string, unknown>, ip = "203.0.113.7") {
  const input: BotCheckInput = {
    request: new Request("https://example.com/auth/email/initiate", {
      method: "POST",
    }),
    body,
    ip,
    providerId: "email",
  }
  return input
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  })
}

describe("TurnstileBotCheck", () => {
  beforeEach(() => {
    vi.spyOn(console, "warn").mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("allows a token siteverify accepts", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse({ success: true }))
    const check = new TurnstileBotCheck({
      secretKey: SECRET_KEY,
      verifyUrl: VERIFY_URL,
    })

    const result = await check.verify(
      inputWith({ "cf-turnstile-response": "widget-token" }),
    )

    expect(result).toEqual({ ok: true })
    const body = String(fetchMock.mock.calls[0]?.[1]?.body)
    expect(body).toContain(`secret=${SECRET_KEY}`)
    expect(body).toContain("response=widget-token")
    expect(body).toContain("remoteip=203.0.113.7")
  })

  it("blocks with the reported error codes", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        success: false,
        "error-codes": ["invalid-input-response", "timeout-or-duplicate"],
      }),
    )
    const check = new TurnstileBotCheck({
      secretKey: SECRET_KEY,
      verifyUrl: VERIFY_URL,
    })

    expect(
      await check.verify(inputWith({ "cf-turnstile-response": "stale" })),
    ).toEqual({
      ok: false,
      reason: "invalid-input-response,timeout-or-duplicate",
    })
  })

  it("blocks a submission with no widget token", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
    const check = new TurnstileBotCheck({
      secretKey: SECRET_KEY,
      verifyUrl: VERIFY_URL,
    })

    expect(
      await check.verify(inputWith({ email: "user@example.com" })),
    ).toEqual({ ok: false, reason: "missing_token" })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("reads a custom field name", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ success: true }),
    )
    const check = new TurnstileBotCheck({
      secretKey: SECRET_KEY,
      verifyUrl: VERIFY_URL,
      fieldName: "captcha",
    })

    expect(await check.verify(inputWith({ captcha: "widget-token" }))).toEqual({
      ok: true,
    })
  })

  it("fails open by default when siteverify is unreachable", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network down"))
    const check = new TurnstileBotCheck({
      secretKey: SECRET_KEY,
      verifyUrl: VERIFY_URL,
    })

    expect(
      await check.verify(inputWith({ "cf-turnstile-response": "token" })),
    ).toEqual({ ok: true })
    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining("turnstile unavailable"),
    )
  })

  it("fails closed when configured to", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network down"))
    const check = new TurnstileBotCheck({
      secretKey: SECRET_KEY,
      verifyUrl: VERIFY_URL,
      failOpen: false,
    })

    expect(
      await check.verify(inputWith({ "cf-turnstile-response": "token" })),
    ).toEqual({ ok: false, reason: "unavailable:error" })
  })

  it("treats a non-200 siteverify response as unavailable", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("nope", { status: 502 }),
    )
    const check = new TurnstileBotCheck({
      secretKey: SECRET_KEY,
      verifyUrl: VERIFY_URL,
      failOpen: false,
    })

    expect(
      await check.verify(inputWith({ "cf-turnstile-response": "token" })),
    ).toEqual({ ok: false, reason: "unavailable:http_502" })
  })

  it("omits remoteip when the client IP is unknown", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse({ success: true }))
    const check = new TurnstileBotCheck({
      secretKey: SECRET_KEY,
      verifyUrl: VERIFY_URL,
    })

    await check.verify({
      ...inputWith({ "cf-turnstile-response": "token" }),
      ip: null,
    })

    expect(String(fetchMock.mock.calls[0]?.[1]?.body)).not.toContain("remoteip")
  })
})

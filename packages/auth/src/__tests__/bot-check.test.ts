import { describe, it, expect, vi, afterEach } from "vitest"
import {
  createFormToken,
  verifyFormToken,
  FormTokenBotCheck,
  FORM_TOKEN_FIELD,
} from "../abuse/bot-check.js"
import type { BotCheckInput } from "../abuse/bot-check.js"

const SECRET = "test-form-token-secret"
const MS_PER_SECOND = 1000

function inputWith(body: Record<string, unknown>): BotCheckInput {
  return {
    request: new Request("https://example.com/auth/email/initiate", {
      method: "POST",
    }),
    body,
    ip: "203.0.113.7",
    providerId: "email",
  }
}

describe("form tokens", () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it("verifies a token after the minimum fill time", async () => {
    vi.useFakeTimers()
    const token = await createFormToken(SECRET)

    vi.advanceTimersByTime(5 * MS_PER_SECOND)
    const result = await verifyFormToken(SECRET, token, {
      minAgeSeconds: 2,
      maxAgeSeconds: 3600,
    })

    expect(result.ok).toBe(true)
  })

  it("rejects a token submitted too fast", async () => {
    const token = await createFormToken(SECRET)

    expect(
      await verifyFormToken(SECRET, token, {
        minAgeSeconds: 2,
        maxAgeSeconds: 3600,
      }),
    ).toEqual({ ok: false, reason: "too_fast" })
  })

  it("rejects a token older than maxAgeSeconds", async () => {
    vi.useFakeTimers()
    const token = await createFormToken(SECRET)

    vi.advanceTimersByTime(7200 * MS_PER_SECOND)

    expect(
      await verifyFormToken(SECRET, token, {
        minAgeSeconds: 2,
        maxAgeSeconds: 3600,
      }),
    ).toEqual({ ok: false, reason: "expired" })
  })

  it("rejects a tampered timestamp", async () => {
    const token = await createFormToken(SECRET)
    const signature = token.split(".")[1]
    const forged = `${Math.floor(Date.now() / MS_PER_SECOND) - 60}.${signature}`

    expect(
      await verifyFormToken(SECRET, forged, {
        minAgeSeconds: 2,
        maxAgeSeconds: 3600,
      }),
    ).toEqual({ ok: false, reason: "invalid_signature" })
  })

  it("rejects a token signed with another secret", async () => {
    const token = await createFormToken("other-secret")

    expect(
      await verifyFormToken(SECRET, token, {
        minAgeSeconds: 0,
        maxAgeSeconds: 3600,
      }),
    ).toEqual({ ok: false, reason: "invalid_signature" })
  })

  it("rejects a malformed token", async () => {
    expect(
      await verifyFormToken(SECRET, "not-a-token", {
        minAgeSeconds: 0,
        maxAgeSeconds: 3600,
      }),
    ).toEqual({ ok: false, reason: "malformed" })
  })
})

describe("FormTokenBotCheck", () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it("allows a submission with no token (form not updated yet)", async () => {
    const check = new FormTokenBotCheck(SECRET)

    expect(await check.verify(inputWith({ email: "a@b.co" }))).toEqual({
      ok: true,
    })
  })

  it("blocks a submission faster than a human", async () => {
    const check = new FormTokenBotCheck(SECRET)
    const token = await createFormToken(SECRET)

    expect(
      await check.verify(inputWith({ [FORM_TOKEN_FIELD]: token })),
    ).toEqual({ ok: false, reason: "too_fast" })
  })

  it("allows a stale token rather than locking out an open tab", async () => {
    vi.useFakeTimers()
    const check = new FormTokenBotCheck(SECRET, 2, 60)
    const token = await createFormToken(SECRET)

    vi.advanceTimersByTime(3600 * MS_PER_SECOND)

    expect(
      await check.verify(inputWith({ [FORM_TOKEN_FIELD]: token })),
    ).toEqual({ ok: true })
  })
})

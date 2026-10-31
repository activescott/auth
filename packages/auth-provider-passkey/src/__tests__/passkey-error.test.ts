import { describe, it, expect } from "vitest"
import { describePasskeyError } from "../passkey-error.js"

describe("describePasskeyError", () => {
  it.each(["NotAllowedError", "AbortError", "TimeoutError"])(
    "reports a %s as no-credential-or-cancelled",
    (name) => {
      const error = new DOMException("The operation timed out", name)

      expect(describePasskeyError(error)).toEqual({
        ok: false,
        reason: "no-credential-or-cancelled",
        message: "The operation timed out",
        error,
      })
    },
  )

  it("reports other DOMExceptions as errors", () => {
    const error = new DOMException("Not supported", "NotSupportedError")

    expect(describePasskeyError(error)).toMatchObject({
      reason: "error",
      message: "Not supported",
    })
  })

  it("keeps a server rejection's message", () => {
    const error = new Error("Unknown credential")

    expect(describePasskeyError(error)).toEqual({
      ok: false,
      reason: "error",
      message: "Unknown credential",
      error,
    })
  })

  it.each([undefined, null, {}, ""])(
    "falls back to a generic message for %o",
    (thrown) => {
      expect(describePasskeyError(thrown)).toMatchObject({
        reason: "error",
        message: "Passkey request failed",
      })
    },
  )
})

import { describe, it, expect } from "vitest"
import { AUTH_ERROR_MESSAGES, getAuthErrorMessage } from "../errors.js"

describe("getAuthErrorMessage", () => {
  it("returns the built-in message for a known code", () => {
    expect(getAuthErrorMessage("RATE_LIMITED")).toBe(
      AUTH_ERROR_MESSAGES.RATE_LIMITED,
    )
  })

  it("still takes a default message as the second argument", () => {
    expect(getAuthErrorMessage("unknown_code", "Something broke")).toBe(
      "Something broke",
    )
  })

  it("answers an app code from the overrides", () => {
    expect(
      getAuthErrorMessage("blocked", { blocked: "Your account is blocked." }),
    ).toBe("Your account is blocked.")
  })

  it("lets an override reword a built-in code", () => {
    expect(
      getAuthErrorMessage("RATE_LIMITED", { RATE_LIMITED: "Slow down." }),
    ).toBe("Slow down.")
  })

  it("falls back to the built-in message when the overrides lack the code", () => {
    expect(getAuthErrorMessage("RATE_LIMITED", { blocked: "Blocked." })).toBe(
      AUTH_ERROR_MESSAGES.RATE_LIMITED,
    )
  })

  it("uses the default message after the overrides for an unknown code", () => {
    expect(getAuthErrorMessage("unknown_code", {}, "Something broke")).toBe(
      "Something broke",
    )
    expect(getAuthErrorMessage("unknown_code", {})).toBe(
      getAuthErrorMessage("unknown_code"),
    )
  })

  it("does not read inherited properties of the overrides", () => {
    const overrides = Object.create({ blocked: "inherited" }) as Record<
      string,
      string
    >
    expect(getAuthErrorMessage("blocked", overrides, "fallback")).toBe(
      "fallback",
    )
  })
})

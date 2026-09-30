// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { act } from "react"
import { useOtpAutoSubmit } from "../client/use-otp-auto-submit.js"
import { usePreservedInput } from "../client/use-preserved-input.js"
import { renderHook } from "./render.js"

/** Type into an input the way a user or autofill does, so React sees it */
function typeInto(input: HTMLInputElement, value: string): void {
  const setValue = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  )?.set
  act(() => {
    setValue?.call(input, value)
    input.dispatchEvent(new Event("input", { bubbles: true }))
  })
}

describe("useOtpAutoSubmit", () => {
  let requestSubmit: ReturnType<typeof vi.fn>

  beforeEach(() => {
    requestSubmit = vi.fn()
    vi.spyOn(HTMLFormElement.prototype, "requestSubmit").mockImplementation(
      requestSubmit,
    )
  })

  afterEach(() => {
    vi.restoreAllMocks()
    document.body.innerHTML = ""
  })

  function renderCodeForm(length = 6) {
    const hook = renderHook(
      () => useOtpAutoSubmit(length),
      ({ inputProps }) => (
        <form>
          <input data-testid="code" {...inputProps} />
        </form>
      ),
    )
    const input = document.querySelector<HTMLInputElement>("[data-testid=code]")
    if (!input) throw new Error("code input not rendered")
    return { ...hook, input }
  }

  it("gives the input the attributes platform autofill looks for", () => {
    const { input } = renderCodeForm(6)
    expect(input.getAttribute("name")).toBe("code")
    expect(input.getAttribute("autocomplete")).toBe("one-time-code")
    expect(input.getAttribute("inputmode")).toBe("numeric")
    expect(input.getAttribute("pattern")).toBe("[0-9]{6}")
    expect(input.getAttribute("maxlength")).toBe("6")
  })

  it("submits once the last digit lands", () => {
    const { input, result } = renderCodeForm(6)
    typeInto(input, "12345")
    expect(requestSubmit).not.toHaveBeenCalled()
    expect(result.current.submitting).toBe(false)

    typeInto(input, "123456")
    expect(requestSubmit).toHaveBeenCalledTimes(1)
    expect(result.current.submitting).toBe(true)
  })

  it("submits only once when a second full code lands before the page leaves", () => {
    const { input } = renderCodeForm(6)
    typeInto(input, "123456")
    typeInto(input, "654321")
    expect(requestSubmit).toHaveBeenCalledTimes(1)
  })

  it("does not submit a code the pattern rejects", () => {
    const { input, result } = renderCodeForm(6)
    typeInto(input, "12345a")
    expect(requestSubmit).not.toHaveBeenCalled()
    expect(result.current.submitting).toBe(false)
  })

  it("allows another submit after the code is edited", () => {
    const { input, result } = renderCodeForm(4)
    typeInto(input, "1234")
    typeInto(input, "123")
    expect(result.current.submitting).toBe(false)
    typeInto(input, "1235")
    expect(requestSubmit).toHaveBeenCalledTimes(2)
  })
})

describe("usePreservedInput", () => {
  afterEach(() => {
    vi.restoreAllMocks()
    sessionStorage.clear()
  })

  it("starts empty and restores what save stored", () => {
    const first = renderHook(() => usePreservedInput("login.email"))
    expect(first.result.current[0]).toBe("")

    act(() => first.result.current[1]("alice@example.com"))
    act(() => first.result.current[2]())
    first.unmount()

    const second = renderHook(() => usePreservedInput("login.email"))
    expect(second.result.current[0]).toBe("alice@example.com")
  })

  it("keeps values under separate keys apart", () => {
    sessionStorage.setItem("login.phone", "4155550100")
    const { result } = renderHook(() => usePreservedInput("login.email"))
    expect(result.current[0]).toBe("")
  })

  it("works without storage", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("SecurityError")
    })
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("QuotaExceededError")
    })
    const { result } = renderHook(() => usePreservedInput("login.email"))
    act(() => result.current[1]("alice@example.com"))

    expect(() => result.current[2]()).not.toThrow()
    expect(result.current[0]).toBe("alice@example.com")
  })
})

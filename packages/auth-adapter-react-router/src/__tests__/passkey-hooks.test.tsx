// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { act } from "react"
import { usePasskeySignIn } from "../client/use-passkey-sign-in.js"
import { useRegisterPasskey } from "../client/use-register-passkey.js"
import { renderHook } from "./render.js"

let assign: ReturnType<typeof vi.fn>

beforeEach(() => {
  assign = vi.fn()
  vi.spyOn(window.location, "assign").mockImplementation(assign)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe("usePasskeySignIn", () => {
  it("signs in and loads redirectTo", async () => {
    const client = { signInWithPasskey: vi.fn().mockResolvedValue(undefined) }
    const { result } = renderHook(() =>
      usePasskeySignIn({ client, redirectTo: "/dashboard" }),
    )

    await act(() => result.current.signIn())

    expect(client.signInWithPasskey).toHaveBeenCalledWith()
    expect(assign).toHaveBeenCalledWith("/dashboard")
    expect(result.current).toMatchObject({ pending: true, error: null })
  })

  it("reports the failure and stays on the page", async () => {
    const client = {
      signInWithPasskey: vi
        .fn()
        .mockRejectedValue(new Error("Unknown credential")),
    }
    const { result } = renderHook(() =>
      usePasskeySignIn({ client, redirectTo: "/dashboard" }),
    )

    await act(() => result.current.signIn())

    expect(assign).not.toHaveBeenCalled()
    expect(result.current).toMatchObject({
      pending: false,
      error: "Unknown credential",
    })
  })

  it("clears the previous error on the next attempt", async () => {
    const client = {
      signInWithPasskey: vi
        .fn()
        .mockRejectedValueOnce(new Error("Cancelled"))
        .mockResolvedValueOnce(undefined),
    }
    const { result } = renderHook(() =>
      usePasskeySignIn({ client, redirectTo: "/" }),
    )

    await act(() => result.current.signIn())
    expect(result.current.error).toBe("Cancelled")
    await act(() => result.current.signIn())
    expect(result.current.error).toBeNull()
  })

  describe("autofill", () => {
    beforeEach(() => {
      vi.useFakeTimers()
    })

    afterEach(() => {
      vi.useRealTimers()
    })

    function stubConditionalUI(available: boolean): void {
      vi.stubGlobal("PublicKeyCredential", {
        isConditionalMediationAvailable: () => Promise.resolve(available),
      })
    }

    async function runAutofill(): Promise<void> {
      await act(async () => {
        await vi.runAllTimersAsync()
      })
    }

    it("starts one conditional request and navigates when it completes", async () => {
      stubConditionalUI(true)
      const client = { signInWithPasskey: vi.fn().mockResolvedValue(undefined) }
      renderHook(() =>
        usePasskeySignIn({ client, redirectTo: "/home", autofill: true }),
      )
      await runAutofill()

      expect(client.signInWithPasskey).toHaveBeenCalledTimes(1)
      expect(client.signInWithPasskey).toHaveBeenCalledWith({
        conditional: true,
      })
      expect(assign).toHaveBeenCalledWith("/home")
    })

    it("does nothing where the browser lacks conditional UI", async () => {
      stubConditionalUI(false)
      const client = { signInWithPasskey: vi.fn() }
      renderHook(() =>
        usePasskeySignIn({ client, redirectTo: "/", autofill: true }),
      )
      await runAutofill()

      expect(client.signInWithPasskey).not.toHaveBeenCalled()
    })

    it("stays off unless asked for", async () => {
      stubConditionalUI(true)
      const client = { signInWithPasskey: vi.fn() }
      renderHook(() => usePasskeySignIn({ client, redirectTo: "/" }))
      await runAutofill()

      expect(client.signInWithPasskey).not.toHaveBeenCalled()
    })

    it("hides ceremony aborts but shows a server rejection", async () => {
      stubConditionalUI(true)
      const aborted = {
        signInWithPasskey: vi
          .fn()
          .mockRejectedValue(new DOMException("Superseded", "AbortError")),
      }
      const abortedHook = renderHook(() =>
        usePasskeySignIn({ client: aborted, redirectTo: "/", autofill: true }),
      )
      await runAutofill()
      expect(abortedHook.result.current.error).toBeNull()

      const rejected = {
        signInWithPasskey: vi
          .fn()
          .mockRejectedValue(new Error("Unknown credential")),
      }
      const rejectedHook = renderHook(() =>
        usePasskeySignIn({ client: rejected, redirectTo: "/", autofill: true }),
      )
      await runAutofill()
      expect(rejectedHook.result.current.error).toBe("Unknown credential")
    })

    it("does not restart the ceremony when the caller re-renders with a new client", async () => {
      stubConditionalUI(true)
      // The conditional request stays pending; the click's modal one fails,
      // and its error state re-renders the caller with fresh options
      const signInWithPasskey = vi.fn((options?: { conditional?: boolean }) =>
        options?.conditional
          ? new Promise<void>(() => {})
          : Promise.reject(new Error("Cancelled")),
      )
      let renders = 0
      const { result } = renderHook(() => {
        renders += 1
        return usePasskeySignIn({
          client: { signInWithPasskey },
          redirectTo: `/r${renders}`,
          autofill: true,
        })
      })
      await runAutofill()
      await act(() => result.current.signIn())
      await runAutofill()

      expect(renders).toBeGreaterThan(1)
      // One conditional request, plus the modal one the click started
      expect(signInWithPasskey).toHaveBeenCalledTimes(2)
    })
  })
})

describe("useRegisterPasskey", () => {
  it("registers, reports added, then calls onRegistered", async () => {
    const client = { registerPasskey: vi.fn().mockResolvedValue(undefined) }
    const onRegistered = vi.fn()
    const { result } = renderHook(() =>
      useRegisterPasskey({ client, onRegistered }),
    )
    expect(result.current.status).toBe("idle")

    await act(() => result.current.register())

    expect(client.registerPasskey).toHaveBeenCalledTimes(1)
    expect(onRegistered).toHaveBeenCalledTimes(1)
    expect(result.current).toMatchObject({ status: "added", error: null })
  })

  it("is pending while the ceremony runs", async () => {
    let finish: () => void = () => {}
    const client = {
      registerPasskey: vi.fn(
        () => new Promise<void>((resolve) => (finish = resolve)),
      ),
    }
    const { result } = renderHook(() => useRegisterPasskey({ client }))

    let registering: Promise<void> = Promise.resolve()
    act(() => {
      registering = result.current.register()
    })
    expect(result.current.status).toBe("pending")

    await act(async () => {
      finish()
      await registering
    })
    expect(result.current.status).toBe("added")
  })

  it("reports the failure", async () => {
    const client = {
      registerPasskey: vi.fn().mockRejectedValue(new Error("Not allowed")),
    }
    const onRegistered = vi.fn()
    const { result } = renderHook(() =>
      useRegisterPasskey({ client, onRegistered }),
    )

    await act(() => result.current.register())

    expect(onRegistered).not.toHaveBeenCalled()
    expect(result.current).toMatchObject({
      status: "error",
      error: "Not allowed",
    })
  })
})

// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { act } from "react"
import { useTurnstile } from "../client/use-turnstile.js"
import { renderHook } from "./render.js"

interface RenderOptions {
  sitekey: string
  callback: () => void
  "expired-callback": () => void
  "error-callback": () => void
}

/** Stands in for Cloudflare's `window.turnstile` */
function installFakeTurnstile() {
  const widgets: { container: HTMLElement; options: RenderOptions }[] = []
  const api = {
    render: vi.fn((container: HTMLElement, options: RenderOptions) => {
      widgets.push({ container, options })
      return `widget-${widgets.length}`
    }),
    remove: vi.fn(),
  }
  ;(globalThis as { turnstile?: unknown }).turnstile = api
  return {
    api,
    latest: () => {
      const widget = widgets.at(-1)
      if (!widget) throw new Error("no widget rendered")
      return widget.options
    },
  }
}

function renderTurnstile(siteKey: string | null, stallTimeoutMs?: number) {
  return renderHook(
    () => useTurnstile(siteKey, { stallTimeoutMs }),
    (state) =>
      state.enabled ? (
        <form>
          <div data-testid="widget" ref={state.containerRef} />
        </form>
      ) : null,
  )
}

/** Let the script promise and the effects it triggers settle */
async function flush(): Promise<void> {
  await act(async () => {
    await Promise.resolve()
  })
}

describe("useTurnstile", () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
    delete (globalThis as { turnstile?: unknown }).turnstile
    document.body.innerHTML = ""
    document.head.innerHTML = ""
  })

  it("reports ready and renders nothing without a site key", () => {
    const { result } = renderTurnstile(null)
    expect(result.current).toMatchObject({
      enabled: false,
      status: "ready",
      ready: true,
    })
    expect(document.head.querySelector("script")).toBeNull()
  })

  it("renders the widget into the container and waits for its token", async () => {
    const turnstile = installFakeTurnstile()
    const { result } = renderTurnstile("site-key")
    await flush()

    expect(turnstile.api.render).toHaveBeenCalledTimes(1)
    const [container, options] = turnstile.api.render.mock.calls[0] ?? []
    expect(container).toBe(document.querySelector("[data-testid=widget]"))
    expect(options?.sitekey).toBe("site-key")
    expect(result.current).toMatchObject({ status: "pending", ready: false })

    act(() => turnstile.latest().callback())
    expect(result.current).toMatchObject({ status: "ready", ready: true })
  })

  it("goes back to pending when the token expires", async () => {
    const turnstile = installFakeTurnstile()
    const { result } = renderTurnstile("site-key")
    await flush()
    act(() => turnstile.latest().callback())

    act(() => turnstile.latest()["expired-callback"]())
    expect(result.current.status).toBe("pending")
  })

  it("fails on the widget's error callback", async () => {
    const turnstile = installFakeTurnstile()
    const { result } = renderTurnstile("site-key")
    await flush()

    act(() => turnstile.latest()["error-callback"]())
    expect(result.current.status).toBe("failed")
  })

  it("fails when no token arrives within the stall timeout", async () => {
    installFakeTurnstile()
    const { result } = renderTurnstile("site-key", 5000)
    await flush()

    act(() => vi.advanceTimersByTime(4999))
    expect(result.current.status).toBe("pending")
    act(() => vi.advanceTimersByTime(1))
    expect(result.current.status).toBe("failed")
  })

  it("does not fail after a token arrived in time", async () => {
    const turnstile = installFakeTurnstile()
    const { result } = renderTurnstile("site-key", 5000)
    await flush()
    act(() => turnstile.latest().callback())

    act(() => vi.advanceTimersByTime(10_000))
    expect(result.current.status).toBe("ready")
  })

  it("removes the widget on unmount", async () => {
    const turnstile = installFakeTurnstile()
    const { unmount } = renderTurnstile("site-key")
    await flush()

    unmount()
    expect(turnstile.api.remove).toHaveBeenCalledWith("widget-1")
  })

  it("loads Cloudflare's script for explicit rendering, and fails if it cannot", async () => {
    // Capture the script instead of letting the DOM fetch it
    const appended: Node[] = []
    vi.spyOn(document.head, "append").mockImplementation((...nodes) => {
      appended.push(...(nodes as Node[]))
    })
    const { result } = renderTurnstile("site-key")
    await flush()

    const script = appended[0] as HTMLScriptElement | undefined
    expect(appended).toHaveLength(1)
    expect(script?.getAttribute("src")).toBe(
      "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
    )

    await act(async () => {
      script?.dispatchEvent(new Event("error"))
      await Promise.resolve()
    })
    await flush()
    expect(result.current.status).toBe("failed")
  })
})

// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import { act, useState } from "react"
import { createRoot, type Root } from "react-dom/client"
import {
  useTurnstile,
  type Turnstile,
  type UseTurnstileOptions,
} from "../turnstile.js"

declare global {
  // eslint-disable-next-line no-var -- `var` is what augments globalThis
  var IS_REACT_ACT_ENVIRONMENT: boolean
}

interface FakeWidget {
  options: Record<string, unknown>
  removed: boolean
}

/** Stand-in for Cloudflare's `window.turnstile`, recording what it was asked to do */
function installFakeTurnstile() {
  const widgets = new Map<string, FakeWidget>()
  let nextId = 0

  const api = {
    render: vi.fn(
      (_container: HTMLElement, options: Record<string, unknown>) => {
        const id = `widget-${nextId++}`
        widgets.set(id, { options, removed: false })
        return id
      },
    ),
    remove: vi.fn((id: string) => {
      const widget = widgets.get(id)
      if (widget) widget.removed = true
    }),
  }
  Object.assign(globalThis, { turnstile: api })

  function callbackFor(name: string, id = "widget-0"): () => void {
    const widget = widgets.get(id)
    if (!widget) throw new Error(`no widget ${id}`)
    return widget.options[name] as () => void
  }

  return { api, widgets, callbackFor }
}

/**
 * Mount the hook and hand back its latest return value plus the DOM it
 * produced. The hook waits on a promise before rendering the widget, so every
 * helper here is async-act'd.
 */
async function mountHook(options: UseTurnstileOptions) {
  const host = document.createElement("div")
  document.body.appendChild(host)
  const root: Root = createRoot(host)

  let latest: Turnstile | undefined
  let setOptions: ((next: UseTurnstileOptions) => void) | undefined

  function Probe({ initial }: { initial: UseTurnstileOptions }) {
    const [current, setCurrent] = useState(initial)
    setOptions = setCurrent
    latest = useTurnstile(current)
    return <>{latest.widget}</>
  }

  await act(async () => {
    root.render(<Probe initial={options} />)
  })

  return {
    host,
    get current(): Turnstile {
      if (!latest) throw new Error("hook never rendered")
      return latest
    },
    async run(fn: () => void) {
      await act(async () => {
        fn()
      })
    },
    async setOptions(next: UseTurnstileOptions) {
      await act(async () => {
        setOptions?.(next)
      })
    },
    async unmount() {
      await act(async () => {
        root.unmount()
      })
      host.remove()
    },
  }
}

describe("useTurnstile", () => {
  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true
  })

  afterEach(() => {
    Reflect.deleteProperty(globalThis, "turnstile")
    document.body.innerHTML = ""
  })

  it("is ready with no widget when there is no site key", async () => {
    const hook = await mountHook({ siteKey: null })

    expect(hook.current.ready).toBe(true)
    expect(hook.current.widget).toBeNull()
    expect(hook.host.innerHTML).toBe("")

    await hook.unmount()
  })

  it("renders the script and a container, and is not ready yet", async () => {
    installFakeTurnstile()
    const hook = await mountHook({
      siteKey: "site-key",
      className: "my-widget",
    })

    expect(hook.current.ready).toBe(false)
    expect(hook.host.querySelector("div.my-widget")).not.toBeNull()

    const script = document.querySelector<HTMLScriptElement>(
      "script[src*='challenges.cloudflare.com']",
    )
    expect(script?.src).toContain("render=explicit")
    expect(script?.src).toContain("onload=__activescottAuthTurnstileOnload")

    await hook.unmount()
  })

  it("renders the widget with the site key and the options that were set", async () => {
    const fake = installFakeTurnstile()
    const hook = await mountHook({
      siteKey: "site-key",
      theme: "dark",
      action: "login",
    })

    const [container, options] = fake.api.render.mock.calls[0]
    expect(container).toBe(hook.host.querySelector("div"))
    expect(options).toMatchObject({
      sitekey: "site-key",
      theme: "dark",
      action: "login",
    })
    // Unset options stay absent so Cloudflare's defaults apply
    expect(options).not.toHaveProperty("size")
    expect(options).not.toHaveProperty("appearance")

    await hook.unmount()
  })

  it("becomes ready when the widget issues a token", async () => {
    const fake = installFakeTurnstile()
    const hook = await mountHook({ siteKey: "site-key" })

    await hook.run(() => fake.callbackFor("callback")())

    expect(hook.current.ready).toBe(true)

    await hook.unmount()
  })

  it.each(["expired-callback", "error-callback", "timeout-callback"])(
    "stops being ready on %s",
    async (callbackName) => {
      const fake = installFakeTurnstile()
      const hook = await mountHook({ siteKey: "site-key" })

      await hook.run(() => fake.callbackFor("callback")())
      expect(hook.current.ready).toBe(true)

      await hook.run(() => fake.callbackFor(callbackName)())
      expect(hook.current.ready).toBe(false)

      await hook.unmount()
    },
  )

  it("removes the widget on unmount", async () => {
    const fake = installFakeTurnstile()
    const hook = await mountHook({ siteKey: "site-key" })

    await hook.unmount()

    expect(fake.api.remove).toHaveBeenCalledWith("widget-0")
    expect(fake.widgets.get("widget-0")?.removed).toBe(true)
  })

  it("re-renders the widget and drops readiness when the site key changes", async () => {
    const fake = installFakeTurnstile()
    const hook = await mountHook({ siteKey: "first-key" })
    await hook.run(() => fake.callbackFor("callback")())
    expect(hook.current.ready).toBe(true)

    await hook.setOptions({ siteKey: "second-key" })

    expect(fake.api.remove).toHaveBeenCalledWith("widget-0")
    expect(fake.api.render.mock.calls[1]?.[1]).toMatchObject({
      sitekey: "second-key",
    })
    expect(hook.current.ready).toBe(false)

    await hook.unmount()
  })

  it("is ready again when the site key is removed", async () => {
    installFakeTurnstile()
    const hook = await mountHook({ siteKey: "site-key" })
    expect(hook.current.ready).toBe(false)

    await hook.setOptions({ siteKey: null })

    expect(hook.current.ready).toBe(true)
    expect(hook.current.widget).toBeNull()

    await hook.unmount()
  })
})

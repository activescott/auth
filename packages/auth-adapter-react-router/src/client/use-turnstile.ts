import { useEffect, useState } from "react"

/**
 * Where the widget stands. "ready" means the form may submit: a token has
 * been issued, or Turnstile is off. "failed" means it errored or never
 * finished, so the page should say so instead of leaving the submit button
 * disabled forever.
 */
export type TurnstileStatus = "ready" | "pending" | "failed"

/** Options for {@link useTurnstile} */
export interface UseTurnstileOptions {
  /**
   * How long to wait for the first token before reporting "failed" (default
   * 20 seconds). The challenge normally completes within a few seconds;
   * tracking protection and extensions can block its subresources, which
   * leaves the widget silently incomplete forever.
   */
  stallTimeoutMs?: number
}

/** What {@link useTurnstile} returns */
export interface TurnstileState {
  /** False when there is no site key; render no container then */
  enabled: boolean
  status: TurnstileStatus
  /** `status === "ready"`: gate the submit button on this */
  ready: boolean
  /**
   * Attach to an empty element inside the form the widget protects. The
   * widget adds a `cf-turnstile-response` field there, which the server's
   * bot check reads.
   */
  containerRef: (element: HTMLElement | null) => void
}

const DEFAULT_STALL_TIMEOUT_MS = 20_000

const TURNSTILE_SCRIPT_SRC =
  "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"

interface TurnstileApi {
  render(
    container: HTMLElement,
    options: {
      sitekey: string
      callback: () => void
      "expired-callback": () => void
      "error-callback": () => void
    },
  ): string | undefined
  remove(widgetId: string): void
}

function turnstileApi(): TurnstileApi | undefined {
  return (globalThis as { turnstile?: TurnstileApi }).turnstile
}

let scriptPromise: Promise<TurnstileApi> | undefined

/**
 * Load Cloudflare's script once for every widget on the page. A failed load
 * is forgotten, so the next widget to mount tries again.
 */
function loadTurnstileScript(): Promise<TurnstileApi> {
  const loaded = turnstileApi()
  if (loaded) return Promise.resolve(loaded)
  scriptPromise ??= new Promise<TurnstileApi>((resolve, reject) => {
    const script = document.createElement("script")
    script.src = TURNSTILE_SCRIPT_SRC
    script.async = true
    script.addEventListener("load", () => {
      const api = turnstileApi()
      if (api) resolve(api)
      else reject(new Error("Turnstile script loaded without an API"))
    })
    script.addEventListener("error", () =>
      reject(new Error("Failed to load the Turnstile script")),
    )
    document.head.append(script)
  }).catch((error: unknown) => {
    scriptPromise = undefined
    throw error
  })
  return scriptPromise
}

/**
 * Cloudflare Turnstile for a form that posts to an initiate endpoint:
 * renders the widget into `containerRef` and reports whether the form may
 * submit yet. Posting before the widget has a token gets the request blocked
 * by the bot check, and the block looks exactly like a successful send, so
 * the user waits for a message that never comes; disable the submit button
 * until `ready`.
 *
 * The widget is rendered explicitly from an effect rather than by Cloudflare's
 * scan for `.cf-turnstile` elements. The scan races hydration: it can render
 * into the server-rendered container before React hydrates it, and React's
 * mismatch recovery then replaces the container and orphans the widget,
 * leaving it empty for good.
 *
 * With no site key the hook does nothing and reports "ready".
 *
 * @param siteKey - The public Turnstile site key, or null/empty when Turnstile is off
 *
 * @example
 * ```tsx
 * const turnstile = useTurnstile(loaderData.turnstileSiteKey)
 * // inside the form
 * {turnstile.enabled && <div ref={turnstile.containerRef} />}
 * {turnstile.status === "failed" ? (
 *   <p>The bot check could not load. Reload the page to try again.</p>
 * ) : (
 *   <button disabled={!turnstile.ready}>Send</button>
 * )}
 * ```
 */
export function useTurnstile(
  siteKey: string | null | undefined,
  options: UseTurnstileOptions = {},
): TurnstileState {
  const stallTimeoutMs = options.stallTimeoutMs ?? DEFAULT_STALL_TIMEOUT_MS
  const enabled = Boolean(siteKey)
  const [container, setContainer] = useState<HTMLElement | null>(null)
  const [status, setStatus] = useState<TurnstileStatus>(
    enabled ? "pending" : "ready",
  )

  useEffect(() => {
    if (!siteKey) {
      setStatus("ready")
      return
    }
    setStatus("pending")

    // Runs even while no container is attached, so a missing ref ends in
    // "failed" rather than a button that never enables
    const stallTimer = setTimeout(() => {
      setStatus((current) => (current === "pending" ? "failed" : current))
    }, stallTimeoutMs)
    let cancelled = false
    let widgetId: string | undefined

    if (container) {
      loadTurnstileScript()
        .then((turnstile) => {
          if (cancelled) return
          widgetId = turnstile.render(container, {
            sitekey: siteKey,
            callback: () => {
              clearTimeout(stallTimer)
              setStatus("ready")
            },
            // The widget fetches a fresh token itself, so wait again rather
            // than alarm
            "expired-callback": () => setStatus("pending"),
            "error-callback": () => {
              clearTimeout(stallTimer)
              setStatus("failed")
            },
          })
        })
        .catch(() => {
          if (cancelled) return
          clearTimeout(stallTimer)
          setStatus("failed")
        })
    }

    return () => {
      cancelled = true
      clearTimeout(stallTimer)
      if (widgetId !== undefined) turnstileApi()?.remove(widgetId)
    }
  }, [siteKey, container, stallTimeoutMs])

  return {
    enabled,
    status,
    ready: status === "ready",
    containerRef: setContainer,
  }
}

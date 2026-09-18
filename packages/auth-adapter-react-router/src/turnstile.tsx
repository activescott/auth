import { useEffect, useRef, useState } from "react"
import type { ReactNode } from "react"

/**
 * Global function Cloudflare's script calls once `window.turnstile` exists.
 * `satisfies` ties it to {@link TurnstileGlobal} so the name in the script URL
 * and the name we assign cannot drift apart.
 */
const ONLOAD_GLOBAL =
  "__activescottAuthTurnstileOnload" satisfies keyof TurnstileGlobal

/**
 * Cloudflare's widget script, in explicit-render mode.
 *
 * The plain script URL renders implicitly: it scans the document for
 * `.cf-turnstile` elements once, when the script loads. A React Router login
 * page is often reached by client-side navigation, long after that scan, so
 * an implicitly rendered widget would never appear, never issue a token, and
 * a submit button gated on `ready` would stay disabled for good. Explicit
 * rendering builds the widget when the hook mounts instead.
 */
const SCRIPT_URL = `https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=${ONLOAD_GLOBAL}`

/** Where Turnstile renders: light, dark, or follow the user's preference */
export type TurnstileTheme = "light" | "dark" | "auto"
/** Widget footprint; `flexible` fills its container's width */
export type TurnstileSize = "normal" | "flexible" | "compact"
/** When the widget becomes visible */
export type TurnstileAppearance = "always" | "execute" | "interaction-only"

export interface UseTurnstileOptions {
  /**
   * Turnstile site key, or null/undefined when Turnstile is not configured.
   * Without a key nothing renders and `ready` is always true, so one form
   * works whether or not the deployment has the check turned on.
   */
  siteKey: string | null | undefined
  /** Class for the element the widget renders into */
  className?: string
  theme?: TurnstileTheme
  size?: TurnstileSize
  appearance?: TurnstileAppearance
  /** Label Cloudflare groups this widget under in analytics */
  action?: string
}

export interface Turnstile {
  /**
   * False until the widget has issued a token, and false again once that
   * token expires, errors, or times out.
   *
   * Disable the form's submit control while this is false. The token is
   * issued asynchronously and can take seconds on a slow phone; a form that
   * posts first sends no `cf-turnstile-response`, and `TurnstileBotCheck`
   * rejects it as `missing_token` after the user already believes they signed
   * in.
   */
  ready: boolean
  /** The widget. Render it inside the form. */
  widget: ReactNode
}

/**
 * Render a Cloudflare Turnstile widget and report whether it has issued a
 * token yet.
 *
 * ```tsx
 * const turnstile = useTurnstile({ siteKey: TURNSTILE_SITE_KEY })
 *
 * return (
 *   <form method="post" action="/auth/email/initiate">
 *     <input name="email" type="email" required />
 *     {turnstile.widget}
 *     <button type="submit" disabled={!turnstile.ready}>
 *       {turnstile.ready ? "Send magic link" : "Verifying you're human…"}
 *     </button>
 *   </form>
 * )
 * ```
 *
 * Pair it with `TurnstileBotCheck` from
 * `@activescott/auth-botcheck-turnstile` on the server.
 */
export function useTurnstile({
  siteKey,
  className,
  theme,
  size,
  appearance,
  action,
}: UseTurnstileOptions): Turnstile {
  const container = useRef<HTMLDivElement | null>(null)
  const [tokenIssued, setTokenIssued] = useState(false)

  useEffect(() => {
    const element = container.current
    if (!siteKey || !element) return

    const options: TurnstileRenderOptions = {
      sitekey: siteKey,
      callback: () => setTokenIssued(true),
      "expired-callback": () => setTokenIssued(false),
      "error-callback": () => setTokenIssued(false),
      "timeout-callback": () => setTokenIssued(false),
    }
    // Only send the keys the caller set; Cloudflare's own defaults are better
    // than anything this hook could invent.
    if (theme) options.theme = theme
    if (size) options.size = size
    if (appearance) options.appearance = appearance
    if (action) options.action = action

    let api: TurnstileApi | undefined
    let widgetId: string | undefined
    let unmounted = false

    void whenTurnstileLoaded().then((loaded) => {
      if (unmounted) return
      api = loaded
      widgetId = loaded.render(element, options)
    })

    return () => {
      unmounted = true
      // A remounted widget starts over with no token, and the old token is
      // bound to a widget that no longer exists.
      setTokenIssued(false)
      if (api && widgetId !== undefined) api.remove(widgetId)
    }
  }, [siteKey, theme, size, appearance, action])

  return {
    ready: !siteKey || tokenIssued,
    widget: siteKey ? (
      <>
        {/* Rendered rather than injected from the effect so the browser
            starts the download while parsing the server's HTML. */}
        <script src={SCRIPT_URL} async defer />
        <div ref={container} className={className} />
      </>
    ) : null,
  }
}

/** The part of Cloudflare's `window.turnstile` this hook uses */
interface TurnstileApi {
  render: (
    container: HTMLElement,
    options: TurnstileRenderOptions,
  ) => string | undefined
  remove: (widgetId: string) => void
}

interface TurnstileRenderOptions {
  sitekey: string
  callback: (token: string) => void
  "expired-callback": () => void
  "error-callback": () => void
  "timeout-callback": () => void
  theme?: TurnstileTheme
  size?: TurnstileSize
  appearance?: TurnstileAppearance
  action?: string
}

interface TurnstileGlobal {
  turnstile?: TurnstileApi
  __activescottAuthTurnstileOnload?: () => void
}

const turnstileGlobal = globalThis as unknown as TurnstileGlobal

let loading: Promise<TurnstileApi> | undefined

/**
 * Resolve once Cloudflare's script has installed `window.turnstile`.
 *
 * The script tag is part of the hook's markup, so it may already have run by
 * the time the effect fires: check for the API before waiting on the onload
 * hook, or a widget mounted late would wait forever.
 */
function whenTurnstileLoaded(): Promise<TurnstileApi> {
  const api = turnstileGlobal.turnstile
  if (api) return Promise.resolve(api)
  loading ??= new Promise<TurnstileApi>((resolve) => {
    turnstileGlobal[ONLOAD_GLOBAL] = () => {
      const loaded = turnstileGlobal.turnstile
      if (loaded) resolve(loaded)
    }
  })
  return loading
}

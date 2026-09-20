import type { ReactNode } from "react"
import { FORM_TOKEN_FIELD } from "@activescott/auth"
import type { TurnstileState } from "@activescott/auth-adapter-react-router/client"

/**
 * The form-side half of the library's built-in bot check, plus the Turnstile
 * widget when it is configured. Drop this inside any form that posts to an
 * `initiate` action, with `turnstile` from `useTurnstile(turnstileSiteKey)`
 * in the same component. Copy it into your app as-is.
 *
 * The form token is a signed render timestamp: the server rejects a
 * submission that arrives faster than a human could have filled the form. It
 * has to be signed — an unsigned timestamp is just another field to forge.
 */
export function AntiBotFields({
  formToken,
  turnstile,
}: {
  formToken: string
  turnstile: TurnstileState
}) {
  return (
    <>
      <input type="hidden" name={FORM_TOKEN_FIELD} value={formToken} />
      {/* The widget is a fixed 300px wide and renders nothing at all under
          data-size="flexible" when its container is narrower, so keep the
          form at least that wide */}
      {turnstile.enabled && <div ref={turnstile.containerRef} />}
    </>
  )
}

/**
 * The submit button for a form with AntiBotFields. It stays disabled until
 * Turnstile has issued a token: a submission without one is blocked, and a
 * blocked request looks exactly like a sent one, so the user would wait for
 * a message that never comes. If the widget never finishes (tracking
 * protection and extensions can block it), the button gives way to a
 * message instead of staying disabled forever.
 */
export function AntiBotSubmitButton({
  turnstile,
  children,
}: {
  turnstile: TurnstileState
  children: ReactNode
}) {
  if (turnstile.status === "failed") {
    return (
      <p className="text-amber-900 bg-amber-50 border border-amber-300 p-3 rounded text-sm">
        The bot check couldn&rsquo;t finish loading. Reload the page to try
        again; tracking protection or a browser extension can block it.
      </p>
    )
  }
  return (
    <button
      type="submit"
      disabled={!turnstile.ready}
      className="bg-blue-600 text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50"
    >
      {turnstile.ready ? children : "Verifying you're human…"}
    </button>
  )
}

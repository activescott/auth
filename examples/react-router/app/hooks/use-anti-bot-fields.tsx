import type { ReactNode } from "react"
import { FORM_TOKEN_FIELD } from "@activescott/auth"
import { useTurnstile } from "@activescott/auth-adapter-react-router/turnstile"

export interface AntiBotFields {
  /**
   * False while Turnstile is still working. Disable the form's submit button
   * on it: Turnstile issues its token asynchronously, and a form that posts
   * before the token exists is rejected server side as `missing_token` — no
   * email, no code, and an error redirect the user is likely to miss.
   */
  ready: boolean
  /** Hidden form token plus the Turnstile widget, if one is configured */
  fields: ReactNode
}

/**
 * The form-side half of the library's built-in bot check, plus the Turnstile
 * widget when it is configured. Use it in any form that posts to an
 * `initiate` action — copy it into your app as-is.
 *
 * The form token is a signed render timestamp: the server rejects a
 * submission that arrives faster than a human could have filled the form. It
 * has to be signed — an unsigned timestamp is just another field to forge.
 *
 * With no `TURNSTILE_SITE_KEY` set (dev and the e2e suite) `ready` is true
 * from the first render and nothing extra renders, so the forms behave the
 * same with the check on or off.
 */
export function useAntiBotFields({
  formToken,
  turnstileSiteKey,
}: {
  formToken: string
  turnstileSiteKey: string | null
}): AntiBotFields {
  const turnstile = useTurnstile({ siteKey: turnstileSiteKey })

  return {
    ready: turnstile.ready,
    fields: (
      <>
        <input type="hidden" name={FORM_TOKEN_FIELD} value={formToken} />
        {turnstile.widget}
      </>
    ),
  }
}

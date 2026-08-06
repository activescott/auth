import { FORM_TOKEN_FIELD } from "@activescott/auth"

/**
 * The form-side half of the library's built-in bot check, plus the Turnstile
 * widget when it is configured. Drop this inside any form that posts to an
 * `initiate` action — copy it into your app as-is.
 *
 * The form token is a signed render timestamp: the server rejects a
 * submission that arrives faster than a human could have filled the form. It
 * has to be signed — an unsigned timestamp is just another field to forge.
 */
export function AntiBotFields({
  formToken,
  turnstileSiteKey,
}: {
  formToken: string
  turnstileSiteKey: string | null
}) {
  return (
    <>
      <input type="hidden" name={FORM_TOKEN_FIELD} value={formToken} />

      {turnstileSiteKey && (
        <>
          <script
            src="https://challenges.cloudflare.com/turnstile/v0/api.js"
            async
            defer
          />
          <div className="cf-turnstile" data-sitekey={turnstileSiteKey} />
        </>
      )}
    </>
  )
}

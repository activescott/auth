# @activescott/auth-botcheck-turnstile

[Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/) bot check
for [`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth).

`@activescott/auth` protects the initiate endpoints out of the box with per-IP
and per-recipient rate limits and a minimum form-fill time —
none of which need a third party. Add this package when you want a hosted bot
check on top of those layers. It is a separate package so applications that do
not use Turnstile never install it.

Zero runtime dependencies: verification is one `fetch` to Cloudflare's
`siteverify` endpoint.

## Install

```bash
npm install @activescott/auth-botcheck-turnstile
```

## Server

```typescript
import { Auth } from "@activescott/auth"
import { TurnstileBotCheck } from "@activescott/auth-botcheck-turnstile"

const auth = new Auth({
  // ...session, stores, providers
  abuse: {
    botChecks: [
      new TurnstileBotCheck({ secretKey: process.env.TURNSTILE_SECRET_KEY }),
    ],
  },
})
```

A request that fails the check is answered exactly as a successful send would
be, and the rejection is logged with the reason Cloudflare returned. A request
with no token at all is the exception: it gets `BOT_CHECK_INCOMPLETE` (below).

## Client

The widget issues its token asynchronously, after the page loads and
sometimes several seconds later on a slow phone. A form submitted before then
posts no `cf-turnstile-response` field and the check rejects it, so the form
must wait. Keep submit disabled until the widget's `callback` fires, and
disable it again on `expired-callback` while the widget fetches a fresh token.
Render the widget explicitly so the callbacks are attached before it runs:

```html
<form method="post" action="/auth/email/initiate">
  <input type="email" name="email" required />
  <div id="turnstile"></div>
  <button type="submit" id="send" disabled>Send magic link</button>
</form>

<script>
  const send = document.getElementById("send")
  function onTurnstileLoad() {
    turnstile.render("#turnstile", {
      sitekey: "YOUR_SITE_KEY",
      callback: () => (send.disabled = false),
      "expired-callback": () => (send.disabled = true),
      "error-callback": () => (send.disabled = true),
    })
  }
</script>
<script
  src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onTurnstileLoad"
  async
  defer
></script>
```

React Router apps can use `useTurnstile` from
[`@activescott/auth-adapter-react-router`](https://www.npmjs.com/package/@activescott/auth-adapter-react-router)
(`/client` subpath), which does this wiring and reports `ready`.

If a form is submitted without a token anyway, the initiate endpoint answers
`BOT_CHECK_INCOMPLETE` instead of the usual block response: a 302 back to the
form with `?error=BOT_CHECK_INCOMPLETE`, or a 400 for JSON callers. Show the
user a message asking them to wait a moment and try again;
`getAuthErrorMessage` from `@activescott/auth` has a default one. Every other
rejection is answered as before. Versions of `@activescott/auth` without
`BOT_CHECK_INCOMPLETE` treat a missing token like any other rejection.

## Configuration

| Option      | Default                   | Notes                                                            |
| ----------- | ------------------------- | ---------------------------------------------------------------- |
| `secretKey` | required                  | Turnstile **secret** key, never the site key                     |
| `fieldName` | `"cf-turnstile-response"` | Form field carrying the widget token                             |
| `verifyUrl` | Cloudflare `siteverify`   | Override for tests or a proxy                                    |
| `timeoutMs` | `5000`                    | How long to wait for `siteverify`                                |
| `failOpen`  | `true`                    | Allow the request when Cloudflare is unreachable; logs a warning |

`failOpen` defaults to `true` because the rate limits still apply
when Turnstile cannot be reached, and an outage at Cloudflare should not lock
every user out of signing in. Set it to `false` to fail closed instead.

## License

MIT

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
be, and the rejection is logged with the reason Cloudflare returned.

## Client

Render the widget inside the login form so the browser posts the
`cf-turnstile-response` field along with the address:

```html
<script
  src="https://challenges.cloudflare.com/turnstile/v0/api.js"
  async
  defer
></script>

<form method="post" action="/auth/email/initiate">
  <input type="email" name="email" required />
  <div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
  <button type="submit">Send magic link</button>
</form>
```

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

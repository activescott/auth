# @activescott/auth-provider-sms

[![npm version](https://img.shields.io/npm/v/@activescott/auth-provider-sms.svg)](https://www.npmjs.com/package/@activescott/auth-provider-sms)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

SMS one-time-code provider for [`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth). The user enters their mobile number, gets texted a 6-digit code, and types (or autofills) it to sign in.

This package has **no vendor dependencies** — message delivery is injected via the `SmsTransport` interface. Use a vendor package or write your own:

- [`@activescott/auth-sms-twilio`](https://www.npmjs.com/package/@activescott/auth-sms-twilio) — Twilio (SMS, or RCS via a Messaging Service)
- `ConsoleTransport` (included) — prints codes to the server console for development
- Custom: implement `SmsTransport { sendMessage(to, message): Promise<boolean> }`. An AWS End User Messaging transport is drafted in [PR #37](https://github.com/activescott/auth/pull/37) — implemented and unit-tested but unverified against a live AWS account; if you want AWS and can test it end to end, feel free to take over that PR ([#36](https://github.com/activescott/auth/issues/36) has the checklist).

## Usage

```ts
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import { SmsProvider, ConsoleTransport } from "@activescott/auth-provider-sms"
import { TwilioTransport } from "@activescott/auth-sms-twilio"

const auth = new Auth({
  session: { secret: process.env.JWT_SECRET! /* ... */ },
  userStore,
  identityStore,
  challengeStore: new InMemoryChallengeStore(), // DB-backed in production
  providers: [
    new SmsProvider(
      { appName: "MyApp", webOtpDomain: "myapp.example" },
      process.env.NODE_ENV === "production"
        ? new TwilioTransport({
            accountSid: process.env.TWILIO_ACCOUNT_SID!,
            authToken: process.env.TWILIO_AUTH_TOKEN!,
            messagingServiceSid: process.env.TWILIO_MESSAGING_SERVICE_SID,
          })
        : new ConsoleTransport(),
    ),
  ],
})
```

The login form posts the phone number to `/auth/sms/initiate` (the provider texts the code, sets an HttpOnly challenge cookie, and redirects back with `?sent=1`); the code form posts to `/auth/sms/verify`. A runnable app demonstrating the full flow is at [`examples/react-router`](https://github.com/activescott/auth/tree/main/examples/react-router):

```html
<form method="post" action="/auth/sms/initiate">
  <input name="phone" type="tel" autocomplete="tel" required />
  <button>Text me a code</button>
</form>

<form method="post" action="/auth/sms/verify">
  <input
    name="code"
    autocomplete="one-time-code"
    inputmode="numeric"
    pattern="[0-9]{6}"
    required
  />
  <button>Sign in</button>
</form>
```

## Configuration

| Option            | Default                | Description                                                                                                                          |
| ----------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `appName`         | `"App"`                | Shown in the default message text                                                                                                    |
| `expiry`          | `"10m"`                | Code lifetime (`"30s"`, `"10m"`, `"1h"`, ...)                                                                                        |
| `webOtpDomain`    | (off)                  | Appends the [WebOTP](https://developer.mozilla.org/docs/Web/API/WebOTP_API) line `@domain #code` for Android/Chrome one-tap autofill |
| `messageTemplate` | built-in               | `(code, appName) => string` to customize the text                                                                                    |
| `otp.length`      | `6`                    | Digits in the code                                                                                                                   |
| `otp.maxAttempts` | `5`                    | Wrong guesses before the challenge is invalidated (`RATE_LIMITED`)                                                                   |
| `otp.cookieName`  | `"auth_sms_challenge"` | Challenge cookie name                                                                                                                |

The default message (with `webOtpDomain` set) looks like:

```
Your MyApp sign-in code is: 123456

@myapp.example #123456
```

The last line is the [origin-bound one-time code format](https://wicg.github.io/sms-one-time-codes/) (a WICG spec co-edited by Apple and Google — what [WebOTP](https://developer.mozilla.org/docs/Web/API/WebOTP_API) and Safari's code autofill parse). The human-readable sentence matters too: Apple publishes no exact grammar for iOS Security Code AutoFill, which recognizes codes heuristically from the message text (see [`autocomplete="one-time-code"` on MDN](https://developer.mozilla.org/docs/Web/HTML/Attributes/autocomplete)) — `Your <app> sign-in code is: <code>` follows the widely observed patterns. Custom templates should keep a similar shape for autofill to work.

## Phone numbers

Input is normalized (spaces, dashes, dots, parentheses stripped; leading `00` → `+`) and must then be valid [E.164](https://en.wikipedia.org/wiki/E.164) (`+` and country code required) — the provider never guesses a default country. `normalizePhoneNumber` is exported if you want the same normalization client-side.

## Testing pattern: capture transport

In e2e tests, wrap your `SmsTransport` in `CaptureSmsTransport` and read the code back through a test-only route (gated on a test-mode env var **and** a shared-secret header) instead of needing a phone — or paying for the text.

```typescript
import { CaptureSmsTransport } from "@activescott/auth-provider-sms/testing"

export const smsTransport =
  process.env.E2E_TEST_MODE === "true"
    ? new CaptureSmsTransport(new TwilioTransport({ ... }))
    : new TwilioTransport({ ... })

// in your gated readback route:
const captured = smsTransport.getCapturedSms(phone) // { message, code }
```

The code is parsed out of the default message template; pass a second argument to `CaptureSmsTransport` when you configure a custom `messageTemplate`. It lives at the `/testing` subpath rather than the package root so it stays out of your application's default import graph.

## Security model

Same challenge model as the email provider: one server-side challenge per send, code stored only as a salted SHA-256 hash, attempts counted **before** each comparison (capped at `maxAttempts`), constant-time compare, single-use (deleted on success), and the challenge is bound to the initiating browser by an HttpOnly cookie — a code alone is useless without it.

Per-number and per-IP send throttling ships in `@activescott/auth` and is on by default (see its [abuse protection](../auth/README.md#abuse-protection) section); vendor-level fraud/pumping guards (Twilio, AWS) are still worth enabling on top.

If you think any of this should work differently — protections that belong in this library, a weakness in the model — please [open an issue or PR](https://github.com/activescott/auth/issues) to discuss.

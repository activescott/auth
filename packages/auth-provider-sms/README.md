# @activescott/auth-provider-sms

[![npm version](https://img.shields.io/npm/v/@activescott/auth-provider-sms.svg)](https://www.npmjs.com/package/@activescott/auth-provider-sms)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

SMS one-time-code provider for [`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth). The user enters their mobile number, gets texted a 6-digit code, and types (or autofills) it to sign in.

This package has **no vendor dependencies** — delivery is injected as a transport. Use a vendor package or write your own:

- [`@activescott/auth-sms-twilio`](https://www.npmjs.com/package/@activescott/auth-sms-twilio) — Twilio: `TwilioMessagingTransport` (SMS, or RCS via a Messaging Service) and `TwilioVerifyTransport` (Twilio Verify)
- `ConsoleTransport` (included) — prints codes to the server console for development
- Custom: implement `SmsTransport { sendMessage(to, message): Promise<boolean> }`. An AWS End User Messaging transport is drafted in [PR #37](https://github.com/activescott/auth/pull/37) — implemented and unit-tested but unverified against a live AWS account; if you want AWS and can test it end to end, feel free to take over that PR ([#36](https://github.com/activescott/auth/issues/36) has the checklist).

## Two kinds of transport

|                                        | `SmsTransport`                                                                                 | `VerificationTransport`                                        |
| -------------------------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| Who makes the code                     | this package                                                                                   | the vendor                                                     |
| Who checks the code                    | this package                                                                                   | the vendor                                                     |
| US A2P 10DLC registration              | **yours to do** — brand + campaign via The Campaign Registry, days to weeks, plus monthly fees | **none** — the vendor sends from senders it already registered |
| Cost per sign-in (US)                  | ~$0.011–0.013 per SMS                                                                          | ~$0.058 (Twilio Verify: $0.05 per success + channel fee)       |
| Message text, code length, WebOTP line | yours                                                                                          | the vendor's                                                   |

`SmsProvider` accepts either. Routes, request bodies, cookie binding, abuse checks, and error responses are identical, so switching is a one-line change at construction:

```ts
new SmsProvider({ appName: "MyApp" }, new TwilioVerifyTransport({ ... }))
```

Pick `VerificationTransport` when 10DLC registration is the thing standing between you and shipping — at low sign-in volume its fixed monthly fees often exceed the entire Verify bill. Pick `SmsTransport` when volume makes per-message price dominate, or you want control over the message text.

## Usage

```ts
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import { SmsProvider, ConsoleTransport } from "@activescott/auth-provider-sms"
import { TwilioMessagingTransport } from "@activescott/auth-sms-twilio"

const auth = new Auth({
  session: { secret: process.env.JWT_SECRET! /* ... */ },
  userStore,
  identityStore,
  challengeStore: new InMemoryChallengeStore(), // DB-backed in production
  providers: [
    new SmsProvider(
      { appName: "MyApp", webOtpDomain: "myapp.example" },
      process.env.NODE_ENV === "production"
        ? new TwilioMessagingTransport({
            accountSid: process.env.TWILIO_ACCOUNT_SID!,
            authToken: process.env.TWILIO_AUTH_TOKEN!,
            messagingServiceSid: process.env.TWILIO_SMS_MESSAGING_SERVICE_SID,
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

With a `VerificationTransport` the vendor composes the message, so `appName`, `messageTemplate`, `webOtpDomain`, and `otp.length` do nothing — configure those at the vendor instead. `expiry`, `otp.maxAttempts`, and `otp.cookieName` still apply; `expiry` bounds this package's challenge record, while the vendor enforces its own code lifetime, and whichever expires first ends the attempt.

The default message (with `webOtpDomain` set) looks like:

```
Your MyApp sign-in code is: 123456

@myapp.example #123456
```

The last line is the [origin-bound one-time code format](https://wicg.github.io/sms-one-time-codes/) (a WICG spec co-edited by Apple and Google — what [WebOTP](https://developer.mozilla.org/docs/Web/API/WebOTP_API) and Safari's code autofill parse). The human-readable sentence matters too: Apple publishes no exact grammar for iOS Security Code AutoFill, which recognizes codes heuristically from the message text (see [`autocomplete="one-time-code"` on MDN](https://developer.mozilla.org/docs/Web/HTML/Attributes/autocomplete)) — `Your <app> sign-in code is: <code>` follows the widely observed patterns. Custom templates should keep a similar shape for autofill to work.

## Phone numbers

Input is normalized (spaces, dashes, dots, parentheses stripped; leading `00` → `+`) and must then be valid [E.164](https://en.wikipedia.org/wiki/E.164) (`+` and country code required) — the provider never guesses a default country. `normalizePhoneNumber` is exported if you want the same normalization client-side.

## Security model

Same challenge model as the email provider: one server-side challenge per send, code stored only as a salted SHA-256 hash, attempts counted **before** each comparison (capped at `maxAttempts`), constant-time compare, single-use (deleted on success), and the challenge is bound to the initiating browser by an HttpOnly cookie — a code alone is useless without it.

With a `VerificationTransport` the code never reaches your server at all, so there is no hash to store; the challenge record holds the phone number and the vendor's reference. Everything else is unchanged, including counting the attempt **before** the vendor is asked — which also caps how many billable checks one challenge can produce.

Delivery-level protections (per-number send throttling, fraud/pumping protection) belong at the app and vendor level; both Twilio and AWS offer built-in fraud guards.

If you think any of this should work differently — protections that belong in this library, a weakness in the model — please [open an issue or PR](https://github.com/activescott/auth/issues) to discuss.

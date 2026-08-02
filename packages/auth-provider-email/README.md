# @activescott/auth-provider-email

[![npm version](https://img.shields.io/npm/v/@activescott/auth-provider-email.svg)](https://www.npmjs.com/package/@activescott/auth-provider-email)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Email magic-link authentication provider for [`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth).

Sends a sign-in email containing a single-use magic link and a numeric one-time code, both backed by one server-side challenge. Redeeming either finds-or-creates the user via your `UserStore`/`IdentityStore` and hands control back to the auth core to issue a session cookie.

Used in production by [ramblefeed.com](https://ramblefeed.com) and [tinkerbellbot.com](https://tinkerbellbot.com).

## Install

```bash
npm install @activescott/auth @activescott/auth-provider-email
```

## Usage

```ts
import { Auth } from "@activescott/auth"
import { EmailProvider } from "@activescott/auth-provider-email"

const auth = new Auth({
  // ...session, identityStore, userStore, challengeStore...
  providers: [
    new EmailProvider({
      smtp: {
        host: process.env.SMTP_HOST!,
        port: Number(process.env.SMTP_PORT),
        user: process.env.SMTP_USER!,
        pass: process.env.SMTP_PASS!,
      },
      from: process.env.FROM_EMAIL!,
      template: { appName: "My App", subject: "Sign in to My App" },
    }),
  ],
})
```

## Routes registered

The provider handles four URL patterns under `/auth/email/*` (mounted by your framework adapter):

| Method | Path                   | Purpose                                          |
| ------ | ---------------------- | ------------------------------------------------ |
| POST   | `/auth/email/initiate` | Send a magic link to the supplied email.         |
| POST   | `/auth/email/send`     | Alias of `initiate`.                             |
| GET    | `/auth/email/verify`   | Verify the token from the link, log the user in. |
| POST   | `/auth/email/verify`   | Verify a one-time code (when `otp` is enabled).  |
| GET    | `/auth/email/callback` | Alias of `verify`.                               |

## How a sign-in email works

Each send creates one server-side challenge (via the `Auth` config's `challengeStore`) with two redemption paths, both single-use and sharing one expiry (default 15m):

1. **The magic link** — `/auth/email/verify?challenge=<id>&key=<256-bit secret>`. Clicking it (GET) shows a minimal **"Confirm sign-in"** page; the confirm button POSTs the redemption. Email security scanners (Outlook SafeLinks, Mimecast, link previews) prefetch links with GET but never submit forms, so they cannot consume the single-use link.
2. **The numeric code** — the user types it on your sign-in page instead of clicking the link. iOS and macOS detect the code in Mail and offer it via AutoFill when your input uses `autoComplete="one-time-code"`. `initiate` sets an HttpOnly `auth_challenge` cookie binding code entry to the initiating browser; your code input POSTs to `/auth/email/verify`. Codes are attempt-capped: wrong code → `INVALID_CREDENTIALS`, too many tries → `RATE_LIMITED`, expired → `EXPIRED_TOKEN`.

There are no signing secrets to manage for sign-in emails — both the link key and the code are stored as salted hashes in the challenge and deleted on use.

Tuning: `expiry` (top-level, e.g. `"15m"`) and `otp: { length?, maxAttempts?, cookieName? }`, or env vars `EMAIL_EXPIRY`, `EMAIL_OTP_LENGTH`, `EMAIL_OTP_MAX_ATTEMPTS` with `emailConfigFromEnvironment`.

## Dev mode (no SMTP needed)

`NodemailerTransport` accepts an `isDevelopment` flag. When `true`, it buffers the email via Nodemailer's stream transport (no real SMTP connection) and prints the magic link to the server console — useful for local dev, examples, and CI:

```ts
import {
  EmailProvider,
  NodemailerTransport,
} from "@activescott/auth-provider-email"

new EmailProvider(
  {/* ...config... */},
  new NodemailerTransport(true), // dev mode: log link, don't send
)
```

Or pass no transport at all and the provider auto-creates `new NodemailerTransport(process.env.NODE_ENV === "development")`.

## Custom email transport

Ships with `NodemailerTransport` (SMTP). Implement `EmailTransport` to plug in Resend, SES, Postmark, or anything else:

```ts
import type {
  EmailProviderConfig,
  EmailTransport,
} from "@activescott/auth-provider-email"

class ResendTransport implements EmailTransport {
  async sendMagicLink(
    to: string,
    magicLink: string,
    config: EmailProviderConfig,
  ): Promise<boolean> {
    // ...call Resend API...
    return true
  }
}

new EmailProvider(config, new ResendTransport())
```

## Testing pattern: capture transport

In e2e tests, wrap your `EmailTransport` in a capture transport that records the last magic link + code per recipient, expose them through a test-only readback route (gated on a test-mode env var and a shared-secret header), and drive the real confirm-page or code-entry flow — no SMTP server, no inbox polling. See the runnable example linked below.

## Documentation & example

Full docs and a runnable React Router framework-mode example with Playwright tests live in the monorepo:

→ **https://github.com/activescott/auth**

## License

MIT

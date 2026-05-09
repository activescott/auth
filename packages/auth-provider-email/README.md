# @activescott/auth-provider-email

[![npm version](https://img.shields.io/npm/v/@activescott/auth-provider-email.svg)](https://www.npmjs.com/package/@activescott/auth-provider-email)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Email magic-link authentication provider for [`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth).

Sends a signed JWT in a clickable link; on click, verifies the token, finds-or-creates the user via your `UserStore`/`IdentityStore`, and hands control back to the auth core to issue a session cookie.

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
  // ...session, identityStore, userStore...
  providers: [
    new EmailProvider({
      magicLinkSecret: process.env.JWT_MAGIC_LINK_SECRET!,
      magicLinkExpiry: "5m",
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
| GET    | `/auth/email/callback` | Alias of `verify`.                               |

## Dev mode (no SMTP needed)

`NodemailerTransport` accepts an `isDevelopment` flag. When `true`, it buffers the email via Nodemailer's stream transport (no real SMTP connection) and prints the magic link to the server console — useful for local dev, examples, and CI:

```ts
import {
  EmailProvider,
  NodemailerTransport,
} from "@activescott/auth-provider-email"

new EmailProvider(
  {
    /* ...config... */
  },
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

## Testing pattern: `additionalSecrets`

`EmailProvider.verify()` accepts tokens signed by either the primary `magicLinkSecret` or any entry in `additionalSecrets`. In e2e tests, mint your own magic-link JWT with a dedicated test secret and visit `/auth/email/verify?token=...` directly — no SMTP server, no inbox polling. See the runnable example linked below.

## Documentation & example

Full docs and a runnable React Router framework-mode example with Playwright tests live in the monorepo:

→ **https://github.com/activescott/auth**

## License

MIT

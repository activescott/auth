# @activescott/auth

[![npm version](https://img.shields.io/npm/v/@activescott/auth.svg)](https://www.npmjs.com/package/@activescott/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Framework-agnostic direct authentication, deliberately small: single-use magic links and one-time codes via email and SMS, and passkeys (WebAuthn). No third-party identity providers. Runs on Node and edge runtimes (e.g. Cloudflare Workers).

This package is the core: the `Auth` class, JWT-cookie session management, and the provider/store interfaces. It does not handle any specific authentication method by itself — pair it with one or more provider packages and (optionally) a framework adapter:

- [`@activescott/auth-provider-email`](https://www.npmjs.com/package/@activescott/auth-provider-email) — email magic links + one-time codes
- [`@activescott/auth-provider-sms`](https://www.npmjs.com/package/@activescott/auth-provider-sms) — SMS one-time codes ([`@activescott/auth-sms-twilio`](https://www.npmjs.com/package/@activescott/auth-sms-twilio) provides both Twilio transports: Messaging and Verify)
- [`@activescott/auth-provider-passkey`](https://www.npmjs.com/package/@activescott/auth-provider-passkey) — passkeys (WebAuthn)
- [`@activescott/auth-adapter-react-router`](https://www.npmjs.com/package/@activescott/auth-adapter-react-router) — React Router v8 adapter

Used in production by [ramblefeed.com](https://ramblefeed.com) and [tinkerbellbot.com](https://tinkerbellbot.com).

## Why direct, passwordless authentication?

Everyone has an email address or a phone number. Nobody wants another password. And many users hesitate at "Sign in with Google/Apple/Microsoft" because it shares their sign-in activity with a third party. This library focuses on the ways a person can authenticate **directly** with your app:

- **Lowest friction for your users.** No password to create, forget, or reset, and no account with a third party required. Modern platforms AutoFill the codes we send, so signing in is: type your email, type the code your OS offers you.
- **Easiest for you.** No OAuth app registrations, no identity-provider dashboards, no extra services. An SMTP server and your database are the only dependencies.
- **Private by design.** No third-party identity provider in the loop — big tech doesn't learn when (or that) your users sign in to your app.
- **Deliberately small.** This is not a works-with-every-OAuth-provider auth library — that niche is well served by projects like [BetterAuth](https://www.better-auth.com/). Constraining the scope is what keeps this one easy to drop into a new app.

Passkeys push the same idea further: phishing-resistant, no shared secret, and still no third party.

## Features

- ✅ **Email magic links** — single-use, server-backed sign-in links with a confirm step that email security scanners can't consume (see the [FAQ](https://github.com/activescott/auth#faq)). In production.
- ✅ **Email one-time codes** — every sign-in email also includes a numeric code with iOS/macOS AutoFill support, so users can type the code instead of switching to the inbox tab.
- ✅ **Bring your own database** — three small store interfaces (`IdentityStore`, `UserStore`, `ChallengeStore`); implement them with Prisma, Drizzle, raw SQL, Redis, whatever you use.
- ✅ **Edge-ready, [WinterTC-compatible](https://wintertc.org/faq) core** — standard Fetch `Request`/`Response`, WebCrypto, and [`jose`](https://github.com/panva/jose) for session JWTs; no Node-only APIs, so it runs on Cloudflare Workers, Deno, Bun, and any WinterTC-aligned runtime.
- ✅ **React Router v8 adapter** — `createAuthHandlers`, `requireAuth`, `optionalAuth`, `getSession`, `logout`.
- ✅ **SMS one-time codes** — vendor-neutral provider with a Twilio Messaging transport (RCS-ready) and [WebOTP](https://developer.mozilla.org/docs/Web/API/WebOTP_API) autofill support.
- ✅ **Hosted verification (no US A2P 10DLC)** — the same SMS provider accepts a `VerificationTransport` where the vendor generates, sends, and checks the code. `TwilioVerifyTransport` ships in the Twilio package: no number to buy, no brand or campaign registration — at the cost of ~4–6x per sign-in.
- ✅ **Abuse protection, on by default** — per-IP and per-recipient rate limits, a minimum-form-fill-time check, blocked attempts logged, and a blocked caller gets the same response a successful send would produce. Optional packages add hosted bot checks ([Turnstile](https://www.npmjs.com/package/@activescott/auth-botcheck-turnstile)).
- ✅ **Passkeys (WebAuthn)** — add a passkey while signed in, then sign in usernameless with Touch ID, Face ID, Windows Hello, 1Password, iCloud Keychain, or a security key; conditional UI (passkey autofill) supported. Verification via [`@simplewebauthn/server`](https://simplewebauthn.dev/); zero-dependency browser client included.

The provider interface (`AuthProvider`) is the extension point. Implementing a new provider does not require changes to this core package.

## Documentation & example

Full docs — quick start, architecture diagram, custom-provider guide, e2e-testing pattern, FAQ — and a runnable React Router framework-mode example with Playwright tests live in the monorepo:

→ **https://github.com/activescott/auth**

The rest of this README covers what this core package itself exports and expects.

## Install

```bash
npm install @activescott/auth
```

## What's in the box

| Export                                                            | Purpose                                                                                                               |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `Auth`                                                            | Orchestrator. Routes auth requests to providers, manages session cookies.                                             |
| `SessionManager`                                                  | Standalone JWT session signer/verifier (rarely needed directly).                                                      |
| `AuthProvider`                                                    | Interface every provider implements (`initiate`, `verify`, `canHandle`, optional `handleAction` for extra endpoints). |
| `IdentityStore`, `UserStore`                                      | Interfaces you implement to plug in your database.                                                                    |
| `ChallengeStore`, `InMemoryChallengeStore`                        | Storage for short-lived, single-use challenges (see below).                                                           |
| `AbuseConfig`, `RateLimitStore`, `InMemoryRateLimitStore`         | Abuse protection for the initiate endpoints — on by default (see below).                                              |
| `BotCheckProvider`, `createFormToken`, `FORM_TOKEN_FIELD`         | Bot-check interface and the login form's anti-bot fields.                                                             |
| `generateOtpCode`, `hashOtpCode`, `verifyOtpCode`                 | One-time-code utilities used by OTP-capable providers.                                                                |
| `AuthUser`, `Identity`, `Session`, `AuthResult`, `AuthInitResult` | Core data types.                                                                                                      |
| `AuthErrors`, `getAuthErrorMessage`, `AUTH_ERROR_CODES`           | Structured error helpers.                                                                                             |

## Data model

You bring three adapters — `IdentityStore`, `UserStore`, and `ChallengeStore` — that read/write your database. The library handles challenges, cookies, provider routing, and session verification.

An `Identity` is a `(provider, identifier)` pair (e.g. `("email", "alice@example.com")`) linked to one of your `User` records. One user can have multiple identities — email, phone, and passkeys all use the same table.

`Identity.metadata` is **provider-owned state**, opaque to your application: persist it unmodified (a JSON/JSONB column) and return it exactly as stored. Providers with per-identity state keep it there — the passkey provider stores each credential's public key and signature counter — and stateless providers store `{}`. It may contain sensitive material, so protect it like credential data (encryption at rest is a reasonable default). `IdentityStore.update(id, {metadata, verifiedAt})` replaces stored metadata wholesale; providers rely on it, so it is a required method.

## Minimal shape

```ts
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import { EmailProvider } from "@activescott/auth-provider-email"

const auth = new Auth({
  session: {
    secret: process.env.JWT_SECRET!,
    maxAge: "30d",
    cookieName: "session",
    cookie: { secure: true, sameSite: "lax", path: "/" },
  },
  identityStore, // your impl
  userStore, // your impl
  challengeStore: new InMemoryChallengeStore(), // DB-backed in production
  providers: [new EmailProvider({ ... })],
})
```

Then call `auth.handleRequest(request)` from your framework's routing layer (or use a framework adapter), and `auth.verifySession(request)` to check the session cookie on protected routes.

## ChallengeStore

Every sign-in attempt is backed by a server-side challenge: magic links and one-time codes store the hashed secret, an attempt counter, and an expiry; passkey ceremonies record the WebAuthn challenge so it is redeemable exactly once. That state lives in the `challengeStore`, which is why it is a required part of the `Auth` config.

`InMemoryChallengeStore` is right for a single server process (and dev/examples). Challenges are lost on restart and not shared across instances — for multi-instance deployments implement the four-method `ChallengeStore` interface against shared storage. A SQL implementation is roughly:

```sql
CREATE TABLE challenges (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  identifier TEXT NOT NULL,
  hashed_code TEXT,
  data JSONB,
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
```

with `incrementAttempts` as `UPDATE challenges SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts` (the increment must be atomic — it enforces the guess limit), and a periodic `DELETE ... WHERE expires_at < now()`.

## Abuse protection

The `initiate` endpoints send mail and texts to whatever address a caller submits, which makes them an attractive way to mail-bomb a third party or burn your sending reputation on bounces. Protection is **on by default** — you do not have to configure or implement anything:

| Layer                  | Default                                                    |
| ---------------------- | ---------------------------------------------------------- |
| Per client IP          | 3 per minute, then 10 per hour                             |
| Per recipient          | 3 per hour, then 10 per day                                |
| Minimum form-fill time | 2 seconds (only enforced if the form posts a token, below) |
| Counter storage        | `InMemoryRateLimitStore`                                   |
| Blocked response       | identical to a successful send                             |

Blocked attempts are always logged (`console.warn`) with the reason, provider, IP, requested identifier, and rule, so an abuse burst is visible:

```
[auth] blocked initiate: reason=identifier_rate_limited provider=email ip=203.0.113.7 identifier=victim@example.com rule=3/3600s retryAfter=2841s
```

### A blocked caller sees a success

By design a throttled or bot-flagged request gets exactly the response a real send would produce — the same 302 back to `?sent=1`, or the same `{success: true, message}` — minus the challenge cookie. Nothing is sent and nothing is stored. This is what keeps a bot from mapping which addresses or IPs are throttled. If you would rather return `429 RATE_LIMITED` (reasonable for an API-only deployment), set `abuse.respondWith: "rateLimited"`.

### Tuning

```ts
const auth = new Auth({
  // ...
  abuse: {
    perIp: [
      { windowSeconds: 60, max: 3 },
      { windowSeconds: 3600, max: 10 },
    ],
    perIdentifier: [{ windowSeconds: 3600, max: 3 }],
    store: myRedisRateLimitStore, // multi-instance: share the counters
    onBlocked: (event) => logger.warn(event, "auth abuse blocked"),
  },
})
```

`abuse: { enabled: false }` turns everything off.

`InMemoryRateLimitStore` counts per process, so a multi-instance deployment effectively multiplies every limit by the instance count. Implement the one-method `RateLimitStore` interface against Redis (`INCR` + `EXPIRE`) or your database to share counters.

Client IPs come from `cf-connecting-ip`, then `x-forwarded-for` (rightmost hop; set `abuse.clientIp.trustedProxyHops` if more than one proxy appends), then `x-real-ip`. These headers are spoofable unless a proxy in front of your app rewrites them — supply `abuse.clientIp.getClientIp` when your runtime exposes the peer address. When no IP can be determined, per-IP limits are skipped and per-recipient limits still apply.

### Form token

The minimum-form-fill-time check needs one hidden field in your login form:

```tsx
import { createFormToken, FORM_TOKEN_FIELD } from "@activescott/auth"

// in the route/loader that renders the form:
const formToken = await createFormToken(process.env.JWT_SECRET!)
```

```html
<input type="hidden" name="authFormToken" value="{formToken}" />
```

The token is a signed render timestamp; the server rejects submissions that arrive faster than `minFormFillSeconds`. It must be signed — an unsigned timestamp is just another field to forge. A submission with **no** token is allowed, so adding the field is optional and can be rolled out later. A token older than a day is also allowed rather than rejected — a login page left open in a tab is a human.

### Hosted bot checks

Cloudflare Turnstile, hCaptcha, and friends live in their own packages, so you only install the vendor you use:

```ts
import { TurnstileBotCheck } from "@activescott/auth-botcheck-turnstile"

abuse: {
  botChecks: [new TurnstileBotCheck({ secretKey: process.env.TURNSTILE_SECRET_KEY! })],
}
```

Implement `BotCheckProvider` (`{ id, verify({ request, body, ip, providerId }) }`) to add your own.

## License

MIT

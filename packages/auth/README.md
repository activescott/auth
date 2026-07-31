# @activescott/auth

[![npm version](https://img.shields.io/npm/v/@activescott/auth.svg)](https://www.npmjs.com/package/@activescott/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Framework-agnostic authentication core for TypeScript. [WinterTC-compatible](https://wintertc.org/faq): built on standard Fetch `Request`/`Response`, WebCrypto, and [`jose`](https://github.com/panva/jose), so it runs on Node and any WinterTC-aligned runtime (Cloudflare Workers, Deno, Bun, etc.).

This package provides the `Auth` class, JWT-cookie session management, and the provider/store interfaces. It does not handle any specific authentication method by itself — pair it with a provider package:

- [`@activescott/auth-provider-email`](https://www.npmjs.com/package/@activescott/auth-provider-email) — email magic links + one-time codes
- _SMS OTP_ — planned
- _Passkeys (WebAuthn)_ — planned

The library deliberately focuses on **direct** authentication — email, phone, passkeys — rather than OAuth federation; see the monorepo README for the reasoning.

…and a framework adapter:

- [`@activescott/auth-adapter-react-router`](https://www.npmjs.com/package/@activescott/auth-adapter-react-router) — React Router v7

Used in production by [ramblefeed.com](https://ramblefeed.com) and [tinkerbellbot.com](https://tinkerbellbot.com).

## Install

```bash
npm install @activescott/auth
```

## What's in the box

| Export                                                            | Purpose                                                                   |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `Auth`                                                            | Orchestrator. Routes auth requests to providers, manages session cookies. |
| `SessionManager`                                                  | Standalone JWT session signer/verifier (rarely needed directly).          |
| `AuthProvider`                                                    | Interface every provider implements (`initiate`, `verify`, `canHandle`).  |
| `IdentityStore`, `UserStore`                                      | Interfaces you implement to plug in your database.                        |
| `ChallengeStore`, `InMemoryChallengeStore`                        | Storage for short-lived OTP challenges (see below).                       |
| `generateOtpCode`, `hashOtpCode`, `verifyOtpCode`                 | One-time-code utilities used by OTP-capable providers.                    |
| `AuthUser`, `Identity`, `Session`, `AuthResult`, `AuthInitResult` | Core data types.                                                          |
| `AuthErrors`, `getAuthErrorMessage`, `AUTH_ERROR_CODES`           | Structured error helpers.                                                 |

## Data model

You bring two adapters, `IdentityStore` and `UserStore`, that read/write your database. The library handles tokens, cookies, provider routing, and session verification.

An `Identity` is a `(provider, identifier)` pair (e.g. `("email", "alice@example.com")`) linked to one of your `User` records. One user can have multiple identities — the model is ready for a future where a user signs in via email _and_ Google.

## Minimal shape

```ts
import { Auth } from "@activescott/auth"
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
  providers: [new EmailProvider({ ... })],
})
```

Then call `auth.handleRequest(request)` from your framework's routing layer (or use a framework adapter), and `auth.verifySession(request)` to check the session cookie on protected routes.

## ChallengeStore (required for OTP codes)

Magic links are stateless JWTs, but one-time codes need server-side state: the hashed code, an attempt counter, and an expiry. Configuring a `challengeStore` on the `Auth` config is what turns codes on — OTP-capable providers (e.g. `EmailProvider`) include codes automatically when it is present and skip them when it is not:

```ts
import { InMemoryChallengeStore } from "@activescott/auth"

const auth = new Auth({
  // ...
  challengeStore: new InMemoryChallengeStore(),
})
```

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

## Documentation & example

Full docs, architecture diagram, custom-provider guide, and a runnable React Router framework-mode example with Playwright tests live in the monorepo:

→ **https://github.com/activescott/auth**

## License

MIT

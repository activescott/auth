# @activescott/auth

[![npm version](https://img.shields.io/npm/v/@activescott/auth.svg)](https://www.npmjs.com/package/@activescott/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Framework-agnostic authentication core for TypeScript. Designed to run on Node and edge runtimes (Workers, Vercel Edge, etc.).

This package provides the `Auth` class, JWT-cookie session management, and the provider/store interfaces. It does not handle any specific authentication method by itself — pair it with a provider package:

- [`@activescott/auth-provider-email`](https://www.npmjs.com/package/@activescott/auth-provider-email) — email magic links
- _SMS magic links / OTP_ — planned
- _OAuth (Google, GitHub, etc.)_ — planned

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

## Documentation & example

Full docs, architecture diagram, custom-provider guide, and a runnable React Router framework-mode example with Playwright tests live in the monorepo:

→ **https://github.com/activescott/auth**

## License

MIT

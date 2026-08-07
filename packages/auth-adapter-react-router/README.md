# @activescott/auth-adapter-react-router

[![npm version](https://img.shields.io/npm/v/@activescott/auth-adapter-react-router.svg)](https://www.npmjs.com/package/@activescott/auth-adapter-react-router)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

React Router adapter (v7 and v8) for [`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth). Wraps the framework-agnostic `Auth` class in handlers that read/write standard `Request` and `Response` objects — exactly what React Router loaders and actions return.

The adapter imports nothing from `react-router`; it only speaks Fetch `Request`/`Response`, so the same build works on both major versions.

Used in production by [ramblefeed.com](https://ramblefeed.com) and [tinkerbellbot.com](https://tinkerbellbot.com).

## Install

```bash
npm install @activescott/auth @activescott/auth-provider-email @activescott/auth-adapter-react-router
```

## Usage

```ts
// app/lib/auth.server.ts
import { Auth } from "@activescott/auth"
import { EmailProvider } from "@activescott/auth-provider-email"
import { createAuthHandlers } from "@activescott/auth-adapter-react-router"

export const auth = new Auth({/* ...session, stores, providers... */})

export const { handleAuth, getSession, requireAuth, optionalAuth, logout } =
  createAuthHandlers(auth, {
    successRedirect: "/",
    errorRedirect: "/login",
    loginUrl: "/login",
  })
```

`errorRedirect` as a string appends `?error=<code>` to that path, which discards whatever query the form was submitted from. If your login page keeps state in the query — a `?via=sms` tab selection, say — a failed code would be answered on the wrong tab. The function form receives the failing request, so core's `buildReturnUrl` can send the browser back to the exact page it posted from:

```ts
import { buildReturnUrl } from "@activescott/auth"

errorRedirect: (error, request) =>
  buildReturnUrl(request, { error: error.code })
```

Then add a single catch-all route at `app/routes/auth.$provider.$action.tsx` that handles every provider's HTTP endpoints:

```tsx
import { handleAuth } from "~/lib/auth.server"
import type { Route } from "./+types/auth.$provider.$action"

export const loader = ({ request }: Route.LoaderArgs) => handleAuth({ request })
export const action = ({ request }: Route.ActionArgs) => handleAuth({ request })
```

This one file covers `/auth/<provider>/<action>` for every registered provider — e.g. `POST /auth/email/initiate` (your login form posts here), `GET /auth/email/verify?...` (magic-link confirm page), `POST /auth/email/verify` (link redemption or code entry), `/auth/sms/...`, `/auth/passkey/...`, etc. `handleAuth` dispatches to the right provider, runs `verify` or `initiate`, sets/clears the session cookie, and returns a redirect — or passes through a page the provider renders (like the magic-link confirm page).

Protect any loader with `requireAuth(request)`:

```tsx
export async function loader({ request }: Route.LoaderArgs) {
  const user = await requireAuth(request) // redirects to /login if no session
  return { user }
}
```

## API

| Export               | Purpose                                                                                        |
| -------------------- | ---------------------------------------------------------------------------------------------- |
| `createAuthHandlers` | Returns `{ handleAuth, getSession, requireAuth, optionalAuth, refreshSessionCookie, logout }`. |

Login pages need no action of their own: post the email form directly to `/auth/email/initiate` (the provider redirects back with `?sent=1`) and the code form to `/auth/email/verify`.

`createAuthHandlers<TUser>` is generic over your application's user type. Pass a `mapUser` to get a typed `requireAuth<TUser>` / `optionalAuth<TUser>` instead of the bare `AuthUser`.

## Documentation & example

Full docs and a runnable React Router framework-mode example with Playwright tests live in the monorepo:

→ **https://github.com/activescott/auth**

## License

MIT

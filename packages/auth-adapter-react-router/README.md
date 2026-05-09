# @activescott/auth-adapter-react-router

React Router v7 adapter for [`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth). Wraps the framework-agnostic `Auth` class in handlers that read/write standard `Request` and `Response` objects — exactly what React Router loaders and actions return.

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
import {
  createAuthHandlers,
  sendMagicLink as sendMagicLinkBase,
} from "@activescott/auth-adapter-react-router"

export const auth = new Auth({
  /* ...session, stores, providers... */
})

export const { handleAuth, getSession, requireAuth, optionalAuth, logout } =
  createAuthHandlers(auth, {
    successRedirect: "/",
    errorRedirect: "/login",
    loginUrl: "/login",
  })

export const sendMagicLink = (email: string, baseUrl: string) =>
  sendMagicLinkBase(auth, email, baseUrl)
```

Then add a single catch-all route at `app/routes/auth.$provider.$action.tsx` that handles every provider's HTTP endpoints:

```tsx
import { handleAuth } from "~/lib/auth.server"
import type { Route } from "./+types/auth.$provider.$action"

export const loader = ({ request }: Route.LoaderArgs) => handleAuth({ request })
export const action = ({ request }: Route.ActionArgs) => handleAuth({ request })
```

This one file covers `/auth/<provider>/<action>` for every registered provider — e.g. `GET /auth/email/verify?token=...` (user clicked the magic link), `POST /auth/email/initiate` (server-side send), and future `/auth/google/callback`, `/auth/sms/verify`, etc. `handleAuth` dispatches to the right provider, runs `verify` or `initiate`, sets/clears the session cookie, and returns a redirect.

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
| `sendMagicLink`      | Convenience for login-page actions that want to stay on the page and show success/error.       |

`createAuthHandlers<TUser>` is generic over your application's user type. Pass a `mapUser` to get a typed `requireAuth<TUser>` / `optionalAuth<TUser>` instead of the bare `AuthUser`.

## Documentation & example

Full docs and a runnable React Router framework-mode example with Playwright tests live in the monorepo:

→ **https://github.com/activescott/auth**

## License

MIT

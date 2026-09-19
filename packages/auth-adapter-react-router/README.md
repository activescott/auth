# @activescott/auth-adapter-react-router

[![npm version](https://img.shields.io/npm/v/@activescott/auth-adapter-react-router.svg)](https://www.npmjs.com/package/@activescott/auth-adapter-react-router)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

React Router adapter (v7 and v8) for [`@activescott/auth`](https://www.npmjs.com/package/@activescott/auth). Wraps the framework-agnostic `Auth` class in handlers that read/write standard `Request` and `Response` objects — exactly what React Router loaders and actions return.

The adapter imports nothing from `react-router`; it only speaks Fetch `Request`/`Response`, so the same build works on both major versions. That holds for the admin pages too — they are React components that emit plain anchors unless you hand them your router's `Link`.

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

## Per-request checks

Apps usually have a rule about who may hold a session beyond "the cookie verifies": approved accounts only, not the ones you blocked this morning. `onSessionVerified` runs on every session `getSession`, `requireAuth` and `optionalAuth` verify, after `mapUser`. Return or throw a `Response` and the request is bounced with it; return nothing and the session goes on to your loader:

```ts
export const { requireAuth, optionalAuth, clearSessionCookie, logout } =
  createAuthHandlers<AppUser>(auth, {
    mapUser,
    onSessionVerified: ({ user }) => {
      if (user.status === "BLOCKED") {
        return redirect("/login", {
          headers: { "Set-Cookie": auth.destroySessionCookie() },
        })
      }
      if (user.status === "PENDING") return redirect("/waitlist")
    },
  })
```

That replaces the wrapper apps write around `requireAuth` to re-read the user and act on what they find, and because it runs in `optionalAuth` and `getSession` too, a page that renders for signed-out visitors gets the same rule for free. Set `session: { cacheTtlMs: 0 }` on the `Auth` config with it: the hook's `user` is whatever `verifySession` returned, which by default may be up to two minutes old.

It does not run in `renewSessionCookie` or `refreshSessionCookie`, which re-issue a cookie for a session a loader already accepted.

`clearSessionCookie()` returns the `Set-Cookie` value that expires the session cookie, for when you want the header rather than the redirect `logout` wraps it in.

## Rolling sessions

A session expires `maxAge` after it was issued, whether or not the visitor is still using the app. Set `session.renewAfter` and call `renewSessionCookie` from your root loader to re-issue the cookie once it passes that age, so people who keep visiting stay signed in and idle sessions still expire on schedule:

```ts
export const { renewSessionCookie, ...handlers } = createAuthHandlers(auth, {
  session: { renewAfter: "7d" }, // well inside the "30d" maxAge
})

// app/root.tsx
export async function loader({ request }: Route.LoaderArgs) {
  const user = await optionalAuth(request)
  const loaderData = { user }

  const cookie = user && (await renewSessionCookie(request, user))
  return cookie
    ? data(loaderData, { headers: { "Set-Cookie": cookie } })
    : loaderData
}
```

`renewSessionCookie` returns null when the session is still fresh, so the common case sets no header. It throws if you call it without configuring `session.renewAfter`. To update the session because the user's own data changed (a new handle, say) rather than because it is old, use `refreshSessionCookie`, which re-issues unconditionally.

## API

| Export                                 | Purpose                                                                                                                                |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `createAuthHandlers`                   | Returns `{ handleAuth, getSession, requireAuth, optionalAuth, renewSessionCookie, refreshSessionCookie, clearSessionCookie, logout }`. |
| `createAdminHandlers` (from `./admin`) | Returns `{ requireAdmin, adminUsersLoader, adminConfigLoader }`.                                                                       |
| `AdminUsersPage`, `AdminConfigPage`    | The admin pages, from `./admin`.                                                                                                       |

Login pages need no action of their own: post the email form directly to `/auth/email/initiate` (the provider redirects back with `?sent=1`) and the code form to `/auth/email/verify`.

`createAuthHandlers<TUser>` is generic over your application's user type. Pass a `mapUser` to get a typed `requireAuth<TUser>` / `optionalAuth<TUser>` instead of the bare `AuthUser`.

## Admin dashboard

A read-only users page and configuration page, at the `./admin` subpath so apps that do not use them never load React:

```tsx
// app/lib/auth.server.ts
import { createAdminHandlers } from "@activescott/auth-adapter-react-router/admin"

export const { adminUsersLoader, adminConfigLoader } = createAdminHandlers(
  auth,
  {
    requireAuth,
    admins: process.env.AUTH_ADMIN_IDENTIFIERS,
  },
)

// app/routes/admin.users.tsx
import { Link } from "react-router"
import { AdminUsersPage } from "@activescott/auth-adapter-react-router/admin"

export const loader = ({ request }: Route.LoaderArgs) =>
  adminUsersLoader({ request })

export default function AdminUsers({ loaderData }: Route.ComponentProps) {
  return <AdminUsersPage data={loaderData} linkComponent={Link} />
}
```

The users page needs `UserStore.listUsers`, which is optional and which your application implements; put anything you want as an extra column into each user's `metadata` and describe it with `metadataColumns`. Access is an allowlist of email addresses and phone numbers (`AUTH_ADMIN_IDENTIFIERS` by default) that admits nobody when unset; non-admins get a 404.

Full walkthrough: [Admin dashboard](https://github.com/activescott/auth#admin-dashboard).

## E2e code readback

`createCaptureReadbackLoader`, at the `./testing` subpath, is a resource-route loader that hands the last captured sign-in email or SMS to your e2e tests, so they can sign in without an inbox or a phone. Wrap your transports in `CaptureEmailTransport` / `CaptureSmsTransport` (from each provider's `/testing` subpath) under the same test-mode flag:

```ts
// app/routes/e2e.otp-code.tsx
import { createCaptureReadbackLoader } from "@activescott/auth-adapter-react-router/testing"

export const loader = createCaptureReadbackLoader({
  transports: { email: captureEmailTransport, sms: captureSmsTransport },
  enabled: process.env.E2E_TEST_MODE === "true",
  secret: process.env.E2E_MAGIC_LINK_SECRET,
})
```

Tests call `GET /e2e/otp-code?email=...` or `?phone=...` with the secret in an `x-e2e-secret` header. The captured codes are live credentials: the route answers a bare 404 unless `enabled` is exactly `true` and the secret matches, and creating it with `enabled` but no secret throws. Never set the flag in production.

## Documentation & example

Full docs and a runnable React Router framework-mode example with Playwright tests live in the monorepo:

→ **https://github.com/activescott/auth**

## License

MIT

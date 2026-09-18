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

## API

| Export                                 | Purpose                                                                                        |
| -------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `createAuthHandlers`                   | Returns `{ handleAuth, getSession, requireAuth, optionalAuth, refreshSessionCookie, logout }`. |
| `createAdminHandlers` (from `./admin`) | Returns `{ requireAdmin, adminUsersLoader, adminConfigLoader }`.                               |
| `AdminUsersPage`, `AdminConfigPage`    | The admin pages, from `./admin`.                                                               |
| `useTurnstile` (from `./turnstile`)    | Renders a Cloudflare Turnstile widget and reports when it has a token.                         |

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

## Turnstile widget

If you protect the initiate endpoints with [`TurnstileBotCheck`](https://www.npmjs.com/package/@activescott/auth-botcheck-turnstile), the form has to wait for the widget. Turnstile issues its token asynchronously and can take seconds on a slow phone; a form submitted before then posts no `cf-turnstile-response` and the server rejects the sign-in as `missing_token` after the user already believes it worked. `useTurnstile` renders the widget and tells you when it is safe to submit:

```tsx
import { useTurnstile } from "@activescott/auth-adapter-react-router/turnstile"

export default function Login({ loaderData }: Route.ComponentProps) {
  const turnstile = useTurnstile({ siteKey: loaderData.turnstileSiteKey })

  return (
    <Form method="post" action="/auth/email/initiate" reloadDocument>
      <input name="email" type="email" required />
      {turnstile.widget}
      <button type="submit" disabled={!turnstile.ready}>
        {turnstile.ready ? "Send magic link" : "Verifying you're human…"}
      </button>
    </Form>
  )
}
```

`ready` starts false, flips true when the widget issues a token, and goes back to false if that token expires, errors, or times out. Pass `siteKey: null` where Turnstile is not configured (dev, e2e) and `ready` is true from the first render with nothing rendered, so one form covers both.

The widget is created with Cloudflare's explicit-render API rather than the `class="cf-turnstile"` markup from their docs, which only gets scanned when their script loads: a login page reached by client-side navigation would otherwise get no widget at all and could never become ready. Either way the widget puts the token in a hidden `cf-turnstile-response` input, so the form posts it with everything else.

This is at the `./turnstile` subpath for the same reason the admin pages are at `./admin`: the main entry stays React-free.

## Documentation & example

Full docs and a runnable React Router framework-mode example with Playwright tests live in the monorepo:

→ **https://github.com/activescott/auth**

## License

MIT

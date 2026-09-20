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
| `createAuthPageLoaders`                | Returns `{ signInLoader, profileAuthLoader, listSignInMethods }`. See [Sign-in and profile pages](#sign-in-and-profile-pages).         |
| Hooks (from `./client`)                | `useTurnstile`, `usePasskeySignIn`, `useRegisterPasskey`, `useOtpAutoSubmit`, `usePreservedInput`.                                     |
| `createAdminHandlers` (from `./admin`) | Returns `{ requireAdmin, adminUsersLoader, adminConfigLoader }`.                                                                       |
| `AdminUsersPage`, `AdminConfigPage`    | The admin pages, from `./admin`.                                                                                                       |
| `ProfilePage` (from `./profile`)       | The profile page, and `AccountSummary`, `SignInMethods`, `Passkeys` separately. See [Profile page](#profile-page).                     |

Login pages need no action of their own: post the email form directly to `/auth/email/initiate` (the provider redirects back with `?sent=1`) and the code form to `/auth/email/verify`.

`createAuthHandlers<TUser>` is generic over your application's user type. Pass a `mapUser` to get a typed `requireAuth<TUser>` / `optionalAuth<TUser>` instead of the bare `AuthUser`.

## Sign-in and profile pages

The adapter ships the logic of a sign-in page and a profile page's sign-in methods section, and leaves the markup to you. The loaders run on the server and read what the providers put in the query string on the way back; the hooks run in the browser. The profile page's markup ships too, as components: see [Profile page](#profile-page).

```ts
// app/lib/auth.server.ts
import { createAuthPageLoaders } from "@activescott/auth-adapter-react-router"
import { listPasskeys } from "@activescott/auth-provider-passkey" // only if you use passkeys

export const { signInLoader, profileAuthLoader } = createAuthPageLoaders(auth, {
  turnstileSiteKey: process.env.TURNSTILE_SITE_KEY,
  listPasskeys,
  errorMessages: { blocked: "Your account has been blocked." },
})
```

`signInLoader(request)` returns `{ via, sent, error, errorCode, redirectTo, formToken, turnstileSiteKey }`: which provider's form to show, whether the message went out, the message for `?error=`, a same-origin `redirectTo` or null, and the signed form token the abuse checks expect under `FORM_TOKEN_FIELD`. `profileAuthLoader(userId, request)` returns `{ identities, passkeys, linkFlow }`, where `linkFlow` is the add-a-sign-in-method flow: the open form (`?add=`), `sent`, `linked`, `merged`, and `conflict`, the provider whose `link-merge` redeems the merge ticket after an `IDENTITY_CONFLICT`. It takes that provider from `?provider=`, else `?add=`, so put `?add=` in the verify step's `redirectTo`. `errorMessages` adds codes the library does not know, such as an initiate gate's, and rewords any it does; both loaders also take it per call.

The hooks are at the `./client` subpath and need React, not React Router:

| Hook                                           | For                                                                                                                                                   |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `useTurnstile(siteKey)`                        | Renders the Turnstile widget into `containerRef` and reports `ready`; disable submit until then. Reports `"failed"` after 20 seconds without a token. |
| `usePasskeySignIn({ client, redirectTo })`     | `signIn` for the passkey button; a full page load of `redirectTo` on success. `autofill: true` adds conditional UI.                                   |
| `useRegisterPasskey({ client, onRegistered })` | `register` for "Add a passkey"; pass `useRevalidator().revalidate` as `onRegistered`.                                                                 |
| `useOtpAutoSubmit(length)`                     | `inputProps` for the code field (autofill attributes included) that submit the form when the last digit lands.                                        |
| `usePreservedInput(key)`                       | Keeps the typed address or number across the round trip through the auth routes, in sessionStorage.                                                   |

The passkey hooks take `createPasskeyClient()` from `@activescott/auth-provider-passkey/browser` as `client`, so apps without passkeys never install the WebAuthn library. A Turnstile token matters more than it looks: a form posted without one is blocked, and the block answers exactly like a successful send, so the user waits for an email that never comes.

[`examples/react-router`](https://github.com/activescott/auth/tree/main/examples/react-router) uses all of them: `app/routes/login.tsx` and `app/routes/dashboard.tsx`.

## Profile page

A profile page is the same page in every app, so the adapter ships one at the `./profile` subpath. `ProfilePage` renders the account summary, the sign-in methods and the passkeys; it takes what `profileAuthLoader` returns.

```tsx
// app/routes/profile.tsx
import { Link, useRevalidator } from "react-router"
import { ProfilePage } from "@activescott/auth-adapter-react-router/profile"
import { profileAuthLoader, requireAuth } from "~/lib/auth.server"
import { passkeys } from "~/lib/passkeys"

export async function loader({ request }: Route.LoaderArgs) {
  const user = await requireAuth(request)
  return {
    email: user.email,
    memberSince: user.createdAt.toISOString(),
    ...(await profileAuthLoader(user.id, request)),
  }
}

export default function Profile({ loaderData }: Route.ComponentProps) {
  const revalidator = useRevalidator()
  return (
    <ProfilePage
      {...loaderData}
      addMethods={[
        { provider: "email" },
        { provider: "sms", callingCode: "+1" },
      ]}
      passkeyClient={passkeys}
      onPasskeyRegistered={revalidator.revalidate}
      linkComponent={Link}
    />
  )
}
```

`addMethods` is what the page offers to add, in the order the links appear; it offers nothing by default, and drops a provider the account already signs in with unless the entry sets `allowMultiple`. `callingCode` makes the field take a national number and submit the full E.164 one. `allowMerge` turns an `IDENTITY_CONFLICT` into an offer to merge the two accounts rather than an error, so set it only where your `UserStore.onMerge` merges.

An application with sections of its own renders the blocks directly, in whatever order, with whatever between them:

```tsx
<AccountSummary email={user.email} entries={[{ label: "Handle", value: user.handle }]} />
<HandleSection handle={user.handle} />
<SignInMethods identities={identities} linkFlow={linkFlow} addMethods={addMethods} linkComponent={Link} />
<Passkeys passkeys={passkeys} client={passkeyClient} onRegistered={revalidator.revalidate} />
```

### Styling

Every block takes `classNames`, one class per slot: `card`, `cardBody`, `cardTitle`, `table`, `th`, `td`, `field`, `label`, `input`, `submitButton`, `success` and the rest of `ProfileClassNames`. A slot you name gets your class and none of the built-in styling, because an inline style outranks any class it would otherwise compete with; slots you say nothing about keep the plain built-in look, and `includeDefaultStyles={false}` drops that everywhere. A Bootstrap application passes its own classes and the page looks like the rest of the app:

```tsx
const profileClasses = {
  card: "card mb-4",
  cardBody: "card-body",
  cardTitle: "h5",
  table: "table",
  input: "form-control",
  label: "form-label",
  submitButton: "btn btn-primary",
  addButton: "btn btn-outline-primary",
  cancelButton: "btn btn-outline-secondary",
  success: "alert alert-success",
  error: "alert alert-danger",
  warning: "alert alert-warning",
}
```

The blocks import React but nothing from `react-router`, so links go through the optional `linkComponent`; without it they are plain anchors, which navigate the whole document. The forms are plain `<form>` elements on purpose: each step of an add-a-sign-in-method flow is a document POST the auth routes answer with a redirect, which is what lets the flow's state live in the URL.

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

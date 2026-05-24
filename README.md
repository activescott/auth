# @activescott/auth

[![npm version](https://img.shields.io/npm/v/@activescott/auth.svg)](https://www.npmjs.com/package/@activescott/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Framework-agnostic authentication for TypeScript with a provider pattern. Designed to run on Node and edge runtimes (e.g. Cloudflare Workers).

Used in production by [ramblefeed.com](https://ramblefeed.com) and [tinkerbellbot.com](https://tinkerbellbot.com).

## Status

- **Email magic link** — implemented and in production.
- **OAuth providers** (Google, GitHub) — implemented. See `@activescott/auth-provider-oauth`.
- **SMS magic link / OTP codes** — planned, not yet implemented.

The provider interface (`AuthProvider` in `@activescott/auth`) is the extension point. Implementing a new provider does not require changes to the core package.

## Packages

| Package                                                                          | Description                                                                                                                               |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| [`@activescott/auth`](./packages/auth)                                           | Core: `Auth` class, `SessionManager`, types, JWT-cookie sessions, `isProviderEnabled()` helper.                                           |
| [`@activescott/auth-provider-email`](./packages/auth-provider-email)             | Email magic link provider. Ships a Nodemailer SMTP transport; the `EmailTransport` interface lets you swap in others (Resend, SES, etc.). |
| [`@activescott/auth-provider-oauth`](./packages/auth-provider-oauth)             | OAuth 2.0 / OIDC social login. Includes `GoogleProvider` (OIDC) and `GitHubProvider`. PKCE, CSRF, account linking built in.               |
| [`@activescott/auth-adapter-react-router`](./packages/auth-adapter-react-router) | React Router v7 adapter. Provides `createAuthHandlers`, `requireAuth`, `optionalAuth`, `getSession`, `logout`, `sendMagicLink`.           |

Adapters for other frameworks (Hono, Next.js, SvelteKit, plain Fetch handlers) can be added — they're thin wrappers around `Auth.handleRequest(request)` and `Auth.verifySession(request)`, both of which take a standard `Request`.

## Architecture

```mermaid
flowchart LR
    app["Your app<br/><br/>• IdentityStore impl<br/>• UserStore impl<br/>• login / logout routes"]
    adapter["Framework adapter<br/>(e.g. react-router)<br/><br/>createAuthHandlers()"]
    core["@activescott/auth<br/><br/>• Auth<br/>• SessionManager (JWT)<br/>• cookie session cache"]
    providers["AuthProvider<br/><br/>• email (magic link)<br/>• oauth (Google, GitHub)<br/>• sms (planned)"]

    app -- "calls" --> adapter
    adapter -- "delegates to" --> core
    core -- "dispatches to" --> providers
    providers -- "reads/writes via" --> app
```

You bring two adapters — `IdentityStore` and `UserStore` — that read/write your database. The library handles tokens, cookies, provider routing, and session verification.

An `Identity` is a `(provider, identifier)` pair (e.g. `("email", "alice@example.com")`) linked to one of your `User` records. One user can have multiple identities — the data model is ready for a future where a user signs in via email _and_ Google.

## Install

```bash
# Email magic link + React Router adapter
npm install @activescott/auth @activescott/auth-provider-email @activescott/auth-adapter-react-router

# Add OAuth social login (Google, GitHub)
npm install @activescott/auth-provider-oauth
```

## React Router quick start

A complete, runnable example lives in [`examples/react-router`](./examples/react-router) — a real React Router v7 framework-mode app with login, logout, a protected dashboard, and a Playwright e2e suite. CI runs the example end-to-end on every PR.

If you'd rather wire it into an existing app, the steps are:

### Step 1 — Implement `IdentityStore` and `UserStore`

Two interfaces from `@activescott/auth` that read/write your database. Identities are `(provider, identifier)` rows; users are your own user records. See [`examples/react-router/app/lib/auth.server.ts`](./examples/react-router/app/lib/auth.server.ts) for in-memory versions you can replace with Prisma/Drizzle/Kysely/raw SQL/Redis/etc.

### Step 2 — Configure `Auth` (server-only)

```ts
// app/lib/auth.server.ts
import { Auth } from "@activescott/auth"
import { EmailProvider } from "@activescott/auth-provider-email"
import {
  createAuthHandlers,
  sendMagicLink as sendMagicLinkBase,
} from "@activescott/auth-adapter-react-router"

export const auth = new Auth({
  session: {
    secret: process.env.JWT_SECRET!,
    maxAge: "30d",
    cookieName: "session",
    cookie: { secure: true, sameSite: "lax", path: "/" },
  },
  identityStore, // from step 1
  userStore, // from step 1
  providers: [
    new EmailProvider({
      magicLinkSecret: process.env.JWT_MAGIC_LINK_SECRET!,
      magicLinkExpiry: "5m",
      smtp: {
        /* host, port, user, pass */
      },
      from: process.env.FROM_EMAIL!,
    }),
  ],
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

### Step 3 — Add the catch-all auth route

A single file at `app/routes/auth.$provider.$action.tsx` handles every provider's HTTP endpoints (`/auth/email/verify`, `/auth/email/initiate`, `/auth/google/callback`, `/auth/github/callback`, etc.):

```tsx
import { handleAuth } from "~/lib/auth.server"
import type { Route } from "./+types/auth.$provider.$action"

export const loader = ({ request }: Route.LoaderArgs) => handleAuth({ request })
export const action = ({ request }: Route.ActionArgs) => handleAuth({ request })
```

`handleAuth` dispatches to the right provider, runs `verify` or `initiate`, sets/clears the session cookie, and returns a redirect.

### Step 4 — Add `login` and `logout` routes

`login.tsx` action calls `sendMagicLink(email, baseUrl)`. `logout.tsx` action/loader calls `logout()`. See the example for the full files (~30 lines each).

### Step 5 — Protect routes with `requireAuth`

In any loader:

```tsx
export async function loader({ request }: Route.LoaderArgs) {
  const user = await requireAuth(request) // redirects to /login if no session
  return { user }
}
```

Use `optionalAuth(request)` instead if the route should render for both signed-in and signed-out users.

---

For a richer pattern — extending `AuthUser` with your own user fields and getting a typed `requireAuth<TUser>` via `mapUser` — see the production usage in ramblefeed (referenced in [`examples/react-router/README.md`](./examples/react-router/README.md)).

## Adding OAuth social login

Install the OAuth package and add providers to the `providers` array:

```ts
import { Auth, isProviderEnabled } from '@activescott/auth'
import { GoogleProvider, GitHubProvider } from '@activescott/auth-provider-oauth'

const auth = new Auth({
  // ...session, identityStore, userStore...
  providers: [
    new GoogleProvider({
      enabled: isProviderEnabled('google'),        // reads AUTH_GOOGLE_ENABLED env var
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      oauthStateSecret: process.env.OAUTH_STATE_SECRET!,
    }),
    new GitHubProvider({
      enabled: isProviderEnabled('github'),
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      oauthStateSecret: process.env.OAUTH_STATE_SECRET!,
    }),
  ],
})
```

The catch-all route from Step 3 above handles the OAuth callbacks automatically — no extra routes needed. Add sign-in links pointing at `/auth/google/initiate` and `/auth/github/initiate` on your login page.

`isProviderEnabled(id)` reads `AUTH_<PROVIDER_ID_UPPER>_ENABLED` from env vars (defaults to `true`). Use `auth.getEnabledProviders()` to get a `{ id, name }[]` list for rendering buttons dynamically.

See [`packages/auth-provider-oauth/README.md`](./packages/auth-provider-oauth/README.md) for full configuration options (custom scopes, `linkByVerifiedEmail`, etc.) and [`examples/react-router`](./examples/react-router) for a complete wired-up example.

## Testing apps that use this library

The example also demonstrates the recommended e2e pattern (also used in production by ramblefeed and tinkerbellbot):

1. Set `additionalSecrets: [process.env.E2E_MAGIC_LINK_SECRET]` on the `EmailProvider` config — these secrets are accepted by the verifier in addition to the primary secret.
2. In your test helper, mint a magic-link JWT signed with that e2e secret and visit `/auth/email/verify?token=...` directly.

This exercises the real verify → cookie → `requireAuth` path with no SMTP server, no inbox polling, and no flaky waits. See [`examples/react-router/tests/helpers/auth.ts`](./examples/react-router/tests/helpers/auth.ts).

For OAuth providers, real browser flows can't run in CI. The example ships a test-only `/auth/test-login` route that creates a real user + session without touching the provider — see [`examples/react-router/README.md`](./examples/react-router/README.md).

## Implementing a custom provider

Implement the [`AuthProvider`](./packages/auth/src/types.ts) interface from `@activescott/auth` and pass an instance into `new Auth({ providers: [...] })`.

Good references:

- [`packages/auth-provider-email/src/email-provider.ts`](./packages/auth-provider-email/src/email-provider.ts) — minimal, no external dependencies; shows how `initiate` / `verify` / `canHandle` / `getRoutes` fit together.
- [`packages/auth-provider-oauth/src/base/oauth-provider.ts`](./packages/auth-provider-oauth/src/base/oauth-provider.ts) — abstract base class for OAuth 2.0 / OIDC providers with PKCE, discovery caching, JWKS token validation, and account linking built in. Extend it to add a new OAuth provider in ~30 lines.

## Development

```bash
npm install
npm run build      # builds all workspaces
npm run typecheck
npm test
```

This is an npm workspaces monorepo.

## Release process

Releases are fully automated from `main`. They use [Conventional Commits](https://www.conventionalcommits.org/) plus per-package independent versioning via [`@simple-release`](https://www.npmjs.com/package/@simple-release/core), and publish to npm with [trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC).

### Commit message rules

Enforced locally by a `husky` `commit-msg` hook running `commitlint` (see `commitlint.config.js`):

- **Type prefix** required: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, etc. (`@commitlint/config-conventional`).
- **Scope is required and restricted** to one of the package directory names:
  - `auth`
  - `auth-provider-email`
  - `auth-provider-oauth`
  - `auth-adapter-react-router`
  - `examples` — for changes under `examples/` (no release, since example workspaces are `private`)
- **Breaking changes** use `!` after the scope or a `BREAKING CHANGE:` footer.

Examples:

```
feat(auth): add SessionManager.refresh()
fix(auth-provider-email): handle empty SMTP response
chore(auth-adapter-react-router): bump react-router peer to ^7.13
feat(auth)!: rename IdentityStore.findByProviderAndIdentifier
```

The commit's scope determines which package gets bumped. A commit scoped to `auth` only bumps `@activescott/auth`; multi-package changes need separate commits per scope.

### Merging PRs

Because release versioning is driven by individual commits, **squash-merging a multi-package PR collapses everything under one commit with one scope** — only that scope's package will be bumped, and the other packages' changes ship un-released. Pick whichever fits the PR:

- **Single package** → squash-merge is fine.
- **Multiple packages** → either:
  1. **Rebase-merge** (preserves the per-scope commits so each package gets its bump), or
  2. **Split into one PR per package**, each squash-mergeable.

The most common pattern here is option 2 — one PR per package keeps reviews focused and release notes clean.

### Version bump rules

Standard conventional-commit semantics, applied independently per package:

| Commit                                    | Bump       |
| ----------------------------------------- | ---------- |
| `fix(scope):`                             | patch      |
| `feat(scope):`                            | minor      |
| `feat(scope)!:` or `BREAKING CHANGE:`     | major      |
| `chore`, `docs`, `refactor`, `test`, etc. | no release |

### CI pipeline (`.github/workflows/ci.yaml`)

Three jobs run on every push to `main`:

1. **`validate`** — `npm ci`, `build`, `typecheck`, `test`. Also runs on PRs.
2. **`release`** (main only) — runs `scripts/release.ts`, which uses `@simple-release` to:
   - Walk commits since the last tag for each package.
   - Bump versions, update `CHANGELOG.md`, commit, tag (`auth@0.1.2`, `auth-provider-email@0.1.3`, …), and push.
   - Create GitHub Releases.
   - Emit `packages-to-publish.json` listing only the packages that actually got bumped.
3. **`publish`** (main only, matrix over `packages-to-publish.json`) — for each bumped package: `npm ci`, `npm run build`, `npm publish --access public`. Authentication uses npm trusted publishing via OIDC (`id-token: write` in workflow permissions); no long-lived `NPM_TOKEN` is required once trusted publishing is configured for each package on npmjs.com.

If no packages were bumped (e.g. a `chore:` commit), the publish job is skipped.

### Releasing

There is no manual release command. To release: merge a PR with conventional-commit messages into `main`. CI handles the rest.

### Branch protection on `main` — why required PRs and status checks are OFF

`main` protection is intentionally minimal: only force-pushes and branch deletion are blocked. Required pull requests and required status checks are both **off**. CI (`validate`, `example-e2e`) still runs on every push and PR — it's just not enforced by branch protection.

The release job needs to push the `chore(release): monorepo release` bump commit + per-package tags directly to `main`. On a personal GitHub repo (not org-owned), there's no way to grant `github-actions[bot]` a bypass for either rule:

- Classic branch protection's `bypass_pull_request_allowances` is org-only — the API rejects it on personal repos with `"Only organization repositories can have users and team restrictions"`.
- Repo rulesets accept an `Integration` bypass actor, but require the integration to be installed at the owner organization — the GitHub Actions integration on a personal repo isn't, so the API rejects with `"Actor GitHub Actions integration must be part of the ruleset source or owner organization"`.
- The available bypass actor types on a personal repo (`RepositoryRole`, `DeployKey`) don't map to the `github-actions[bot]` identity.
- `enforce_admins: false` lets the human admin bypass via the API, but `github-actions[bot]` is not an admin, so it doesn't help the release job.

Required status checks fail similarly: when the bot pushes the bump commit, that commit has no checks yet (they haven't run for the new SHA), so protection rejects it with `"2 of 2 required status checks are expected"`.

The realistic options on a personal repo are: (a) drop both rules and rely on CI as informational, (b) wire the release job to a PAT/GitHub App token that bypasses protection, or (c) refactor the release flow to land bumps via auto-merging PRs. We've picked (a) — CI still surfaces failures in PRs and on commits, and force-pushes / branch deletion are still blocked. The trade-off: nothing prevents an authorized contributor from pushing code that fails CI directly to `main`. For this repo's scale that's acceptable; revisit if/when the project moves under an org (then `bypass_pull_request_allowances` and ruleset `Integration` actors become available, and you can re-enable both rules with the bot allowlisted).

## License

MIT

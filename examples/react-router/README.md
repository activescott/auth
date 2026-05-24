# React Router framework example

A minimal, runnable React Router v7 (framework mode, Node SSR) app demonstrating `@activescott/auth` with email magic-link login and OAuth social login (Google, GitHub). Scaffolded from the official `create-react-router` template, then wired up with the auth packages.

It's a workspace member of the [`@activescott/auth` monorepo](../../README.md), so it always builds against the local source.

The app (`examples/react-router/`) and the e2e suite (`examples/react-router/tests/`) are separate npm workspaces so they don't share a tsconfig, devDependencies (Playwright/jsonwebtoken don't bleed into the app), or root configs.

## Run the app

From the **repo root**:

```bash
npm install                    # installs all workspaces
npm run dev --workspace=@activescott/auth-example-react-router
# → http://localhost:5173
```

No env vars required for email magic-link login — `app/lib/auth.server.ts` ships with hardcoded `dev-only-*` secrets so the example just runs.

The example uses **`NodemailerTransport`'s built-in dev mode** — pass `true` to the constructor and it buffers the email via Nodemailer's stream transport (no real SMTP connection) and prints the magic link to the server console. Open `/login`, submit your email, then copy the link from the terminal running `npm run dev` and paste it into the browser to finish signing in. Drop the `true` and configure real `smtp` settings to send actual email.

### Enable OAuth (optional)

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

| Variable | Where to get it |
| --- | --- |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | [APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials) — add `http://localhost:5173/auth/google/callback` to Authorized redirect URIs |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | [Developer Settings → OAuth Apps](https://github.com/settings/developers) — set callback URL to `http://localhost:5173/auth/github/callback` |
| `OAUTH_STATE_SECRET` | Any random 32+ character string |

OAuth providers are registered only when their credentials are present; the login page shows their buttons automatically.

## Run the e2e tests

```bash
npm run install-browsers --workspace=@activescott/auth-example-react-router-e2e   # first time only
npm run e2e --workspace=@activescott/auth-example-react-router-e2e
```

Playwright's `webServer` block builds the app, starts it on `:3200` with stable test secrets, runs the tests, and tears it down.

## Testing pattern: `additionalSecrets` for e2e

The interesting bit in `app/lib/auth.server.ts`:

```ts
new EmailProvider({
  magicLinkSecret: MAGIC_LINK_SECRET,
  additionalSecrets: [E2E_MAGIC_LINK_SECRET],
  // ...
})
```

`EmailProvider.verify()` accepts tokens signed by either the primary secret or any `additionalSecrets`. In tests we mint our own token signed with the e2e secret (see `tests/helpers/auth.ts`) and visit the verify URL directly — no SMTP, no inbox polling, full coverage of the verify → cookie → `requireAuth` path.

The same pattern is used in production by [ramblefeed](https://ramblefeed.com) and [tinkerbellbot](https://tinkerbellbot.com). In a real app `MAGIC_LINK_SECRET` and `E2E_MAGIC_LINK_SECRET` come from env / your secret store, not hardcoded constants.

## Testing OAuth flows in e2e

Real OAuth providers require browser interaction and live credentials — they can't run unattended in CI. Instead, the suite uses a test-only route (`/auth/test-login`) that creates a real user + identity in the in-memory store and issues a genuine session cookie, simulating a completed OAuth callback without touching GitHub or Google. The `loginAsOAuth` helper in `tests/helpers/auth.ts` wraps this endpoint.

The `/auth/test-login` route is disabled in production (`NODE_ENV === "production"` returns 404).

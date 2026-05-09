# React Router framework example

A minimal, runnable React Router v7 (framework mode, Node SSR) app demonstrating `@activescott/auth` with email magic-link login. Scaffolded from the official `create-react-router` template, then wired up with the auth packages.

It's a workspace member of the [`@activescott/auth` monorepo](../../README.md), so it always builds against the local source.

The app (`examples/react-router/`) and the e2e suite (`examples/react-router/tests/`) are separate npm workspaces so they don't share a tsconfig, devDependencies (Playwright/jsonwebtoken don't bleed into the app), or root configs.

## Run the app

From the **repo root**:

```bash
npm install                    # installs all workspaces
npm run dev --workspace=@activescott/auth-example-react-router
# → http://localhost:5173
```

No env vars to set — `app/lib/auth.server.ts` ships with hardcoded `dev-only-*` secrets so the example just runs. Override any of `JWT_SECRET`, `JWT_MAGIC_LINK_SECRET`, or `E2E_MAGIC_LINK_SECRET` via env to point at real values.

The example uses **`NodemailerTransport`'s built-in dev mode** — pass `true` to the constructor and it buffers the email via Nodemailer's stream transport (no real SMTP connection) and prints the magic link to the server console. Open `/login`, submit your email, then copy the link from the terminal running `npm run dev` and paste it into the browser to finish signing in. Drop the `true` and configure real `smtp` settings to send actual email.

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

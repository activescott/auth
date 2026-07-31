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

No env vars to set — `app/lib/auth.server.ts` ships with a hardcoded `dev-only-*` session secret so the example just runs. Override `JWT_SECRET` via env to point at a real value.

The example uses **`NodemailerTransport`'s built-in dev mode** — pass `true` to the constructor and it buffers the email via Nodemailer's stream transport (no real SMTP connection) and prints the magic link and one-time code to the server console. Open `/login`, submit your email, then either type the code from the terminal into the code field, or paste the link into the browser and click **Confirm sign-in**. Drop the `true` and configure real `smtp` settings to send actual email.

## Run the e2e tests

```bash
npm run install-browsers --workspace=@activescott/auth-example-react-router-e2e   # first time only
npm run e2e --workspace=@activescott/auth-example-react-router-e2e
```

Playwright's `webServer` block builds the app, starts it on `:3200` with stable test secrets, runs the tests, and tears it down.

## Testing pattern: capture transport + readback route

Sign-in emails are backed by server-side challenges, so tests read the captured email instead of minting tokens:

1. `app/lib/capture-transport.server.ts` wraps the real transport and records the last magic link + code per recipient.
2. `app/routes/e2e.otp-code.tsx` returns them as JSON — only when `E2E_TEST_MODE=true` (set by `tests/playwright.config.ts`) and the `x-e2e-secret` header matches; 404 otherwise.
3. `tests/helpers/auth.ts` submits the login form, fetches the captured link/code, and drives the real confirm-page or code-entry flow.

No SMTP, no inbox polling, full coverage of the challenge → confirm/code → cookie → `requireAuth` path. In a real app the shared secret comes from env / your secret store, not a hardcoded constant.

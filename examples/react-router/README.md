# React Router framework example

A minimal, runnable React Router v7 (framework mode, Node SSR) app demonstrating `@activescott/auth` with **email magic-link + code login** and **SMS one-time-code login** side by side. Scaffolded from the official `create-react-router` template, then wired up with the auth packages.

It's a workspace member of the [`@activescott/auth` monorepo](../../README.md), so it always builds against the local source.

The app (`examples/react-router/`) and the e2e suite (`examples/react-router/tests/`) are separate npm workspaces so they don't share a tsconfig, devDependencies (Playwright doesn't bleed into the app), or root configs.

## Run the app

From the **repo root**:

```bash
npm install                    # installs all workspaces
npm run dev --workspace=@activescott/auth-example-react-router
# → http://localhost:5173
```

No env vars to set — `app/lib/auth.server.ts` ships with a hardcoded `dev-only-*` session secret, email runs in dev mode (printed to the server console instead of sent), and SMS uses the console transport. Open `/login`:

- **Email tab**: submit your email, then type the code from the terminal into the code field, or paste the printed magic link into the browser and click **Confirm sign-in**.
- **Phone tab** (`/login?via=sms`): enter any US-format number (the example fixes the `+1` prefix), then type the code from the terminal.

The login page keeps the two providers on separate tabs via the `?via=` query param — each provider redirects back to the page the form was posted from, so the active tab survives the round trip.

## Send real email

Set `SMTP_HOST` (see [`.env.example`](./.env.example)) to switch from dev mode to real sending. Ready-made configs:

```bash
cp .env.example.mailpit .env   # see emails in a local Mailpit web inbox
cp .env.example.smtp .env      # send real email via an SMTP provider
```

## Send real texts

Set `SMS_TRANSPORT=twilio` in `.env`. The interactive setup script verifies credentials, helps pick/provision a sender, writes `.env`, and prints the manual steps (carrier registration, RCS onboarding) it can't do for you — run from the repo root:

```bash
./infra/twilio/setup-twilio.mts
```

The script is plain TypeScript run directly by Node ([type stripping](https://nodejs.org/api/typescript.html#type-stripping), on by default since Node 22.18) — no install or build step. The repo's `.nvmrc` pins Node 22.

If a text never arrives, check Twilio's [per-message delivery log](https://console.twilio.com/us1/monitor/logs/sms) — carriers can filter messages the API accepted (e.g. error 30034, an unregistered A2P 10DLC number), and that log is the only place the failure shows. More troubleshooting in the [`auth-sms-twilio` README](../../packages/auth-sms-twilio#provisioning-step-by-step).

### WebOTP one-tap autofill

Set `webOtpDomain` in `app/lib/auth.server.ts` to your app's domain to append the WebOTP line (`@domain #code`) to each text — Android/Chrome then offer one-tap autofill. iOS autofills from the message text without it (the input already has `autoComplete="one-time-code"`).

## Run the e2e tests

```bash
npm run install-browsers --workspace=@activescott/auth-example-react-router-e2e   # first time only
npm run e2e --workspace=@activescott/auth-example-react-router-e2e
```

Playwright's `webServer` block builds the app, starts it on `:3200` with stable test secrets, runs the tests, and tears it down. E2e always forces `SMS_TRANSPORT=console`, so tests never text real messages.

## Testing pattern: capture transports + readback route

Sign-in emails and texts are backed by server-side challenges, so tests read the captured message instead of an inbox or a phone:

1. `app/lib/capture-email-transport.server.ts` and `app/lib/capture-sms-transport.server.ts` wrap the real transports and record the last message per recipient.
2. `app/routes/e2e.otp-code.tsx` returns them as JSON (`?email=` or `?phone=`) — only when `E2E_TEST_MODE=true` (set by `tests/playwright.config.ts`) and the `x-e2e-secret` header matches; 404 otherwise.
3. `tests/helpers/auth.ts` submits the login form, fetches the captured link/code, and drives the real confirm-page or code-entry flow.

No SMTP, no SMS gateway, full coverage of the challenge → confirm/code → cookie → `requireAuth` path. In a real app the shared secret comes from env / your secret store, not a hardcoded constant.

## One user, multiple sign-in methods

A user who signs in with email and with the same person's phone gets **two separate users** in this example — the `IdentityStore` data model supports multiple identities per user, but linking them (signing in with one method while adding another) is an app-level flow this example keeps out of scope.

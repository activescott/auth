# React Router SMS example

A minimal, runnable React Router v7 (framework mode, Node SSR) app demonstrating `@activescott/auth` with SMS one-time-code login: the user enters their mobile number, gets texted a 6-digit code, and types (or autofills) it to sign in.

It's a workspace member of the [`@activescott/auth` monorepo](../../README.md), so it always builds against the local source.

The app (`examples/react-router-sms/`) and the e2e suite (`examples/react-router-sms/tests/`) are separate npm workspaces so they don't share a tsconfig, devDependencies, or root configs.

## Run the app

From the **repo root**:

```bash
npm install                    # installs all workspaces
npm run dev --workspace=@activescott/auth-example-react-router-sms
# → http://localhost:5173
```

No env vars to set — the default `SMS_TRANSPORT=console` prints the code to the server console instead of texting it, and `app/lib/auth.server.ts` ships with a hardcoded `dev-only-*` session secret so the example just runs. Open `/login`, enter any E.164 number (e.g. `+14155550100`), and type the code from the terminal.

## Send real texts

The transport is selected by `SMS_TRANSPORT` (`console` | `twilio` | `aws`) in `.env`. Each vendor has an interactive setup script that verifies credentials, helps pick/provision a sender, writes `.env`, and prints the manual steps (carrier registration, RCS onboarding) it can't do for you:

```bash
cd examples/react-router-sms
./scripts/setup-twilio.mts   # Twilio: SMS, or RCS via a Messaging Service
./scripts/setup-aws.mts      # AWS End User Messaging: SMS, or RCS via a pool
```

The scripts are plain TypeScript run directly by Node ([type stripping](https://nodejs.org/api/typescript.html#type-stripping), on by default since Node 22.18) — no install or build step. The repo's `.nvmrc` pins Node 22.

See [`.env.example`](./.env.example) for the variables each transport uses, and the vendor package READMEs ([`auth-sms-twilio`](../../packages/auth-sms-twilio), [`auth-sms-aws`](../../packages/auth-sms-aws)) for provisioning details.

If a text never arrives, check Twilio's [per-message delivery log](https://console.twilio.com/us1/monitor/logs/sms) — carriers can filter messages the API accepted (e.g. error 30034, an unregistered A2P 10DLC number), and that log is the only place the failure shows. More troubleshooting in the [`auth-sms-twilio` README](../../packages/auth-sms-twilio#provisioning-step-by-step).

### WebOTP one-tap autofill

Set `webOtpDomain` in `app/lib/auth.server.ts` to your app's domain to append the WebOTP line (`@domain #code`) to each message — Android/Chrome then offer one-tap autofill. iOS autofills from the message text without it (the input already has `autoComplete="one-time-code"`).

## Run the e2e tests

```bash
npm run install-browsers --workspace=@activescott/auth-example-react-router-sms-e2e   # first time only
npm run e2e --workspace=@activescott/auth-example-react-router-sms-e2e
```

Playwright's `webServer` block builds the app, starts it on `:3201` with the console transport and stable test secrets, runs the tests, and tears it down. E2e always forces `SMS_TRANSPORT=console` so tests never text real messages.

## Testing pattern: capture transport + readback route

Sign-in codes are backed by server-side challenges, so tests read the captured message instead of a phone:

1. `app/lib/capture-transport.server.ts` wraps the real transport and records the last message + code per phone number.
2. `app/routes/e2e.otp-code.tsx` returns them as JSON — only when `E2E_TEST_MODE=true` (set by `tests/playwright.config.ts`) and the `x-e2e-secret` header matches; 404 otherwise.
3. `tests/helpers/auth.ts` submits the login form, fetches the captured code, and drives the real code-entry flow.

No SMS gateway, no phone, full coverage of the challenge → code → cookie → `requireAuth` path. In a real app the shared secret comes from env / your secret store, not a hardcoded constant.

## Adding email too

One user can have both a phone and an email identity — the `IdentityStore` data model already supports it. Add the `EmailProvider` to the same `providers: []` array and both `/auth/email/*` and `/auth/sms/*` routes work side by side; see the [email example](../react-router) for the email wiring.

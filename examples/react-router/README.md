# React Router framework example

A minimal, runnable React Router (framework mode, Node SSR) app demonstrating `@activescott/auth` with **email magic-link + code login**, **SMS one-time-code login**, and **passkeys** side by side. Scaffolded from the official `create-react-router` template, then wired up with the auth packages.

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

## Passkeys

Sign in (email or phone), click **Add a passkey** on the dashboard, log out, then use **Sign in with a passkey** on the login page. The email input also offers passkey autofill (conditional UI) in browsers that support it. Unlike the email/SMS forms, the passkey buttons are `fetch()` calls — WebAuthn ceremonies run in page JavaScript (see `app/lib/passkey.client.ts`), and the verify endpoints return JSON plus the session cookie rather than a redirect. The e2e specs exercise the real ceremonies against a Chrome DevTools Protocol virtual authenticator (`tests/passkeys.spec.ts`).

## Send real email

Set `SMTP_HOST` (see [`.env.example`](./.env.example)) to switch from dev mode to real sending. Ready-made configs:

```bash
cp .env.example.mailpit .env   # see emails in a local Mailpit web inbox
cp .env.example.smtp .env      # send real email via an SMTP provider
```

## Send real texts

Set the Twilio env vars in `.env` (see [`.env.example`](./.env.example)) — when they're all present the app texts real messages; when any are missing it falls back to the console transport and logs which vars are absent. There are two paths, and which one you configure is the only difference:

### Twilio Verify (quickest)

Create a Verify service (Console → Verify → Services), then set `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_VERIFY_SERVICE_SID`. Twilio generates, texts, and checks the code from senders it already registered, so there is no number to buy and no A2P 10DLC registration to wait out. Nothing else about the login page or the routes changes; see [`createSmsTransport`](./app/lib/auth.server.ts). It costs $0.05 per successful verification plus the channel fee, versus roughly a penny for a raw SMS.

### Raw SMS (cheaper per message)

Set `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and either `TWILIO_SMS_MESSAGING_SERVICE_SID` or `TWILIO_SMS_FROM`. You own the number and the code. For US traffic this also means registering an A2P 10DLC brand and campaign — a one-time fee, monthly fees, and days to weeks of waiting. Until it clears, carriers filter the messages while the API still reports success.

If a text never arrives, check Twilio's [per-message delivery log](https://console.twilio.com/us1/monitor/logs/sms) — that log is the only place the failure shows, and error 30034 there means the number isn't registered yet. More troubleshooting in the [`auth-sms-twilio` README](../../packages/auth-sms-twilio#provisioning-step-by-step).

### WebOTP one-tap autofill

Set `webOtpDomain` in `app/lib/auth.server.ts` to your app's domain to append the WebOTP line (`@domain #code`) to each text — Android/Chrome then offer one-tap autofill. iOS autofills from the message text without it (the input already has `autoComplete="one-time-code"`).

## Run the e2e tests

```bash
npm run install-browsers --workspace=@activescott/auth-example-react-router-e2e   # first time only
npm run e2e --workspace=@activescott/auth-example-react-router-e2e
```

Playwright's `webServer` block builds the app, starts it on `:3200` with stable test secrets, runs the tests, and tears it down. `E2E_TEST_MODE` forces the console SMS transport, so tests never text real messages even if Twilio env vars are present.

## Testing pattern: capture transports + readback route

Sign-in emails and texts are backed by server-side challenges, so tests read the captured message instead of an inbox or a phone:

1. `app/lib/capture-email-transport.server.ts` and `app/lib/capture-sms-transport.server.ts` wrap the real transports and record the last message per recipient.
2. `app/routes/e2e.otp-code.tsx` returns them as JSON (`?email=` or `?phone=`) — only when `E2E_TEST_MODE=true` (set by `tests/playwright.config.ts`) and the `x-e2e-secret` header matches; 404 otherwise.
3. `tests/helpers/auth.ts` submits the login form, fetches the captured link/code, and drives the real confirm-page or code-entry flow.

No SMTP, no SMS gateway, full coverage of the challenge → confirm/code → cookie → `requireAuth` path. In a real app the shared secret comes from env / your secret store, not a hardcoded constant.

## One user, multiple sign-in methods

A user who signs in with email and with the same person's phone gets **two separate users** in this example — the `IdentityStore` data model supports multiple identities per user, but linking them (signing in with one method while adding another) is an app-level flow this example keeps out of scope.

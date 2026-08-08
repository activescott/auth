# AGENTS.md

This file guide LLM coding agents (e.g. Claude Code, claude.ai/code) working with code in this repo.

## Commands

npm workspaces monorepo. From repo root:

```bash
npm install
npm run build        # tsc build in every workspace
npm run typecheck    # tsc --noEmit in every workspace
npm test             # vitest run in every workspace
npm run lint         # prettier --check .
```

Scope to one package with `-w`:

```bash
npm test -w packages/auth
npm test -w packages/auth -- src/__tests__/auth.test.ts   # single test file
npm test -w packages/auth -- -t "test name pattern"        # single test by name
```

E2e tests (Playwright, drives example app; needs packages built first):

```bash
npm run build --workspace=@activescott/auth --workspace=@activescott/auth-provider-email --workspace=@activescott/auth-provider-sms --workspace=@activescott/auth-sms-twilio --workspace=@activescott/auth-adapter-react-router
npm run install-browsers -w examples/react-router/tests   # once
npm run e2e -w examples/react-router/tests
```

## Architecture

Read [README.md](./README.md) first — documents package layout, app → adapter → core → provider layering (with diagram), `IdentityStore`/`UserStore` contracts, `Identity` data model, how to implement custom `AuthProvider`, and recommended e2e test pattern (`additionalSecrets` + minting magic-link JWTs directly).

Source map for what lives where (not in README):

- `packages/auth/src/auth.ts` — `Auth` class: dispatches standard `Request`s to providers, verifies sessions.
- `packages/auth/src/session/session-manager.ts` — `SessionManager`: issues/verifies JWT cookie sessions.
- `packages/auth/src/types.ts` — contracts: `AuthProvider`, `IdentityStore`, `UserStore`, `AuthUser`, `Identity`, `Session`.
- `packages/auth/src/errors.ts` — `AuthErrors`.
- `packages/auth/src/otp.ts` — one-time-code generation + shared `verifyOtpChallenge` redemption flow; `src/provider-util.ts` — helpers for provider authors (body parsing, challenge cookies, `authenticateWithIdentifier`).
- `packages/auth-provider-email/src/email-provider.ts` — email magic link + code provider; `src/transports/` holds `EmailTransport` implementations (Nodemailer SMTP).
- `packages/auth-provider-sms/src/sms-provider.ts` — SMS one-time-code provider (vendor-neutral; `SmsTransport` interface, `ConsoleTransport` for dev). Also accepts a `VerificationTransport` (`src/types.ts`) where the vendor owns the code — that path stores no `hashedCode` and redeems via `redeemVendorChallenge` instead of `verifyOtpChallenge`.
- `packages/auth-sms-twilio/src/twilio-messaging-transport.ts` — Twilio Messaging `SmsTransport` (raw fetch, zero deps); `src/twilio-verify-transport.ts` — Twilio Verify `VerificationTransport`, which sidesteps US A2P 10DLC registration. Two Twilio products, named after the product each one talks to.
- `packages/auth/src/abuse/` — abuse protection for the initiate endpoints, active by default: `abuse-guard.ts` (orchestration, `AbuseConfig`, block logging), `rate-limiter.ts` + `rate-limit-store.ts` (fixed-window rules), `client-ip.ts`, `bot-check.ts` (`BotCheckProvider`, signed form token); `src/stores/in-memory-rate-limit-store.ts` is the default store.
- `packages/auth-botcheck-turnstile/src/turnstile-bot-check.ts` — Cloudflare Turnstile `BotCheckProvider` (raw fetch, zero deps). Hosted bot checks each get their own package so consumers don't install vendors they don't use.
- `packages/auth/src/admin/admin-data.ts` — framework-agnostic admin dashboard data (`createAdminData`), exported at the `@activescott/auth/admin` subpath. Reads `UserStore.listUsers` / `IdentityStore.findByUserIds` (both optional) and `Auth.describeConfig()`. Never copies `Identity.metadata` into its output.
- `packages/auth-adapter-react-router/src/handlers.ts` — `createAuthHandlers` and friends.
- `packages/auth-adapter-react-router/src/admin/` — the admin dashboard's React pages and allowlist gate, at the `./admin` subpath so the main entry stays React-free. Still imports nothing from `react-router` (links go through an optional `linkComponent` prop), which is what keeps one build working on v7 and v8.
- `examples/react-router/` — runnable example app (email + SMS sign-in on tabbed login page); its Playwright e2e suite is nested workspace `examples/react-router/tests`.

Everything speaks Fetch-API `Request`/`Response` (no Node-only APIs in core path) so packages run on Node and edge runtimes — preserve when changing core or providers.

## Code style

Follow best practices for best-in-class, easy-to-understand JS/TS open-source projects. Here that means:

- Small, focused modules with named exports; kebab-case filenames. No barrel `index.ts` aggregating fewer than 3 modules.
- JSDoc on every export. In example app, write for reader copying code into own app: explain _why_ (which input attributes trigger OTP autofill, why tabs are links, why sessionStorage instead of redirect URL) — not restatement of code.
- Examples teaching material first: prefer little duplication over indirection making reader chase imports to understand flow. Generic reusable pieces (components, hooks) get extracted — with standalone docs.
- Resolve messy input at boundary where it enters (e.g. login form composes full E.164 number before submit) so everything downstream handles one canonical form.
- **Dependencies.** Splitting the library into packages exists so an app installs only what it uses, so the rule differs by package:
  - `packages/auth` (core) — effectively zero runtime deps (`jose` only, for session JWTs), and no Node-only APIs. Everything else has to earn its way in past a very high bar; prefer raw `fetch` and WebCrypto. Adding a dependency here taxes every consumer.
  - Provider, transport, bot-check, and framework-adapter packages — **may take runtime dependencies**, and several do (`auth-provider-email` → `nodemailer`; `auth-provider-passkey` → `@simplewebauthn/server`, `zod`; `auth-adapter-react-router` → `react` and `react-router` as peers). That is the point of the split: an app that signs in by SMS never installs a WebAuthn library. Still be deliberate — vendor SDKs that are a thin wrapper over one HTTP call are not worth it (`auth-sms-twilio` and `auth-botcheck-turnstile` use raw `fetch` and ship zero deps).
  - Peer vs. regular: something the host app already owns goes in `peerDependencies` (React, React Router); something only this package needs is a regular dependency. Mark a peer `optional` when only a subpath needs it — `react` is optional on the adapter because its main entry is React-free.

## Specs

Plans, specs, and post-implementation summaries live in `docs/specs/<name>/`
(`plan.md`, `spec.md`, `summary.md`) and **are committed** with the work they
describe.

This is a public repository, so scrub a spec before committing it:

- no local filesystem paths (`/Users/...`, `~/src/...`) — reference repo-relative paths or name the other repository
- no deployment details of any live site that runs this library (instance counts, hostnames, database/cache topology) — describe the constraint generically ("single instance, no shared cache")
- nothing about credentials being exposed, leaked, or awaiting rotation; handle that out of band
- no third parties' email addresses, keys, tokens, or internal URLs

Working notes are fine; treat the spec as something a stranger will read.

## Commits and releases

Commit format drives automated per-package releases — full rules, bump table, rationale in README's [Release process](./README.md#release-process). Parts agent must not get wrong:

- Conventional Commits with **required scope**, restricted to list in `commitlint.config.js` (one scope per package, plus `examples`). Enforced by husky commitlint hook. Adding package requires extending that scope-enum AND tag-prefix map in `scripts/release.ts`, else package silently never publishes.
- Scope determines which package version-bumped and published. Change spanning multiple packages needs separate commits per scope — preferred workflow one PR per package. Never squash-merge multi-package PR.
- No manual release command; merging to `main` releases automatically.

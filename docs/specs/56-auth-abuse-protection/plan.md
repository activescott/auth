# Abuse protection on the auth initiate endpoints (activescott/auth #56)

## Context

`POST /auth/{provider}/initiate` sends an email (or SMS) to any address a caller
submits, with no rate limit, no bot check, and a response that differs on
success vs failure. Ramblefeed (ramblefeed.com), which consumes this library,
is being abused through exactly this path right now: many junk accounts created
in the last days and a stream of bounce/return mail from the SMTP sender.

Two distinct defects are in play:

1. **No abuse protection in `@activescott/auth`** — anyone can drive unlimited
   outbound mail through the endpoint (mail-bombing a third party, burning the
   SMTP sender's reputation via bounces).
2. **Ramblefeed runs `@activescott/auth` ^0.1.1**, where a magic-link **GET**
   redeems the challenge and creates the user. Email security scanners and
   crawlers that prefetch links therefore create accounts by themselves. Auth
   v3 already fixed this (GET renders a confirm page; only the form POST
   redeems), so upgrading Ramblefeed removes the account-creation half of the
   problem independently of the new rate limiting.

Outcome wanted: layered protection in the library — per-IP limits, per-recipient
limits, honeypot + minimum form-fill-time, a hook for Turnstile/hCaptcha,
identical "check your email" response whether or not mail was sent, and clear
logging of every block — then roll it out to Ramblefeed.

Design decisions already made with the user:

- Protection is **on by default and never required**: an app that configures
  nothing still gets rate limiting via `InMemoryRateLimitStore`, plus the
  honeypot and form-token checks. `abuse: { enabled: false }` opts out.
- Core ships only checks that need no third party: **honeypot + min-fill-time**
  (zero deps, edge safe). Hosted bot checks are separate opt-in packages behind
  a `BotCheckProvider` interface — `@activescott/auth-botcheck-turnstile` now,
  hCaptcha and others later — so no consumer picks up a vendor they don't use.
- Client IP comes from proxy headers by default (`cf-connecting-ip`,
  `x-forwarded-for`, `x-real-ip`), overridable with a `getClientIp` config fn.
- Every block is logged clearly with reason, provider, IP, and requested
  identifier.

## Task 0

Save this plan to `docs/specs/56-auth-abuse-protection/plan.md`.

---

## Part 1 — `packages/auth` (core)

Commit scope: `feat(auth): ...` — one commit, this package only (scope rules in
`AGENTS.md` / `commitlint.config.js`).

### New: `src/abuse/rate-limit-store.ts`

```ts
export interface RateLimitStore {
  /** Atomically count one hit against key inside a fixed window; returns the
   * post-increment count and when the window resets. */
  hit(key: string, windowSeconds: number): Promise<RateLimitHit>
}
export interface RateLimitHit {
  count: number
  resetAt: Date
}
```

Mirrors the existing `ChallengeStore` contract style in `src/types.ts` (atomic
increment, documented as `INCR`/`UPDATE ... RETURNING` for real backends).

### New: `src/stores/in-memory-rate-limit-store.ts`

`InMemoryRateLimitStore implements RateLimitStore`. Model on
`src/stores/in-memory-challenge-store.ts`: `Map`, periodic `sweep()` on a
`setInterval`, `destroy()` to clear it. Same "single-instance only; back with
shared storage for multi-instance" JSDoc.

### New: `src/abuse/rate-limiter.ts`

```ts
export interface RateLimitRule {
  windowSeconds: number
  max: number
}
export interface AbuseConfig {
  store?: RateLimitStore // default: InMemoryRateLimitStore
  perIp?: RateLimitRule[] // default: burst 3/min, 10/hour
  perIdentifier?: RateLimitRule[] // default: 3/hour, 10/day
  honeypotField?: string // default "nickname"; empty string disables
  minFormFillSeconds?: number // default 2
  /** Extra checks appended to the built-in honeypot + form-token checks —
   * e.g. new TurnstileBotCheck({ secretKey }). Default: []. */
  botChecks?: BotCheckProvider[]
  getClientIp?: (request: Request) => string | null
  onBlocked?: (event: AbuseEvent) => void // in addition to the default log
  respondWith?: "generic" | "rateLimited" // default "generic"
  enabled?: boolean // default true
}
export interface AbuseEvent {
  reason:
    | "ip_rate_limited"
    | "identifier_rate_limited"
    | "honeypot"
    | "too_fast"
    | "bot_check_failed"
  providerId: string
  ip: string | null
  identifier?: string
  rule?: RateLimitRule
  at: Date
}
```

`RateLimiter` evaluates every rule in a list against `store.hit()` and returns
`{ allowed: false, reason, rule, retryAfterSeconds }` on the first breach.
Fixed-window counters — two rules per scope give the issue's "small burst
allowance, then a hard hourly limit" without a token bucket.

### New: `src/abuse/client-ip.ts`

`getClientIp(request, config)`: `cf-connecting-ip` → `x-forwarded-for` (rightmost
hop, `trustedProxyHops` default 1) → `x-real-ip` → `null`. `config.getClientIp`
overrides entirely. Document that XFF is spoofable when the app is not behind a
proxy that rewrites it, and that per-IP limits are skipped when the IP is
`null` (per-identifier still applies).

### New: `src/abuse/bot-check.ts`

The extension point every hosted bot check (Turnstile, hCaptcha, future ones)
implements:

```ts
export interface BotCheckProvider {
  readonly id: string
  verify(input: BotCheckInput): Promise<BotCheckResult>
}
export interface BotCheckInput {
  request: Request
  body: Record<string, unknown>
  ip: string | null
  providerId: string
}
export type BotCheckResult = { ok: true } | { ok: false; reason: string }
```

Two implementations ship in core and run by default (both zero-dep, no third
party):

- `HoneypotBotCheck` — blocked when the configured field is present and
  non-empty.
- `FormTokenBotCheck` — minimum fill time. `createFormToken(secret)` /
  `verifyFormToken(secret, value, { minAgeSeconds, maxAgeSeconds })`,
  HMAC-SHA-256 over an issue timestamp via WebCrypto (edge safe). Signed so the
  timestamp cannot be forged; secret defaults to `config.session.secret`. The
  app mints the token when rendering the login form and posts it in a hidden
  field (`authFormToken`). Absent token → allowed (apps that have not updated
  their form keep working); present-but-too-fast or expired → blocked.

`abuse.botChecks` entries run after those, in order, first failure wins. A
provider that throws is treated as `{ ok: false, reason: "<id>_error" }` and
logged with the error.

### New: `src/abuse/abuse-guard.ts`

`AbuseGuard` owns limiter + bot checks + logging:

- `checkInitiate(request, providerId, body)` — honeypot, form-token age,
  `botCheck`, then per-IP rules.
- `checkIdentifier(request, providerId, identifier)` — per-recipient rules,
  keyed `identifier:{providerId}:{identifier}` (lowercased), independent of IP.
- `logBlocked(event)` — always emits a single-line `console.warn` (matching the
  `// eslint-disable-next-line no-console` pattern already used in
  `src/auth.ts`) containing reason, provider, ip, identifier, rule, then calls
  `config.onBlocked` if supplied. **Every** rejection is logged — this is a
  requirement, not an option.

### Changed: `src/types.ts`

- `AuthConfig.abuse?: AbuseConfig` (optional; absent = defaults, still active).
- `AuthContext.abuse?: { checkIdentifier(providerId, identifier): Promise<AbuseDecision> }`
  so providers can throttle per recipient after they parse the body.
- `AuthProvider.initiateSentMessage?: string` — the message used for both the
  real "sent" response and the silent-block response so the two are
  byte-identical.

### Changed: `src/auth.ts`

In `handleRequest`, for `action === "initiate" | "send"` only:

1. `const decision = await this.abuseGuard.checkInitiate(request.clone(), providerId, body)`
   — `request.clone()` before body parse so the provider can still read the
   body (Fetch semantics; works on Node 18+ and edge).
2. Blocked → build the **same** response the provider would produce on success,
   minus the challenge cookie: 302 to `buildReturnUrl(request, { sent: "1" })`
   for `isBrowserFormPost(request)`, else
   `{ success: true, message: provider.initiateSentMessage ?? DEFAULT_SENT_MESSAGE }`
   (200). `respondWith: "rateLimited"` instead returns the existing
   `RATE_LIMITED` 429 for API-only deployments.
3. `createContext()` gains the `abuse` member wired to the guard.
4. `destroy()` also destroys an owned default `InMemoryRateLimitStore`.

### Changed: `src/provider-util.ts`

Add `initiateAccepted(request, message, setCookies?)` — the shared
browser-redirect-vs-JSON success builder used by core's silent block and by both
providers, so the three paths cannot drift.

### Changed: `src/index.ts`

Export `RateLimitStore`, `RateLimitHit`, `RateLimitRule`, `AbuseConfig`,
`AbuseEvent`, `AbuseDecision`, `BotCheckProvider`, `BotCheckInput`,
`BotCheckResult`, `HoneypotBotCheck`, `FormTokenBotCheck`,
`InMemoryRateLimitStore`, `createFormToken`, `verifyFormToken`,
`initiateAccepted`.

### Tests (`src/__tests__/`, vitest, alongside `auth.test.ts`)

- `in-memory-rate-limit-store.test.ts` — counting, window rollover, sweep.
- `rate-limiter.test.ts` — burst rule trips before hourly rule; independent keys.
- `client-ip.test.ts` — header precedence, hop selection, null.
- `bot-check.test.ts` — honeypot, token too-fast/expired/tampered/absent, a
  stub `BotCheckProvider` that fails/throws is honored and logged.
- `auth.test.ts` additions — blocked initiate returns byte-identical response to
  a successful initiate minus `Set-Cookie`; block is logged; `respondWith:
"rateLimited"` returns 429.

---

## Part 2 — providers

Separate commits, one per scope (`fix(auth-provider-email)`,
`fix(auth-provider-sms)`).

- `packages/auth-provider-email/src/email-provider.ts` — after `email` is
  validated (line ~86) and **before** `challengeStore.create`, call
  `context.abuse?.checkIdentifier("email", email)`. Blocked → return
  `initiateAccepted(request, this.initiateSentMessage)` with no challenge and no
  cookie. Add `public readonly initiateSentMessage = "Magic link sent. Please check your email."`
  and use it for the success path too.
- `packages/auth-provider-sms/src/sms-provider.ts` — same, after
  `normalizePhoneNumber` (line ~78), message `"Code sent. Check your phone."`.
- Tests in each package's `src/__tests__/`: throttled initiate sends no mail/SMS
  (transport spy not called) yet returns the success-shaped response.

---

## Part 3 — new package `@activescott/auth-botcheck-turnstile`

Modeled on `packages/auth-sms-twilio` (vendor adapter, raw `fetch`, zero runtime
deps, `peerDependencies` on the package whose interface it implements). Layout:
`package.json`, `tsconfig.json`, `README.md`, `LICENSE`, `src/turnstile-bot-check.ts`,
`src/index.ts`, `src/__tests__/turnstile-bot-check.test.ts`.

```ts
export interface TurnstileConfig {
  secretKey: string
  /** Form field carrying the widget token (default "cf-turnstile-response") */
  fieldName?: string
  /** Override for tests / self-hosted proxies */
  verifyUrl?: string
  timeoutMs?: number // default 5000
  /** Allow the request through when Cloudflare is unreachable or times out
   * (default true — rate limits and honeypot still apply, and a hard outage
   * at Cloudflare should not lock every user out of sign-in). Set false to
   * fail closed. */
  failOpen?: boolean
}
export class TurnstileBotCheck implements BotCheckProvider {
  public readonly id = "turnstile"
  public verify(input: BotCheckInput): Promise<BotCheckResult>
}
```

`verify` POSTs `secret`, `response`, and `remoteip` (from `input.ip`) to
`https://challenges.cloudflare.com/turnstile/v0/siteverify` with an
`AbortSignal.timeout`, maps `success: false` to
`{ ok: false, reason: "turnstile:<error-codes>" }`. Missing token → blocked.

Tests use a stubbed `verifyUrl`/`fetch`: success, failure with error codes,
missing token, timeout under both `failOpen` settings.

README documents the two halves: server (`botChecks: [new TurnstileBotCheck({ secretKey })]`)
and client (script tag + `<div class="cf-turnstile" data-sitekey="...">` in the
login form).

**Repo plumbing that is easy to miss** (`AGENTS.md` calls it out — get it wrong
and the package silently never publishes):

- add `auth-botcheck-turnstile` to `scope-enum` in `commitlint.config.js`
- add the `auth-botcheck-turnstile` entry to `tagPrefixToPackage` in
  `scripts/release.ts` (line ~61)
- first commit for it is `feat(auth-botcheck-turnstile): ...`

An hCaptcha package later is the same shape — implement `BotCheckProvider`, add
the two plumbing entries. Nothing in core changes to add one.

---

## Part 4 — example app + docs

Commit scopes: `docs(examples)`, `docs(auth)`.

- `examples/react-router/app/routes/login.tsx` — add to the `EmailLogin` form
  (and the SMS form): a honeypot input (`name="nickname"`, `tabIndex={-1}`,
  `autoComplete="off"`, visually hidden, **not** `display:none` only) and a
  hidden `authFormToken` from a `createFormToken` call in the route loader.
  Comment the _why_ per the repo's example-code style.
- `examples/react-router/app/lib/auth.server.ts` — wire
  `new TurnstileBotCheck({ secretKey: process.env.TURNSTILE_SECRET_KEY })` into
  `abuse.botChecks` **only when the env var is set**, and render the widget in
  `login.tsx` only when the site key is set, so the example still runs with no
  Cloudflare account. `@activescott/auth-botcheck-turnstile` is a dependency of
  the example only.
- `packages/auth/README.md` — new "Abuse protection" section: what is on by
  default, the defaults table, how to supply a Redis/Postgres `RateLimitStore`
  for multi-instance, the honeypot/form-token form contract, the
  `BotCheckProvider` interface plus the list of shipped implementations, why
  blocked responses look like successes, and what the block log line looks
  like.

---

## Part 5 — Ramblefeed rollout (separate repository)

Separate repo, separate PR(s). Ramblefeed runs a single application instance
with no shared cache, so `InMemoryRateLimitStore` is correct there today.

1. **Upgrade auth deps** in `packages/web-app/package.json`:
   `@activescott/auth` ^0.1.1 → ^3, `@activescott/auth-provider-email` ^0.1.2 →
   ^1, `@activescott/auth-adapter-react-router` ^0.1.1 → ^1. This alone stops
   scanner-clicks from creating accounts (GET → confirm page).
2. **Rewrite `app/lib/auth.server.ts` for the v3 API**:
   - `EmailProvider` config changed: drop `magicLinkSecret`,
     `additionalSecrets`, `magicLinkExpiry`; use `expiry: "15m"`, `smtp`,
     `from`, `template`, optional `otp`.
   - `Auth` config now requires `challengeStore` — start with
     `InMemoryChallengeStore` (single instance); a database-backed `ChallengeStore`
     is the follow-up if the deployment ever scales out or restarts often
     enough to annoy users mid-sign-in.
   - `additionalSecrets` for E2E now belongs under `session`.
   - The adapter no longer exports `sendMagicLink` (only `createAuthHandlers`
     and friends) — remove the `sendMagicLink` wrapper.
   - `identityStore.create/update` must return `metadata: {}` not `undefined`
     (v3 `Identity.metadata` is required).
3. **Rewrite `app/routes/start.tsx`**: the form posts directly to
   `/auth/email/initiate` (like `examples/react-router/app/routes/login.tsx`),
   reads `?sent=1` / `?error=`, and includes the honeypot + `authFormToken`
   fields. Drop the route `action` that called `sendMagicLink`.
4. **Add the code-entry path** (optional but free in v3): a form posting the
   6-digit code to `/auth/email/verify`.
5. **Abuse config**: rely on defaults; wire `onBlocked` into
   `app/lib/logger.ts` so blocks land in the app's normal logs, and confirm the
   ingress passes `X-Forwarded-For` (nginx ingress does). Turnstile is a
   follow-up decision once the default layers' effect on the bounce rate is
   measurable — adding it later is a dependency plus two lines of config.
6. **Cleanup of existing junk accounts** — inventory first (count users with no
   notes/bookmarks and `verifiedAt IS NULL`), report the numbers, and get
   explicit approval before deleting anything.

---

## Verification

Library:

```bash
npm run build && npm run typecheck && npm test && npm run lint
npm test -w packages/auth -- src/__tests__/rate-limiter.test.ts
```

End to end against the example app:

```bash
npm run build --workspace=@activescott/auth --workspace=@activescott/auth-provider-email \
  --workspace=@activescott/auth-provider-sms --workspace=@activescott/auth-sms-twilio \
  --workspace=@activescott/auth-adapter-react-router
npm run e2e -w examples/react-router/tests
```

Manual checks (example app on `npm run dev`, magic link printed to console):

1. Submit the login form 5x quickly with different addresses → first N send,
   the rest return the identical `?sent=1` redirect, **no** mail in the console,
   and one `console.warn` block line per rejection naming ip + address.
2. Submit the same address repeatedly → per-identifier rule trips independently
   of IP.
3. Fill the honeypot field via devtools → blocked + logged, response
   indistinguishable from success.
4. Submit within `minFormFillSeconds` → blocked + logged.
5. Diff a blocked response against a successful one: identical status, headers
   (except `Set-Cookie`), and body.

Ramblefeed: after upgrade, run its test suite, sign in end to end on a local
build (magic link → confirm page → session), confirm a `GET` of the magic link
alone creates **no** user row, then deploy and watch the logs for block lines
and the SMTP bounce rate.

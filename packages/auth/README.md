# @activescott/auth

[![npm version](https://img.shields.io/npm/v/@activescott/auth.svg)](https://www.npmjs.com/package/@activescott/auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Framework-agnostic direct authentication, deliberately small: single-use magic links and one-time codes via email and SMS, and passkeys (WebAuthn). No third-party identity providers. Runs on Node and edge runtimes (e.g. Cloudflare Workers).

This package is the core: the `Auth` class, JWT-cookie session management, and the provider/store interfaces. It does not handle any specific authentication method by itself — pair it with one or more provider packages and (optionally) a framework adapter:

- [`@activescott/auth-provider-email`](https://www.npmjs.com/package/@activescott/auth-provider-email) — email magic links + one-time codes
- [`@activescott/auth-provider-sms`](https://www.npmjs.com/package/@activescott/auth-provider-sms) — SMS one-time codes ([`@activescott/auth-sms-twilio`](https://www.npmjs.com/package/@activescott/auth-sms-twilio) provides both Twilio transports: Messaging and Verify)
- [`@activescott/auth-provider-passkey`](https://www.npmjs.com/package/@activescott/auth-provider-passkey) — passkeys (WebAuthn)
- [`@activescott/auth-adapter-react-router`](https://www.npmjs.com/package/@activescott/auth-adapter-react-router) — React Router v8 adapter

Used in production by [ramblefeed.com](https://ramblefeed.com) and [tinkerbellbot.com](https://tinkerbellbot.com).

## Why direct, passwordless authentication?

Everyone has an email address or a phone number. Nobody wants another password. And many users hesitate at "Sign in with Google/Apple/Microsoft" because it shares their sign-in activity with a third party. This library focuses on the ways a person can authenticate **directly** with your app:

- **Lowest friction for your users.** No password to create, forget, or reset, and no account with a third party required. Modern platforms AutoFill the codes we send, so signing in is: type your email, type the code your OS offers you.
- **Easiest for you.** No OAuth app registrations, no identity-provider dashboards, no extra services. An SMTP server and your database are the only dependencies.
- **Private by design.** No third-party identity provider in the loop — big tech doesn't learn when (or that) your users sign in to your app.
- **Deliberately small.** This is not a works-with-every-OAuth-provider auth library — that niche is well served by projects like [BetterAuth](https://www.better-auth.com/). Constraining the scope is what keeps this one easy to drop into a new app.

Passkeys push the same idea further: phishing-resistant, no shared secret, and still no third party.

## Features

- ✅ **Email magic links** — single-use, server-backed sign-in links with a confirm step that email security scanners can't consume (see the [FAQ](https://github.com/activescott/auth#faq)). In production.
- ✅ **Email one-time codes** — every sign-in email also includes a numeric code with iOS/macOS AutoFill support, so users can type the code instead of switching to the inbox tab.
- ✅ **Bring your own database** — three small store interfaces (`IdentityStore`, `UserStore`, `ChallengeStore`); implement them with Prisma, Drizzle, raw SQL, Redis, whatever you use.
- ✅ **Edge-ready, [WinterTC-compatible](https://wintertc.org/faq) core** — standard Fetch `Request`/`Response`, WebCrypto, and [`jose`](https://github.com/panva/jose) for session JWTs; no Node-only APIs, so it runs on Cloudflare Workers, Deno, Bun, and any WinterTC-aligned runtime.
- ✅ **React Router v8 adapter** — `createAuthHandlers`, `requireAuth`, `optionalAuth`, `getSession`, `logout`.
- ✅ **SMS one-time codes** — vendor-neutral provider with a Twilio Messaging transport (RCS-ready) and [WebOTP](https://developer.mozilla.org/docs/Web/API/WebOTP_API) autofill support.
- ✅ **Hosted verification (no US A2P 10DLC)** — the same SMS provider accepts a `VerificationTransport` where the vendor generates, sends, and checks the code. `TwilioVerifyTransport` ships in the Twilio package: no number to buy, no brand or campaign registration — at the cost of ~4–6x per sign-in.
- ✅ **Abuse protection, on by default** — per-IP and per-recipient rate limits, a minimum-form-fill-time check, blocked attempts logged, and a blocked caller gets the same response a successful send would produce. Optional packages add hosted bot checks ([Turnstile](https://www.npmjs.com/package/@activescott/auth-botcheck-turnstile)).
- ✅ **Passkeys (WebAuthn)** — add a passkey while signed in, then sign in usernameless with Touch ID, Face ID, Windows Hello, 1Password, iCloud Keychain, or a security key; conditional UI (passkey autofill) supported. Verification via [`@simplewebauthn/server`](https://simplewebauthn.dev/); zero-dependency browser client included.

The provider interface (`AuthProvider`) is the extension point. Implementing a new provider does not require changes to this core package.

## Documentation & example

Full docs — quick start, architecture diagram, custom-provider guide, e2e-testing pattern, FAQ — and a runnable React Router framework-mode example with Playwright tests live in the monorepo:

→ **https://github.com/activescott/auth**

The rest of this README covers what this core package itself exports and expects.

## Install

```bash
npm install @activescott/auth
```

## What's in the box

| Export                                                            | Purpose                                                                                                               |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `Auth`                                                            | Orchestrator. Routes auth requests to providers, manages session cookies.                                             |
| `SessionManager`                                                  | Standalone JWT session signer/verifier (rarely needed directly).                                                      |
| `AuthProvider`                                                    | Interface every provider implements (`initiate`, `verify`, `canHandle`, optional `handleAction` for extra endpoints). |
| `IdentityStore`, `UserStore`                                      | Interfaces you implement to plug in your database.                                                                    |
| `ChallengeStore`, `InMemoryChallengeStore`                        | Storage for short-lived, single-use challenges (see below).                                                           |
| `AbuseConfig`, `RateLimitStore`, `InMemoryRateLimitStore`         | Abuse protection for the initiate endpoints — on by default (see below).                                              |
| `InitiateGate`                                                    | Your own policy on who may start a sign-in or link (see below).                                                       |
| `createWaitlist`, `waitlistNotificationEmail`                     | Waitlist with admin approval, built on the gate's `onVerified` (see below).                                           |
| `BotCheckProvider`, `createFormToken`, `FORM_TOKEN_FIELD`         | Bot-check interface and the login form's anti-bot fields.                                                             |
| `generateOtpCode`, `hashOtpCode`, `verifyOtpCode`                 | One-time-code utilities used by OTP-capable providers.                                                                |
| `AuthUser`, `Identity`, `Session`, `AuthResult`, `AuthInitResult` | Core data types.                                                                                                      |
| `AuthErrors`, `getAuthErrorMessage`, `AUTH_ERROR_CODES`           | Structured error helpers.                                                                                             |

Plus the `@activescott/auth/admin` subpath: admin dashboard data and the admin allowlist check (see [Admin subpath](#admin-subpath)).

## Data model

You bring three adapters — `IdentityStore`, `UserStore`, and `ChallengeStore` — that read/write your database. The library handles challenges, cookies, provider routing, and session verification.

An `Identity` is a `(provider, identifier)` pair (e.g. `("email", "alice@example.com")`) linked to one of your `User` records. One user can have multiple identities — email, phone, and passkeys all use the same table.

`Identity.metadata` is **provider-owned state**, opaque to your application: persist it unmodified (a JSON/JSONB column) and return it exactly as stored. Providers with per-identity state keep it there — the passkey provider stores each credential's public key and signature counter — and stateless providers store `{}`. It may contain sensitive material, so protect it like credential data (encryption at rest is a reasonable default). `IdentityStore.update(id, {metadata, verifiedAt})` replaces stored metadata wholesale; providers rely on it, so it is a required method.

## Minimal shape

```ts
import { Auth, InMemoryChallengeStore } from "@activescott/auth"
import { EmailProvider } from "@activescott/auth-provider-email"

const auth = new Auth({
  session: {
    secret: process.env.JWT_SECRET!,
    maxAge: "30d",
    cookieName: "session",
    cookie: { secure: true, sameSite: "lax", path: "/" },
  },
  identityStore, // your impl
  userStore, // your impl
  challengeStore: new InMemoryChallengeStore(), // DB-backed in production
  providers: [new EmailProvider({ ... })],
})
```

Then call `auth.handleRequest(request)` from your framework's routing layer (or use a framework adapter), and `auth.verifySession(request)` to check the session cookie on protected routes.

## Session cache

`verifySession` keeps each verified session in memory for two minutes, so a page whose loaders each ask who is signed in costs one pair of store reads instead of one per loader. What you pay for it is staleness: for up to two minutes after you block or delete someone, their requests still verify.

`session.cacheTtlMs` is that window in milliseconds, and `0` turns the cache off so every request reads your stores:

```ts
session: {
  secret: process.env.JWT_SECRET!,
  maxAge: "30d",
  cookieName: "session",
  cookie: { secure: true, sameSite: "lax", path: "/" },
  cacheTtlMs: 0, // block a user, and their next request is signed out
}
```

With the cache on, it holds at most 10,000 sessions and evicts the oldest past that, so a burst of sign-ins between sweeps cannot grow it without limit. Nothing is shared between instances: an entry is only ever a repeat of what that process's stores just said.

## ChallengeStore

Every sign-in attempt is backed by a server-side challenge: magic links and one-time codes store the hashed secret, an attempt counter, and an expiry; passkey ceremonies record the WebAuthn challenge so it is redeemable exactly once. That state lives in the `challengeStore`, which is why it is a required part of the `Auth` config.

`InMemoryChallengeStore` is right for a single server process (and dev/examples). It sweeps expired challenges every 5 minutes and holds at most 10,000; past that, a new challenge drops expired ones first (sweeping at most once per sweep interval, so a flood does not pay for a full sweep on every request), then the oldest live ones, so a flood of requests cannot grow memory without limit. Tune both with `new InMemoryChallengeStore({ sweepIntervalMs, maxChallenges })`.

The cap trades a crash for a denial of service. Past it, a flood fails other users' in-flight sign-ins until it stops: every provider shares the one store, so a loop on the passkey options endpoint also evicts pending email links and codes, SMS codes, and OIDC `start` state. The store logs a `console.warn` the first time it evicts a live challenge in each sweep interval. What keeps a flood from reaching the cap is the per-IP limit on those endpoints, and that only works when the client IP is real: behind a proxy that rewrites the headers, or with `abuse.clientIp.getClientIp` (see [Abuse protection](#abuse-protection)). Challenges are lost on restart and not shared across instances — for multi-instance deployments implement the four-method `ChallengeStore` interface against shared storage. A SQL implementation is roughly:

```sql
CREATE TABLE challenges (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  identifier TEXT NOT NULL,
  hashed_code TEXT,
  data JSONB,
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
```

with `incrementAttempts` as `UPDATE challenges SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts` (the increment must be atomic — it enforces the guess limit), and a periodic `DELETE ... WHERE expires_at < now()`.

## Abuse protection

The `initiate` endpoints send mail and texts to whatever address a caller submits, which makes them an attractive way to mail-bomb a third party or burn your sending reputation on bounces. Protection is **on by default** — you do not have to configure or implement anything:

| Layer                   | Default                                                    |
| ----------------------- | ---------------------------------------------------------- |
| Per client IP           | 3 per minute, then 10 per hour                             |
| Per recipient           | 3 per hour, then 10 per day                                |
| Per IP, passkey options | 20 per minute, then 200 per hour (see below)               |
| Minimum form-fill time  | 2 seconds (only enforced if the form posts a token, below) |
| Counter storage         | `InMemoryRateLimitStore`                                   |
| Blocked response        | identical to a successful send                             |

Blocked attempts are always logged (`console.warn`) with the reason, provider, IP, requested identifier, and rule, so an abuse burst is visible:

```
[auth] blocked initiate: reason=identifier_rate_limited provider=email ip=203.0.113.7 identifier=victim@example.com rule=3/3600s retryAfter=2841s
```

### A blocked caller sees a success

By design a throttled or bot-flagged request gets exactly the response a real send would produce — the same 302 back to `?sent=1`, or the same `{success: true, message}` — minus the challenge cookie. Nothing is sent and nothing is stored. This is what keeps a bot from mapping which addresses or IPs are throttled. If you would rather return `429 RATE_LIMITED` (reasonable for an API-only deployment), set `abuse.respondWith: "rateLimited"`.

One block is answered differently in both modes: a bot check reporting `incomplete` (a hosted widget that had not issued its token yet when the form was submitted) gets `BOT_CHECK_INCOMPLETE`, as a 302 back with `?error=BOT_CHECK_INCOMPLETE` or a 400. That verdict comes from the request alone, never from the identifier, so it tells the caller nothing they did not send, and it lets a real user on a slow connection know to try again. It is still logged and passed to `onBlocked` as `bot_check_failed`.

### Tuning

```ts
const auth = new Auth({
  // ...
  abuse: {
    perIp: [
      { windowSeconds: 60, max: 3 },
      { windowSeconds: 3600, max: 10 },
    ],
    perIdentifier: [{ windowSeconds: 3600, max: 3 }],
    store: myRedisRateLimitStore, // multi-instance: share the counters
    onBlocked: (event) => logger.warn(event, "auth abuse blocked"),
  },
})
```

`abuse: { enabled: false }` turns everything off.

### Rate-limited action routes

Some provider routes send nothing but still write server-side state on every call, with no session required: the passkey `authenticate-options` endpoint stores a WebAuthn challenge each time. A provider marks such a route `rateLimitByIp: true` in `getRoutes()`, and `Auth` then applies `abuse.perIpAction` (default 20 per minute, then 200 per hour) per client IP, provider, and route before calling `handleAction`. Bot checks do not run there, since these are fetch calls with no form token. The client IP comes from the same `abuse.clientIp` setting, blocks go to the same log line and `onBlocked` (with `action` set on the event), and `enabled: false` turns the limit off too. A refused call always gets `429 RATE_LIMITED` with `Retry-After`, whatever `respondWith` says, because a JSON options endpoint has no "sent" answer to imitate.

```ts
abuse: {
  perIpAction: [{ windowSeconds: 60, max: 30 }],
}
```

`InMemoryRateLimitStore` counts per process, so a multi-instance deployment effectively multiplies every limit by the instance count. It holds at most 100,000 keys per keyspace (the key's prefix: `ip`, `ip-action`, `identifier`), and a client IP uses two under the default per-IP rules, kept for up to an hour. Past that, starting a window for a new key evicts the oldest one in the same keyspace, so a caller rotating spoofed IPs cannot grow memory without limit, and cannot push out per-recipient windows either. An evicted key counts from zero again, so such a flood can reset other IPs' counters early, but not a recipient's. Recipient keys are caller input, though: initiating sign-ins for about 50,000 distinct addresses or numbers (each holds an hourly and a daily window under the default per-recipient rules) evicts the oldest recipient windows, letting a recipient who hit their limit receive messages again. Every such request sends a real message and counts against the caller's per-IP initiate limit when the IP is known, so the flood is costly and buys only a few more messages to that recipient. Tune it with `new InMemoryRateLimitStore({ sweepIntervalMs, maxKeys })` passed as `abuse.store`. Implement the one-method `RateLimitStore` interface against Redis (`INCR` + `EXPIRE`) or your database to share counters.

Client IPs come from `x-forwarded-for` (rightmost hop; set `abuse.clientIp.trustedProxyHops` if more than one proxy appends), then `x-real-ip`. `cf-connecting-ip` is read first only with `abuse.clientIp.trustCloudflare: true`: any proxy other than Cloudflare (nginx, an ALB, Caddy) forwards that header exactly as the client sent it, so trusting it there lets a caller choose a new IP on every request. Set it only when all traffic reaches the app through Cloudflare. Cloudflare also appends the client to `x-forwarded-for`, so leaving it off is safe there as long as `trustedProxyHops` counts every proxy that appends. Behind Cloudflare _and_ a second proxy that appends (an ALB, nginx), leaving both at their defaults picks the Cloudflare edge address for every user: initiate limits then block real users silently (no email or code arrives), and every user through one edge shares one `rateLimitByIp` bucket, so the 21st passkey options call a minute gets 429. Set `trustCloudflare: true` or raise `trustedProxyHops` there. Before version 6, `cf-connecting-ip` was always read first.

Per-IP limits count each client under one key however its address is spelled. A `:port` suffix on a header value is dropped (IIS/ARR, Azure App Service and Front Door append one to `x-forwarded-for`), case is ignored, and an IPv6 address counts under its /64, so a host handed a whole /64 cannot rotate through it to get fresh buckets. The flip side is that every client sharing one /64 shares one limit. An IPv4-mapped address (`::ffff:203.0.113.7`) counts as its IPv4 address. This applies to a `getClientIp` result too. The block log shows the address itself, not the /64.

These headers are spoofable unless a proxy in front of your app rewrites them. Supply `abuse.clientIp.getClientIp` when your runtime exposes the peer address; it replaces header inspection entirely, so none of the above applies. When no IP can be determined, `initiate` routes skip their per-IP limits (per-recipient limits still apply), while `rateLimitByIp` action routes count the call against one shared `unknown` bucket, so leaving the headers off does not bypass the limit. A deployment that sees no IP headers at all therefore shares that one bucket across all its users, and any one caller can fill it on purpose: 20 header-less requests a minute (the default `perIpAction`) answer every other header-less user with 429. Give such a deployment a `getClientIp`; the block log reads `ip=unknown (set abuse.clientIp)` when this is happening.

With no proxy in front and no `getClientIp`, a caller can still send a fresh `x-forwarded-for` on every request, and no per-IP limit stops a deliberate attacker. The challenge store's cap is then the only control, and it fails real users' sign-ins once reached (see [ChallengeStore](#challengestore)).

### Form token

The minimum-form-fill-time check needs one hidden field in your login form:

```tsx
import { createFormToken, FORM_TOKEN_FIELD } from "@activescott/auth"

// in the route/loader that renders the form:
const formToken = await createFormToken(process.env.JWT_SECRET!)
```

```html
<input type="hidden" name="authFormToken" value="{formToken}" />
```

The token is a signed render timestamp; the server rejects submissions that arrive faster than `minFormFillSeconds`. It must be signed — an unsigned timestamp is just another field to forge. A submission with **no** token is allowed, so adding the field is optional and can be rolled out later. A token older than a day is also allowed rather than rejected — a login page left open in a tab is a human.

### Hosted bot checks

Cloudflare Turnstile, hCaptcha, and friends live in their own packages, so you only install the vendor you use:

```ts
import { TurnstileBotCheck } from "@activescott/auth-botcheck-turnstile"

abuse: {
  botChecks: [new TurnstileBotCheck({ secretKey: process.env.TURNSTILE_SECRET_KEY! })],
}
```

Implement `BotCheckProvider` (`{ id, verify({ request, body, ip, providerId }) }`) to add your own.

## Initiate gate

An invite-only beta, an allowlist, or a blocked domain is a rule about _who_ may be sent a sign-in message. Put it in `gate.onInitiate` rather than in a preamble in your auth route:

```ts
const auth = new Auth({
  // ...
  gate: {
    async onInitiate({ provider, identifier, mode, request }) {
      if (mode === "link") return "allow" // already signed in
      if (await invites.has(provider, identifier)) return "allow"
      return { redirect: "/waitlist" }
    },
  },
})
```

The gate runs inside `handleRequest`, after the provider has parsed, normalized, and validated the identifier (`User@Example.com ` arrives as `user@example.com`, a phone number as E.164) and before anything is created or sent. A malformed identifier is rejected by the provider first, so the gate never acts on one. `mode` is `"signin"` or `"link"` (see [linking identities](../../README.md#linking-identities--account-merge)); `request` is a clone of the initiate request, for headers or cookies.

Return one of:

- `"allow"` — send as usual.
- `{ redirect: "/waitlist" }` — send nothing and answer with a 302 to that URL, for every caller.
- `{ error: AuthErrors.invalidCredentials({ reason: "Invite only" }) }` — send nothing and fail like any other initiate: a browser form post goes back to the submitting page with `?error=<code>`, a fetch caller gets the error as JSON.

A gate that throws fails the initiate. Per-IP and per-recipient abuse limits run before the gate, so a throttled request still gets the silent "sent" answer.

Anyone can start a sign-in for an address they do not own, so a rule that writes something or tells someone about the identifier belongs in the optional `gate.onVerified` instead. It runs after the provider has verified the identifier and before the session is created, with the same `provider`, `identifier`, `mode`, and `request` (the verify request), plus the `user` and `identity` the verify resolved and `isNewUser`. It returns the same decisions: `"allow"` creates the session, `{ redirect }` answers with a 302 and no session, `{ error }` fails the verify like a bad code. It sees email and SMS verifies; passkey sign-ins skip it.

The built-in email and SMS providers consult the gate. With `gate` set, `new Auth` throws if any provider that serves an initiate route does not declare `consultsInitiateGate: true` — an older provider package would otherwise skip your policy without a trace. A custom provider opts in by calling `context.gate?.check({ provider, identifier, mode })` once its identifier is valid, returning the result when there is one, and setting `consultsInitiateGate = true`.

## Admin subpath

`@activescott/auth/admin` is what the admin dashboard is built from, with no framework in it:

| Export                         | Purpose                                                                              |
| ------------------------------ | ------------------------------------------------------------------------------------ |
| `createAdminData(auth)`        | `{ listUsers, describeConfig }` over your stores, as plain serializable rows.        |
| `createAdminPredicate(admins)` | Builds the allowlist check from a delimited string, an array, or your own predicate. |
| `isAdminUser(auth, user)`      | Answers that check for one user against `AUTH_ADMIN_IDENTIFIERS`.                    |

The allowlist is email addresses and E.164 phone numbers, separated by commas or whitespace, matched against **every** identity a user owns. An allowlisted address therefore admits its owner even when they signed in by SMS. An empty or missing allowlist admits nobody.

```ts
import { isAdminUser } from "@activescott/auth/admin"

const session = await auth.verifySession(request)
if (!session || !(await isAdminUser(auth, session.user))) {
  return new Response("Not Found", { status: 404 })
}
```

`isAdminUser` reads the environment allowlist and loads the user's identities on each call. When the list comes from somewhere else, build the check with `createAdminPredicate(admins)` and hand it the user's identities yourself (`identityStore.findByUserId(user.id)`). The React Router adapter's dashboard uses these, so a page you gate yourself and the dashboard agree on who is an admin.

## Logging

Redirect destinations reach the library from `?redirectTo=`, form fields, and the `Referer` header. One that names another origin or another scheme is declined and a configured path is used instead, which is otherwise invisible to your app: a stale link or a proxy rewriting `Referer` shows up only as users landing somewhere unexpected. Give the library somewhere to say so:

```ts
const auth = new Auth({
  // ...
  logger: console, // or { warn: (message, context) => log.warn(context, message) }
})
```

Each declined destination logs one WARN naming the parameter it came from and that value's origin. The value itself is never logged, because a magic-link URL carries a single-use key in its query:

```
[auth] redirect destination declined, using fallback { source: 'redirectTo', fallback: '/', reason: 'other-origin', origin: 'https://other.example' }
```

`logger` is optional and nothing is logged through it when it is absent. Providers receive it as `AuthContext.logger`, and framework adapters read it off the `Auth` instance (`auth.getLogger()`), so configuring it here covers the whole flow. Abuse blocks are separate: those always go to `console.warn`, plus `abuse.onBlocked` if you set it.

## Waitlist

`createWaitlist` is a gate for apps that approve new users by hand. Everyone gets a code. Once they verify it, a user without an approved account becomes PENDING and lands on your waitlist page with no session; admins hear about it through `notify`; an admin approves or blocks from the dashboard. Approved users sign in as usual.

The status lives in your database, behind an `ApprovalStore`. Its values, `"PENDING" | "APPROVED" | "BLOCKED"`, match the enum apps usually already have:

```ts
import {
  createWaitlist,
  waitlistApprovalEmail,
  waitlistNotificationEmail,
} from "@activescott/auth"

const emailOptions = {
  appName: "Fernfiles",
  domain: "fernfiles.com",
  from: "noreply@fernfiles.com",
}

export const waitlist = createWaitlist({
  // Only needed so onApproved below can look up an address to email
  identityStore,
  approvalStore: {
    getApprovalStatus: async (userId) =>
      (await db.user.findUnique({ where: { id: userId } }))?.approvalStatus ??
      null,
    setApprovalStatus: async (userId, approvalStatus) => {
      await db.user.update({ where: { id: userId }, data: { approvalStatus } })
    },
  },
  waitlistUrl: "/waitlist",
  blockedUrl: "/login?error=blocked", // defaults to waitlistUrl
  // App rules that skip the waitlist. Never consulted for BLOCKED users.
  autoApprove: ({ identifier }) => autoApproved.has(identifier),
  notify: (notice) =>
    transporter.sendMail({
      ...waitlistNotificationEmail(notice, emailOptions),
      to: adminEmails,
    }),
  // Tell the user when an admin approves them
  onApproved: ({ identities }) => {
    const to = identities.find((i) => i.provider === "email")?.identifier
    if (to) {
      return transporter.sendMail({
        ...waitlistApprovalEmail(emailOptions),
        to,
      })
    }
  },
  logger: console,
})

const auth = new Auth({ /* ... */ gate: waitlist })
```

The waitlist acts only after verification, so starting a sign-in for someone else's address creates no user and sends admins nothing. The verify step creates the user as it would without a waitlist; the waitlist then records their status. `notify` fires once when a user joins the waitlist (`reason: "waitlisted"`) and whenever `autoApprove` lets someone in (`reason: "auto-approved"`); a throw there is logged and does not fail the sign-in. The email is plain and generic on purpose: app name, domain, sender, and a link to `/admin/users` (`adminPath` changes it). Sending it is yours, so the core takes no mail dependency.

`onApproved` fires when an admin approves a user who was not already approved, through `approve` or `handleAdminAction`, with the user's identities so you can pick an address (an SMS-only user has no email identity). It does not fire for `autoApprove`, whose user is already signing in. `waitlistApprovalEmail` renders the message, linking to `/login` (`signInPath` changes it). A throw is logged and the approval stands.

A user with no recorded status counts as not approved. Mark existing users APPROVED before turning the waitlist on.

The gate only sees email and SMS sign-ins, and only when they verify. Passkey sign-ins and a user you block after they signed in need a per-request check; `waitlist.redirectFor(userId)` returns null for approved users and the URL to send anyone else to. With the React Router adapter:

```ts
createAuthHandlers(auth, {
  // ...
  onSessionVerified: async ({ user }, request) => {
    const to = await waitlist.redirectFor(user.id)
    if (to) return logout(request, to)
  },
})
```

For the dashboard, render approve and block buttons in `AdminUsersPage`'s `rowActions` as forms posting `userId` and `intent` (`"approve"` or `"block"`) to your admin route, and in that route's action call `waitlist.handleAdminAction(await request.formData())` after checking the caller is an admin. `waitlist.approve(userId)` and `waitlist.block(userId)` do the same from your own code. The form has no CSRF token of its own; it relies on the session cookie being `SameSite=Lax` or stricter, as the example configures. The [example app](../../examples/react-router/app/routes/admin.users.tsx) has the whole flow.

## License

MIT

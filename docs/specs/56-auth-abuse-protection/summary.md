# Summary — abuse protection on the auth initiate endpoints (issue #56)

Status: **library work (Parts 1–4) implemented and staged, not committed.** Rollout to the consuming app (Part 5 of `plan.md`) tracked in that app's repo.

## What was built

Protection is on by default with no app configuration; a missing `RateLimitStore` falls back to `InMemoryRateLimitStore`. Every rejection is logged.

`packages/auth` (core, new `src/abuse/`):

- `rate-limit-store.ts` — `RateLimitStore` / `RateLimitHit` (one atomic `hit(key, windowSeconds)`).
- `rate-limiter.ts` — `RateLimitRule`, `RateLimiter`; fixed windows, stops at the first exceeded rule so a blocked caller does not inflate later counters.
- `client-ip.ts` — `cf-connecting-ip` → `x-forwarded-for` (rightmost hop, `trustedProxyHops` default 1) → `x-real-ip`; overridable via `abuse.clientIp.getClientIp`.
- `bot-check.ts` — `BotCheckProvider` interface, `FormTokenBotCheck`, `createFormToken`/`verifyFormToken` (HMAC-SHA-256 over the render timestamp, WebCrypto). Absent token = allowed; token older than 24h = allowed (open tab, not a bot).
- `abuse-guard.ts` — `AbuseConfig`, `AbuseEvent`, `AbuseGuard`; `checkInitiate` (bot checks + per-IP) and `checkIdentifier` (per-recipient). Logs `[auth] blocked initiate: reason=… provider=… ip=… identifier=… rule=…` then calls `onBlocked`.
- `stores/in-memory-rate-limit-store.ts` — default store, sweeps ended windows, `destroy()`.
- `auth.ts` — runs `checkInitiate` before `initiate`/`send` dispatch; blocked callers get the provider's own success response (`abuse.respondWith: "rateLimited"` opts into 429 + `Retry-After`). `createContext` exposes `abuse` to providers; `destroy()` releases the owned store.
- `provider-util.ts` — `initiateAccepted(request, message, setCookies?)`, shared by the providers' success paths and the silent block.

Defaults: per IP 3/min + 10/hour; per recipient 3/hour + 10/day; min form fill 2s. (A honeypot field was built first and then dropped at the user's direction — modern agents won't fill a decoy.)

Providers: `EmailProvider` and `SmsProvider` call `context.abuse?.checkIdentifier(...)` after normalizing the recipient and before creating a challenge; both expose `initiateSentMessage` and return `initiateAccepted(...)` on both paths.

New package `@activescott/auth-botcheck-turnstile` (`TurnstileBotCheck`): raw `fetch` to `siteverify`, `failOpen` defaults to true with a warn log. Plumbing added in `package.json` workspaces, `commitlint.config.js` scope-enum, `scripts/release.ts` `tagPrefixToPackage`.

Example app: `app/components/anti-bot-fields.tsx` (`authFormToken` + optional Turnstile widget), `createLoginFormFields()` in `auth.server.ts`, `abuse` config with `onBlocked` logging and `minFormFillSeconds: 1` (so the Playwright suite need not pause 2s per sign-in). E2E helper `waitForMinimumFormFill(page)` (1200ms) added at every login-form submission.

Docs: "Abuse protection" section in `packages/auth/README.md`, feature bullet, exports table rows, new package row in root `README.md`, source-map entries in `AGENTS.md`.

## Verification run

```bash
npm run build && npm run typecheck && npm test     # 8+2+1+1+1+1+1 test files, all pass
npm run e2e -w examples/react-router/tests          # 24 passed (7.2s)
npx prettier --check .                              # only docs/specs/*.md (untracked) flagged
```

`git diff --cached --stat`: 23 modified + 17 new files.

## Gotchas discovered

- `Auth.handleRequest` must clone the request before the guard parses the body, or the provider gets an empty stream. `AbuseGuard.readBody` does the clone.
- Adding the form token to the example login form breaks Playwright until every submission waits out `minFormFillSeconds` — the failure surfaces later, at the missing OTP code, because a blocked send looks like a successful one.
- Local Playwright requests carry no `x-forwarded-for`, so per-IP limits are skipped in e2e; per-recipient limits still apply (tests use distinct addresses).
- `normalizePhoneNumber` needs a leading `+`, so `"(415) 555-0100"` is rejected before the abuse check ever runs.

## Next steps

1. Split the staged work into per-scope commits: `feat(auth)`, `fix(auth-provider-email)`, `fix(auth-provider-sms)`, `feat(auth-botcheck-turnstile)`, `docs(examples)`, plus repo plumbing.
2. Part 5 of `plan.md`: Ramblefeed upgrade `@activescott/auth` ^0.1.1 → ^3 (stops scanner clicks creating accounts), rewrite `app/lib/auth.server.ts` and `app/routes/start.tsx`, wire `onBlocked` into its logger, then inventory junk accounts before any deletion.

# Plan: Email OTP codes, SMS auth, Passkeys for @activescott/auth

## Context

`@activescott/auth` is a framework-agnostic magic-link auth monorepo (npm workspaces; core `packages/auth`, `packages/auth-provider-email`, `packages/auth-adapter-react-router`, `examples/react-router`). Three features to add, shipped as three independent, sequential phases:

1. **Email OTP code** alongside the magic link, so iOS/macOS autofill the code from Mail (clean sign-in UX).
2. **SMS auth** via a vendor-neutral SMS provider + Twilio/AWS transport adapter packages (RCS preferred where configured), with example apps and provisioning docs/scripts.
3. **Passkeys (WebAuthn)** compatible with 1Password, iOS, macOS, Android, Windows.

Guidelines honored: standards-based, no deps in core (deps only in adapter/vendor packages), minimal react-router examples, unit + e2e tests in CI, conventional-commit scopes select package bumps (one PR/commit per package scope).

**First implementation task: save this plan to `docs/specs/otp-sms-passkeys/plan.md`** (repo has no docs/ yet; create it; keep summary.md updated at milestones).

## Related future feature: identity merge

`../identity-merge/spec.md` (added 2026-07-30) specifies merging two users' authenticators into one user. Accommodations binding on THIS plan: keep per-provider user-lookup/create logic in one shared function per provider (link-mode branches there later); `IdentityStore` additions stay optional/additive; `StoredCredential` links to user via `userId` only; `AuthContext.getSession` stays optional; Phase 2 "email + phone" docs must note the existing-identity-conflict case as "account merge — coming later", not silent behavior.

## Verified constraints found in exploration

- Magic links are stateless JWTs; **no server-side storage exists for OTP codes / WebAuthn challenges** → new store interfaces needed.
- Core routing (`auth.ts:175-186`) dispatches only `initiate|send|verify|callback`; anything else → 404 "Unknown action". Passkeys need 4 endpoints → additive core extension.
- Adapter `handleAuth` treats any path containing `/verify` as a link-verify (`handlers.ts:89`) — would wrongly capture passkey `register-verify`; needs exact-action match fix.
- `provider.initiate`/`verify` results have no header channel; adapter discards headers → additive `setCookies?: string[]` on result types required for challenge cookies.
- CI/release: `scripts/release.ts` has a hardcoded tag-prefix→package map; commitlint `scope-enum` lists package dirs — **both must be updated for each new package or it silently won't publish**.
- AGENTS.md: core path = Fetch Request/Response only, edge-compatible (note: `jsonwebtoken` already Node-bound — see Deferred).

## Research findings (drive the design)

- **Apple email code autofill**: heuristic (iOS 17+ Mail; iOS 26/macOS Tahoe expand to 3rd-party apps + Chrome). No formal spec. Best practice: plain-text sentence `Your sign-in code is: 123456` + input `autocomplete="one-time-code" inputmode="numeric"`.
- **SMS autofill**: WebOTP spec — SMS **last line** `@<domain> #<code>` (Android/Chrome `navigator.credentials.get({otp})`); Safari/iOS use heuristics + `autocomplete="one-time-code"`.
- **Twilio RCS**: GA; same Messages API via a Messaging Service with an onboarded RCS sender; automatic SMS fallback. Carrier/brand onboarding is manual (days–weeks), not scriptable.
- **AWS**: SMS via End User Messaging (`@aws-sdk/client-pinpoint-sms-voice-v2`, `SendTextMessageCommand`). RCS support new (Mar 2026), agent registration + approval, SMS fallback via phone pools. No code-path difference for us; pool as origination identity.
- **@simplewebauthn/server v13**: MIT, node>=20, WebCrypto-based (edge-ok), 8 small parse deps (ASN.1/CBOR/base64). Hand-rolling attestation parsing = reimplementing exactly those — security-critical, not worth it.

## Shared design decisions

- **D1 `ChallengeStore` in core (F1)**: `Challenge {id, type, identifier, hashedCode?, data?, attempts, maxAttempts, createdAt, expiresAt}`; `ChallengeStore {create, findById, incrementAttempts (atomic), delete}`. Ship `InMemoryChallengeStore` (lazy expiry + sweep, like existing `SessionCache`); README documents multi-instance caveat + SQL example. Serves email OTP + SMS OTP; optional for WebAuthn strict single-use.
- **D2 OTP mechanics** (core `packages/auth/src/otp.ts`, WebCrypto only): 6-digit default (configurable), CSPRNG w/ rejection sampling, stored as `SHA-256("${challengeId}:${code}")`, constant-time compare, `incrementAttempts` before compare, cap 5, expiry 10m, single-use (delete on success).
- **D3 Cookie-bound code entry**: initiate sets HttpOnly SameSite=Lax `Path=/auth` cookie with challenge id (`__Host-` prefix when secure); user types only the code. No email+code fallback in v1 (magic link covers cross-device). Resend = new challenge, cookie overwritten.
- **D4 No new core action for OTP**: `POST /auth/email/verify` + `code` body + cookie = code path; `GET /auth/email/verify?token=` = magic link, unchanged.
- **D5 Header channel**: additive `setCookies?: string[]` on `AuthInitResult` success + `AuthSuccess`; core response builders and adapter propagate. Minor bump, backwards compatible.
- **D6 Reuse error codes**: wrong code → `INVALID_CREDENTIALS`, cap → `RATE_LIMITED`, expired → `EXPIRED_TOKEN`. No union growth.
- **D7 Provider-defined actions (F3)**: optional `AuthProvider.handleAction?(action, request, context): Promise<Response>`; `handleRequest` falls back to it before 404. Additive.

## App-facing interface (validation reference)

What an app implements to support email magic link + SMS OTP. Use this to validate each phase — the surface must stay this small.

**The only new interface an app must implement is `ChallengeStore`** (optional — `InMemoryChallengeStore` shipped). Exists because OTP codes need server-side state (hashed code, attempts, expiry), unlike stateless magic-link JWTs:

```ts
interface ChallengeStore {
  create(data: Omit<Challenge, "attempts" | "createdAt">): Promise<Challenge>
  findById(id: string): Promise<Challenge | null>
  incrementAttempts(id: string): Promise<number> // atomic
  delete(id: string): Promise<void>
}
```

`Challenge` row: `{id, type: "sms-otp" | "email-otp" | "webauthn", identifier, hashedCode?, data?, attempts, maxAttempts, createdAt, expiresAt}`.

**Existing stores unchanged.** `UserStore`/`IdentityStore` keep exact current interfaces; SMS login = identity row `{provider: "sms", identifier: "+14155550100"}`.

**Wiring** — the two NEW lines are the whole difference:

```ts
const auth = new Auth({
  session: { secret: env.JWT_SECRET },
  userStore, // unchanged
  identityStore, // unchanged
  challengeStore: new InMemoryChallengeStore(), // NEW
  providers: [
    new EmailProvider(emailConfig, new NodemailerTransport()), // unchanged
    new SmsProvider(
      // NEW
      { appName: "MyApp" },
      new TwilioTransport({ accountSid, authToken, messagingServiceSid }),
    ),
  ],
})
```

Vendor creds live in the transport constructor (vendor package); `auth-provider-sms` stays dependency-free. Custom vendor = implement `SmsTransport { sendMessage(to, message): Promise<boolean> }`.

**Routes: nothing new** — existing catch-all `/auth/:provider/:action` dispatches `sms`. Adapter handler signatures unchanged.

**UI = the app's only real work:** phone form POSTs `/auth/sms/initiate` (server sends SMS, sets HttpOnly challenge cookie); code form `<input name="code" autoComplete="one-time-code" inputMode="numeric">` POSTs `/auth/sms/verify` → session cookie + redirect. User types only the code; cookie binds it to the initiation.

**Email required in addition to phone:** existing multi-identity model — one user, two identity rows; sign in via SMS then run email initiate while signed in. Docs only, no code.

Email OTP (Phase 1) is analogous: same `challengeStore` line, `otp: { enabled: true }` in the email provider config, plus a code-entry form on the login page.

## Per-PR local test + release workflow (user-confirmed cadence)

Merging to `main` auto-releases the changed package (conventional-commit scope → version bump → npm publish). So each PR is its own reviewable, locally testable, released unit:

1. I implement one PR on a branch (single commitlint scope — never mix scopes in one PR; release tooling depends on it).
2. **Local test checkpoint**: I stage/push and hand Scott exact commands — typically `npm ci && npm run build && npm test`, then `npm run dev --workspace=examples/react-router` (or the SMS example) plus a short manual script of what to click/verify (e.g. "send email → code logged to console → enter code → dashboard").
3. Scott confirms (and we iterate on changes within the phase here — this is the design-feedback window).
4. Merge PR → CI validates + e2e → auto-release of that package.
5. Next PR in the phase builds on the released version.

Package PRs land before example PRs in each phase, so every example PR is testable against already-released package changes. Each phase ends with a working example + e2e green + README status updated — a clean released-feature boundary.

## Phase 1 — Email OTP (packages: auth, auth-provider-email, auth-adapter-react-router, examples; 4 PRs in that order)

1. **`feat(auth)`**: add `Challenge`/`ChallengeStore` types + `challengeStore?` on `AuthConfig`/`AuthContext`; `src/otp.ts` utils; `src/stores/in-memory-challenge-store.ts`; `setCookies` support in `initResultToResponse`/`authResultToResponse`; exports. Tests: otp utils, store expiry/attempts, cookie propagation.
2. **`feat(auth-provider-email)`**: `EmailProviderConfig.otp? {enabled, length=6, expiry="10m", maxAttempts=5, cookieName="auth_challenge"}`; `EmailTransport.sendMagicLink` gains optional `options?: {code?}` (additive-safe); `initiate` creates hashed challenge + sets cookie when enabled (missing challengeStore → CONFIGURATION_ERROR); `verify` branches GET+token (unchanged) vs POST+code (cookie → findById → expiry → incrementAttempts/cap → constant-time compare → delete → shared identity/user upsert extracted from magic-link path); nodemailer template adds code block in HTML **and plain-text sentence `Your sign-in code is: <code>`**; dev mode logs code; env config parsing. Tests: happy path, wrong code increments, cap → RATE_LIMITED even w/ correct code, expiry, replay fails, resend invalidates, magic link regression both flag states.
3. **`feat(auth-adapter-react-router)`**: `sendMagicLink` result carries `setCookies`; `handleAuth` verify branch merges `result.setCookies` with session cookie. Tests.
4. **`feat(examples)`** + e2e: example wires `InMemoryChallengeStore` + `otp:{enabled:true}` + code-capture transport wrapper (dev); `login.tsx` shows code-entry form after send (`<input name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}>`, resend button, link copy retained); e2e-only code-readback route gated on `E2E_TEST_MODE` + secret header (analog of existing `E2E_MAGIC_LINK_SECRET` mint pattern); Playwright specs: code login success, wrong code error, magic-link regression.

Docs: root README status row; auth README (ChallengeStore + caveats + SQL example); email README (otp config + autofill notes).

## Phase 2 — SMS (new packages: auth-provider-sms, auth-sms-twilio, auth-sms-aws; example(s); 4 PRs)

1. **`feat(auth-provider-sms)`** (zero vendor deps; peer `@activescott/auth`): `SmsTransport {sendMessage(to, message)}`; `SmsProviderConfig {otp?, appName?, webOtpDomain?, messageTemplate?}` — vendor creds live in transport constructors, not provider config; id `"sms"`, `POST /auth/sms/initiate` + `POST /auth/sms/verify`; E.164 validate/normalize (`/^\+[1-9]\d{1,14}$/`); reuses core otp utils + ChallengeStore (`type:"sms-otp"`); ships `ConsoleTransport` (dev, zero-setup). Extract shared `verifyOtpChallenge` helper into core `otp.ts` (separate `feat(auth)` commit) since email/SMS verify are near-identical. Default message (WebOTP line LAST):

   ```
   Your <appName> sign-in code is: <code>

   @<domain> #<code>
   ```

2. **`feat(auth-sms-twilio)`**: raw `fetch` to Twilio Messages REST (Basic auth, form-encoded), zero deps, edge-safe; config `{accountSid, authToken, from? | messagingServiceSid?}`; fetch injected for tests. RCS = point `messagingServiceSid` at Messaging Service with onboarded RCS sender → Twilio does RCS + SMS fallback, zero code. README: RCS onboarding is manual, days–weeks.
3. **`feat(auth-sms-aws)`**: dep `@aws-sdk/client-pinpoint-sms-voice-v2`, `SendTextMessageCommand`; config `{originationIdentity, configurationSetName?, region?}`; client injectable. RCS: approved agent in a phone pool as origination identity; fallback via pool. Verify current AWS RCS API surface at implementation time (feature is new).
4. **`feat(examples)`** + e2e: ONE SMS example app (`examples/react-router-sms`) with transport selected by `SMS_TRANSPORT=console|twilio|aws` env var, console default (user-confirmed). Interactive `tsx` setup scripts per vendor (`scripts/setup-twilio.ts`, `scripts/setup-aws.ts`): prompt creds, provision automatable pieces (Twilio: search/buy number, optional Messaging Service; AWS: phone pool/origination), write `.env`, print manual-steps checklist (RCS onboarding, toll-free verification). Step-by-step provisioning docs in vendor READMEs. Document email+phone pattern (existing multi-identity model; no code). E2E: console transport + code-capture route; specs: phone → code → dashboard, invalid E.164.

Cross-cutting: workspaces entries; commitlint `scope-enum` += 3 packages; `scripts/release.ts` tag-prefix map += 3; CI `sms-example-e2e` job cloned from `example-e2e`; README status row.

## Phase 3 — Passkeys (package: auth-provider-passkey; core + adapter tweaks; 4 PRs)

1. **`feat(auth)`**: `handleAction?` on `AuthProvider` (D7) + dispatch fallback before 404; `AuthContext.getSession?` bound to `verifySession`. Tests incl. 404 regression.
2. **`feat(auth-provider-passkey)`** (dep: `@simplewebauthn/server` v13 — user-confirmed; WebCrypto/edge-ok, verify at impl time):
   - `CredentialStore` interface in this package (not core): `{findById, findByUserId, create, updateCounterAndLastUsed, delete?}` over `StoredCredential {credentialId, publicKey (base64url), counter, transports?, userId, deviceType, backedUp, nickname?, createdAt, lastUsedAt?}`; ship `InMemoryCredentialStore`.
   - Config: `{rpName, rpID?, expectedOrigin?, credentialStore, challengeSecret, challengeExpiry="5m", challengeCookieName?, challengeStore?}`.
   - Challenge: stateless signed-JWT HttpOnly cookie (5m) by default; optional `challengeStore` (`type:"webauthn"`) for strict single-use.
   - Actions via `handleAction`: `register-options` (requires session; `generateRegistrationOptions` w/ **residentKey "preferred", userVerification "preferred", NO authenticatorAttachment, attestation "none", ES256 + RS256**, excludeCredentials), `register-verify` (persist credential + identity `{provider:"passkey", identifier: credentialId}`), `authenticate-options` (empty allowCredentials → discoverable/usernameless), `authenticate-verify` (lookup by response.id, verify, counter update — warn-not-fail on regression for synced passkeys, create session, return JSON + Set-Cookie since caller is fetch not navigation).
   - Browser client: subpath export `@activescott/auth-provider-passkey/browser`, zero deps (~120 lines: base64url conversions, `startRegistration()`, `startAuthentication({conditional})`).
   - Registration model: add-passkey-while-signed-in (email/SMS first) + usernameless login. Passkey-first signup deferred.
   - Tests: DI fakes + canned WebAuthn fixture responses; challenge cookie lifecycle; 401 unauth register.
3. **`feat(auth-adapter-react-router)`**: fix `handlers.ts:89` — exact action match for `verify|callback` only, so `register-verify`/`authenticate-verify` fall through to `auth.handleRequest`. Regression tests.
4. **`feat(examples)`** + e2e: extend existing example — dashboard "Add a passkey", login "Sign in with passkey" + conditional UI (`autoComplete="username webauthn"` on email input, `startAuthentication({conditional:true})` on load). E2E via Playwright CDP virtual authenticator (`WebAuthn.enable`, ctap2/internal/residentKey/userVerified/automaticPresence): magic-link login → add passkey → logout → passkey login; no-credential failure case.

Cross-cutting: workspaces, commitlint scope, release.ts map, CI build list, README status + passkey README (cross-platform notes, CredentialStore SQL example).

## Decisions made (recommendation stated; overridable)

- OTP length 6 (cap carries security; matches autofill heuristics); configurable.
- Cookie-bound code entry only in v1 (no email+code fallback).
- Reuse existing AuthErrorCodes.
- Resend throttling deferred to app-level docs.
- Provisioning via interactive tsx scripts (repo is tsx-native; no IaC precedent); terraform appendix snippet in AWS docs only.
- Passkey browser client as subpath export, not separate package.
- Keep `jsonwebtoken` for consistency. **Deferred follow-ups**: migrate core to `jose` for real edge support; drop-or-use unused `zod` dep in core.

## Verification

- Per package: `npm run build && npm run typecheck && npm test` (workspace fan-out from root).
- E2E: `npm run e2e -w examples/react-router/tests` (+ new SMS example tests). New specs listed per phase above.
- Manual: run example (`npm run dev`), email OTP: send → console shows code → enter code → dashboard; magic link still works. SMS: console transport flow. Passkeys: chromium virtual authenticator via e2e; manual cross-platform spot check (1Password/iCloud) post-merge.
- CI runs all of the above on PR; release publishes per changed scope (verify release.ts map + commitlint updated with every new package).

## User-confirmed decisions (AskUserQuestion, 2026-07-30)

1. SMS examples: ONE app, env-switched transport (`SMS_TRANSPORT=console|twilio|aws`).
2. SMS content: code only (no magic link in SMS).
3. Passkey server verify: use `@simplewebauthn/server` dep in the passkey provider package.
4. Provisioning: interactive tsx scripts writing `.env`; no terraform, no in-app wizard.

## v2 breaking redesign (user-confirmed, 2026-07-31)

Decided after Phase 1 shipped to the PR branch; supersedes parts of the original design above.

1. **`challengeStore` is REQUIRED** on `AuthConfig`/`AuthContext`. Rationale: user/identity stores are already required state; one more table does not change the library's value, and the library cleans up after itself (single-use delete + expiry sweep). Known consumers (ramblefeed, tinkerbell) will be migrated by agents.
2. **Challenge-backed magic links** replace stateless JWT links. One challenge per send with two redemption paths: link (`?challenge=<id>&key=<256-bit secret>`, key hashed at rest) and numeric code (always included; no enable flag). Removes `magicLinkSecret`, `additionalSecrets`, `magicLinkExpiry`, and the `jsonwebtoken` dependency from the email provider. One unified `expiry` (default 15m).
3. **Confirm-interstitial for links (scanner guard)** — DOCUMENTED FEATURE: links are strictly single-use; GET renders a minimal "Confirm sign-in" page and redemption happens on the confirm POST. Email security scanners (SafeLinks, Mimecast, previews) prefetch with GET but never POST, so they cannot consume the link. Costs one extra user click; keeps GETs side-effect-free. `AuthProvider.verify` may now return `Response | AuthResult` to support this.
4. **Forms post directly to auth routes.** `sendMagicLink` helper and `SendMagicLinkResult.setCookies` removed from the adapter; login pages need no action. Initiate answers browser form posts (urlencoded + Accept: text/html) with a 302 back to the Referer carrying `?sent=1`/`?error=<code>` and the challenge cookie; JSON callers get `AuthInitResult` + `setCookies`.
5. **Scope principle documented in README**: direct authentication only (email, phone, passkeys) — deliberately NOT an OAuth-federation library (that niche is served by BetterAuth et al.). OAuth removed from comments/roadmap language.
6. **E2E pattern replaced**: `additionalSecrets` JWT-minting is gone; tests use the capture-transport + gated readback route and drive the real confirm/code flows.

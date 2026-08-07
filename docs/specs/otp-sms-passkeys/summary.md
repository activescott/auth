# Summary: OTP / SMS / Passkeys implementation progress

Last updated: 2026-08-02 (Phases 1+2+3 SHIPPED — PR #53 merged, all 5 packages on npm; nothing outstanding). Plan: `plan.md` (Phase 3 section is the spec). Related future spec: `../identity-merge/spec.md`.

**README refresh (2026-08-02, after release)**: `packages/auth/README.md` rewritten (root-README intro + Why + Features + Documentation section on top; fixed stale "SMS/passkeys planned" and "challengeStore optional" claims), react-router v7→v8 refs fixed in root README / adapter README / example home.tsx, email README prettier-formatted. Shipped as `fix(auth)` `863b91f` + `fix(auth-adapter-react-router)` `52ef5c6` + `docs:` `168363e` → auth@3.0.1 + auth-adapter-react-router@1.0.4 published via OIDC (run 30735691773), new READMEs verified in npm registry. Note: `docs:` commits don't release, so npm README updates need a `fix`/`feat` on that package.

## PHASE 3 MERGED AND RELEASED (2026-08-02)

PR #53 merged to main with a merge commit (`70c1d47`, no squash) after checks passed (validate 32s, example-e2e 47s). Main CI run 30735148707: release job created all 5 tags + GitHub releases (auth@3.0.0, auth-provider-email@1.0.2, auth-provider-sms@0.1.2, auth-adapter-react-router@1.0.3, auth-provider-passkey@0.1.0). Publish matrix results, verified against npm:

- `@activescott/auth@3.0.0` ✅
- `@activescott/auth-provider-email@1.0.2` ✅
- `@activescott/auth-provider-sms@0.1.2` ✅
- `@activescott/auth-adapter-react-router@1.0.3` ✅
- `@activescott/auth-provider-passkey@0.1.0` ✅ — CI publish failed E404 (OIDC trusted publishing cannot create a brand-new package, same as Phase 2 twilio first-publish); Scott published 0.1.0 manually and configured the trusted publisher on npmjs.com (GitHub Actions, activescott/auth, `ci.yaml`, environment blank) on 2026-08-02. Subsequent releases publish via OIDC automatically.

## PHASE 3 STATE (2026-08-01)

All four scopes implemented and validated on branch `feat/passkeys` (based on main `a6520fe`). 181 unit tests green (81 auth / 24 email / 26 sms / 25 passkey / 5 twilio / 20 adapter), 24/24 e2e green (incl. 3 new passkey specs driving real WebAuthn ceremonies via CDP virtual authenticator), build + typecheck + prettier clean on all changed files.

**Commit state**: (historical — PR #53 since reviewed, grew to 21 commits, MERGED; see section above) 17 commits on `feat/passkeys`, pushed. PR body (updated after the metadata redesign) carries the no-squash warning + pre-merge manual-publish checklist. Metadata-redesign commits: `b5c3c7b` feat(auth)! required metadata+update (→3.0.0), `c6757d8` passkey-in-metadata rework, `93557c3`/`2891f2e`/`e5d3717` peer widenings, `bcdab14` example, `ac49af7` docs, `12d040e` chore format. Original series:

1. `4269a6c` feat(auth): handleAction + getSession (→ core 2.1.0→2.2.0 on release)
2. `f6755cd` feat(auth-provider-passkey): the new package (0.1.0)
3. `e60c427` fix(auth-adapter-react-router): exact verify/callback action match
4. `f524b98` feat(examples): passkeys in the react-router example + e2e
5. `1c12428` docs: mark passkeys shipped in the readme (releases nothing)

**DESIGN DECISION (Scott, 2026-08-01, supersedes plan.md's CredentialStore): passkey credentials live in `Identity.metadata`, not a separate store.** Discussion outcome: the CredentialStore/IdentityStore split was contract-level only (both implementable on one table), and `Identity.metadata` was already documented as provider-owned — so the passkey provider now stores `{publicKey, counter, transports, deviceType, backedUp, nickname?, lastUsedAt?}` in the identity row's metadata (identifier = credential ID), validated with a zod schema on every read (`parsePasskeyCredentialMetadata`), written back wholesale after each sign-in. Scott's rationale, accepted: apps (de)serialize JSON regardless, so provider-owned zod validation at runtime beats compile-time typing of app adapter code; and Identity/IdentityStore simply hadn't been designed flexibly enough — this fixes that so future stateful providers (TOTP seeds, recovery codes) need no core changes. Breaking core changes (auth → 3.0.0): `Identity.metadata` REQUIRED (stateless providers store `{}`), documented as provider-owned/opaque/sensitive ("encrypt at rest is a reasonable default"); `IdentityStore.update` REQUIRED (metadata replaced wholesale). CredentialStore/StoredCredential/InMemoryCredentialStore deleted before ever being published. Peer ranges widened: email/sms `^2.1.0 || ^3.0.0`, adapter `^2.0.0 || ^3.0.0`, passkey `^3.0.0`. Counter update loses single-field atomicity — acceptable because counter regression is warn-not-fail by design.

**Review round 1 (2026-08-02, all 8 comments addressed + replied inline)**: peers simplified to exactly `^3.0.0` (adapter also react-router `^8.0.0` only) — Scott: no backward compat concerns (`22dc854`/`f99433a`/`5aedd33`); passkey challenges now ALWAYS single-use via the core `context.challengeStore` — Scott caught that the provider's optional challengeStore knob was vestigial since core requires one; `PasskeyProviderConfig.challengeStore` removed (`27adf84`); WebAuthn response envelope guards converted to declarative zod schemas in new `webauthn-response.ts` (`27adf84`); README wiring snippet notes passkey provider sits alongside email/SMS. `jsonResponse` deliberately kept in-file (12 lines, one consumer) — said so in reply.

**What was built (key decisions honored from plan.md)**:

- Core (already committed): `AuthProvider.handleAction?(action, request, context)` dispatched by `handleRequest` before the 404; `AuthContext.getSession?` bound to `verifySession`.
- `packages/auth-provider-passkey` v0.1.0 (per release rule 1): dep `@simplewebauthn/server` ^13.2.2 + `jose` ^6 (challenge JWT, same lib as core); peer `@activescott/auth` ^2.2.0 (core will bump 2.1.0→2.2.0 from commit 1's feat).
- Challenge = signed-JWT (HS256, jti, purpose registration|authentication, userId bound for registration) in HttpOnly `auth_passkey_challenge` cookie via core `buildChallengeCookie`; optional config.challengeStore consumes jti row on first redemption (strict single-use; replay test proves it).
- Counter regression: library gets `counter: 0` (disables its hard fail); we compare vs stored counter ourselves, console.warn, never block (synced passkeys).
- Registration requires session via `context.getSession`; 401 SESSION_INVALID without, 500 CONFIGURATION_ERROR when getSession absent (old core).
- Browser client `./browser` subpath: zero runtime deps (type-only imports from @simplewebauthn/server), startRegistration/startAuthentication({conditional})/isConditionalUIAvailable, plus a module-level AbortController so a new ceremony aborts a pending conditional one (required for conditional→modal transition on the login page).
- WebAuthnServer DI interface (4 lib functions) injectable in provider constructor — tests use fakes, no attestation fixtures needed.
- e2e: CDP `WebAuthn.enable` + virtual authenticator (ctap2/internal/residentKey/userVerified/automaticPresenceSimulation). Specs: add-then-signin roundtrip, no-credential failure (modal rejects fast, no hang), 401 register-options unauthenticated. Conditional UI request on login page does NOT auto-resolve with virtual authenticator (waits for autofill pick) so it doesn't race the tests.

**To resume after 1Password unlock**: make commits 2-5 above (files for 3-5 are unstaged in the working tree; stage by name per scope), then `npm run lint` note below, then push + PR per Scott's call (single PR merge-commit like Phase 2 #35, or split).

**Gotchas found this session**:

- **1Password "encountered a problem" toast after passkey sign-in — VERIFIED cause is 1P's AbortSignal bug, NOT navigation.** 1Password's extension ignores `AbortController` on conditional-mediation `credentials.get()` (staff-acknowledged, unfixed since Oct 2024: https://www.1password.community/1password-at-home-31/passkey-authentication-doesn-t-abort-on-signal-2930). Every aborted conditional ceremony strands a 1P-internal ceremony that later fails → generic toast, regardless of sign-in outcome. Our page start→abort→started ceremonies twice via React StrictMode's dev double-mount, AND the button click aborts the pending conditional (spec-required). Fixes in `login.tsx`: setTimeout(0)+clearTimeout in the effect so exactly ONE conditional ceremony starts per page load; success handler no longer gated on a stale `cancelled` flag (users could complete the aborted ceremony → verified server-side but no navigation). Button-path abort is unavoidable → 1P may still toast there even on success; comment at the call site says so. Earlier theory ("1P watches for a document navigation to detect success") had NO supporting evidence — full-page `location.assign` after sign-in was kept only for the fresh server render, not for 1P. 1P publishes zero documentation on any of this (developer.1password.com checked); historical 1P-specific localhost passkey failures exist (2023 community thread), status today unknown.
- Chrome's CDP **virtual authenticator auto-resolves conditional-UI requests** (real browsers wait for the user to pick from autofill) — so with a registered credential, the e2e login page auto-signs-in on load. `passkeys.spec.ts` accepts either the auto path or the button path.
- Example passkey UX truths (documented on the login page since `1165a54`): passkey sign-in only works after add-passkey-while-signed-in; dev-server restart wipes the in-memory credential store, orphaning passkeys saved in 1P/iCloud for localhost — delete them in the manager when that happens.

- Prettier drift EXISTS ON MAIN (pre-existing, not ours): `packages/auth/src/otp.ts`, `packages/auth-provider-email/README.md`, `packages/auth-adapter-react-router/README.md`, root `README.md` fail `npm run lint` on a clean checkout — likely from a dependabot prettier bump. CI does not run lint (validate = build/typecheck/test only). Left untouched; flag to Scott.
- Shell node is v22.21.1 (< .nvmrc 22.23); react-router prints a version warning but build/e2e all pass anyway.
- `npm run build --workspace=examples/react-router` fails ("Missing script" in the tests workspace — the dir path matches both workspaces); use `--workspace=@activescott/auth-example-react-router`.
- The `nickname` field: register-verify reads optional `body.nickname` (string) alongside the WebAuthn response JSON and stores it on the credential; the example does not use it yet.

## PHASE 3 HANDOFF — read this first (fresh agent starts here)

**Task**: Passkeys (WebAuthn) per plan.md "Phase 3" section. 4 PRs: (1) `feat(auth)` core `handleAction?` on AuthProvider + `AuthContext.getSession` bound to verifySession; (2) `feat(auth-provider-passkey)` new package w/ `@simplewebauthn/server` v13 (user-approved dep), CredentialStore interface in that package, actions register-options/register-verify/authenticate-options/authenticate-verify via handleAction, browser client as subpath export `/browser`; (3) `fix(auth-adapter-react-router)` exact-action-match (handlers.ts treats any path containing `/verify` as link-verify — would wrongly capture `register-verify`; find it via `grep -n 'verify' packages/auth-adapter-react-router/src/handlers.ts`); (4) `feat(examples)` extend `examples/react-router` (dashboard "Add a passkey", login conditional UI, CDP virtual-authenticator e2e). Registration model: add-passkey-while-signed-in + usernameless login; passkey-first signup deferred. All design decisions (challenge cookie vs store, residentKey/userVerification params, counter-regression warn-not-fail) are in plan.md — follow them.

**Current state on npm** (all release via OIDC trusted publishing w/ provenance, verified working): `@activescott/auth@2.1.0`, `auth-provider-email@1.0.1`, `auth-adapter-react-router@1.0.2` (react-router peer `^7.0.0 || ^8.0.0`), `auth-provider-sms@0.1.1`, `auth-sms-twilio@0.1.1`.

**Quick commands**:

```bash
git checkout main && git pull
npm install && npm run build && npm run typecheck && npm test   # 149 unit tests
npm run e2e --workspace=@activescott/auth-example-react-router-e2e   # 21 specs, port 3200
npm run dev --workspace=examples/react-router   # login: email tab default, phone tab /login?via=sms
```

**CRITICAL release-process rules for a NEW package** (learned the hard way, see Phase 2 recovery below):

1. Start `package.json` at the intended first version (e.g. `0.1.0`), NEVER `0.0.0` — simple-release releases a tag-less package at its current version.
2. Extend BOTH `commitlint.config.js` scope-enum AND the tag map in `scripts/release.ts`, else publishing silently skips it.
3. First publish of a new package CANNOT use OIDC: before merging the PR, Scott must `npm publish --access public` manually (needs his OTP) and then configure the trusted publisher on npmjs.com (Settings → Trusted Publisher → GitHub Actions: `activescott` / `auth` / `ci.yaml`, environment blank). Only then does CI publishing work.
4. Per-scope commits, lowercase subjects, NO AI attribution, never squash-merge multi-scope PRs. Scope-less `chore:`/`docs:` commits pass commitlint and release nothing.

**Working cadence Scott expects**: all commits local on one branch → Scott tests locally → push + open PR → Scott merges (or says "ship it") → auto-release. Stage files by name. Commit signing via 1Password — if it fails ("failed to fill whole buffer"), 1Password is locked; wait for Scott.

**Environment gotchas**:

- Node: `.nvmrc` = `22.23` (react-router 8.3.0 requires node >=22.22; type stripping default-on so `.mts` scripts run with plain `#!/usr/bin/env node`).
- Example runs react-router **8.3.0** with matching v8 toolchain (issue #50 / PR #51, merged).
- E2e: Playwright webServer builds/starts the app on port 3200; `E2E_TEST_MODE=true` gates the `/e2e/otp-code` readback route AND forces the console SMS transport. Virtual-authenticator specs will need Playwright CDP (`WebAuthn.enable`).
- Example login page: tabs are links (`/login`, `/login?via=sms`) because the provider's Referer-based redirect preserves query params through `?sent=1` — a passkey tab/section should follow the same pattern; note passkey verify posts are fetch() calls returning JSON, not form navigations (plan.md D7).
- Twilio in the example auto-detects from `TWILIO_*` env vars (no SMS_TRANSPORT var); `examples/react-router/.env` has Scott's real Twilio creds — NEVER commit, already gitignored. Carrier delivery pending his A2P 10DLC campaign review (2-3 weeks); Twilio API-accept verified via delivery log.
- Dependabot lockfile regens are broken in this workspace (drops nested duplicate entries → npm ci fails). Apply dep bumps locally with `npm install`/`npm update` instead (see PR #49).
- vitest resolves workspace deps via built `dist/` — run `npm run build` after core changes before provider tests.
- docs/specs is intentionally NOT committed (repo convention) — keep updating this file locally.

**Open/parked items**: AWS transport on branch `feat/sms-aws` (draft PR #37, issue #36, tag `archive/sms-aws-v1`) awaiting a community tester. Dependabot #48 (morgan) open. ramblefeed/tinkerbell migration to auth 2.x pending. Dependabot vulns backlog untriaged.

## Phase 2 (SMS) — MERGED + RELEASED (2026-08-01, with manual recovery)

PR #35 merged (merge commit `fad292b`, 18 commits, no squash). **Release automation failed on first run** (run 30713003323) — two compounding causes, both now fixed:

1. **0.0.0 bug confirmed**: simple-release releases a tag-less package at its current package.json version (`firstRelease` only applies to a fully untagged repo) → new packages tagged/attempted at 0.0.0. Fix: new packages must START at intended first version in package.json (both set to 0.1.0 via chore-scoped commits in PR #40).
2. **First publish of a NEW package cannot use OIDC trusted publishing** (relationship configurable only on existing packages) → twilio publish E404 in 16s → `fail-fast` cancelled the 3 good publishes. Reruns useless: workflow snapshot keeps fail-fast, twilio fails first, re-cancels (verified twice). Fix: `fail-fast: false` on publish matrix (PR #40). Lesson for Phase 3: BEFORE merging a PR adding a new package, manually publish its first version + configure the trusted publisher, or expect this dance again.

Recovery: deleted bogus 0.0.0 tags/releases; Scott `npm login` + one OTP; manually published all 5 (auth@2.1.0, email@1.0.1, adapter@1.0.1, provider-sms@0.1.0, sms-twilio@0.1.0 — no provenance on these versions, cosmetic); created 0.1.0 tags + GH releases; merged PR #40 (release no-op).

**Post-recovery (2026-08-01, all VERIFIED):** Scott configured trusted publishers for the 2 new packages; PR #47 (fix-scoped README tweaks) released provider-sms@0.1.1 + sms-twilio@0.1.1 via OIDC WITH provenance attestations — trusted publishing proven end to end for all 5 packages. Deleted 9 stale draft GH releases (early 0.1.x era). Scott merged dependabot #43 (react-router 7.15.0→8.3.0 MAJOR) → adapter peer `^7.0.0` was a published ERESOLVE bug for v8 users → widened to `^7.0.0 || ^8.0.0` in PR #49 → adapter@1.0.2 released via OIDC. PR #49 also applied dependabot's 5 transitive bumps locally (dependabot lockfile regen DROPS nested duplicate entries — conventional-commits-parser, meow — its PRs can NEVER pass npm ci in this workspace; superseded PRs closed manually since its own update job also fails). Issue #50: align @react-router/dev+serve+node (still 7.15.0) with the v8 runtime — Scott assigning to another agent. Dependabot #48 (morgan) left open.

## Phase 2 (SMS) — pre-merge state (historical)

PR #35 (feat/sms-auth, 11 commits `8bf3dfe`..`554206a`), awaiting Scott's merge (merge commit, NO squash).

**Examples consolidated (Scott's call via AskUserQuestion, 2026-08-01):** ONE example app (`examples/react-router`) hosts email + SMS side by side — tabbed login (`?via=sms`; Referer-based provider redirect preserves the tab through `?sent=1`), phone input with FIXED `+1` prefix (visible national-number input + hidden composed E.164 field), per-channel capture transports (`capture-email-transport` / `capture-sms-transport`), merged `/e2e/otp-code` (`?email=`/`?phone=`), single 19-spec e2e suite, `sms-example-e2e` CI job removed. `examples/react-router-sms` DELETED. `setup-twilio.mts` moved to `infra/twilio/` (arg = .env target path, defaults to the example). User metadata key is now generic `identifier` (was `email`). Phase 3 passkeys extends this same app. Commits `243169e` (merge) + `554206a` (docs/script home). Releases on merge: auth 2.1.0, email-provider + adapter peer-dep patches, first releases of auth-provider-sms + auth-sms-twilio (0.0.0 → verify tooling bumps to 0.1.0).

**AWS transport parked (Scott's call, 2026-08-01):** untested against live AWS (sandbox exit + separate 10DLC — not worth doing now). Removed from #35 by commit `aaf7b36`; lives on branch `feat/sms-aws` (revert of parking commit), draft PR #37 (base feat/sms-auth, auto-retargets to main after #35 merges), help-wanted issue #36 with verification checklist, snapshot tag `archive/sms-aws-v1`. Merge criteria: someone runs setup-aws.mts → real text → sign-in, reports on PR.

## Phase 2 build details (now committed)

All code complete and validated: 152 unit tests (76 auth / 24 email / 26 sms / 5 twilio / 3 aws / 18 adapter), 10/10 email e2e, 11/11 sms e2e, build+typecheck+prettier clean. **Commits blocked: 1Password locked → SSH signing fails ("1Password: failed to fill whole buffer"). SSH push/fetch also blocked (worked around fetch via https).**

What was built (working tree, branch `feat/sms-auth` based on origin/main `ade8601`):

- **Core** (`packages/auth`): `verifyOtpChallenge` + `constantTimeEqual` exports in otp.ts; NEW `provider-util.ts` (parseRequestBody, isBrowserFormPost, buildReturnUrl, buildChallengeCookie/ClearingCookie, readCookie, parseDuration, authenticateWithIdentifier); session-manager uses parseDuration; +25 tests.
- **Email provider**: refactored onto shared core helpers (−~200 lines of privates), peerDeps `^2.1.0` (was `^0.1.1` — PUBLISHED BUG: 1.0.0 on npm ERESOLVEs vs core 2.0.0). Adapter peerDep → `^2.0.0` too.
- **NEW `packages/auth-provider-sms`** (zero deps): SmsProvider (E.164 normalize `normalizePhoneNumber`, challenge type "sms", cookie `auth_sms_challenge`, WebOTP last line via `webOtpDomain`, messageTemplate), ConsoleTransport.
- **NEW `packages/auth-sms-twilio`**: raw-fetch Messages API, Basic auth, From/MessagingServiceSid (RCS via Messaging Service), injectable fetch.
- **NEW `packages/auth-sms-aws`**: @aws-sdk/client-pinpoint-sms-voice-v2 SendTextMessageCommand TRANSACTIONAL, `PinpointSmsClientLike` for tests.
- **NEW `examples/react-router-sms`**: phone→code login, SMS_TRANSPORT=console|twilio|aws switch, capture transport + /e2e/otp-code?phone= readback (secret env `E2E_SECRET`, default "e2e_test_secret"), port 3201 e2e (forces SMS_TRANSPORT=console), interactive `scripts/setup-twilio.mts` + `setup-aws.mts` (executable, `#!/usr/bin/env node`, run via Node type stripping — no tsx; verify creds, pick/buy number or list AWS origination identities, write .env, print manual checklist). Root `.nvmrc` pins Node 22 (type stripping default-on ≥ 22.18).
- **Cross-cutting**: workspaces +5 entries, commitlint scope-enum +3, release.ts tag map +3, ci.yaml `sms-example-e2e` job + release needs it; root README (Features SMS ✅, Packages +3 rows, Try-the-example SMS mention); package READMEs for all 3 new packages.

## Scott's live Twilio test (2026-07-31 → 08-01)

Real-world run of `setup-twilio.mts` surfaced issues, all fixed in working tree:

- Scripts converted `.ts`→`.mts`, shebang `#!/usr/bin/env node` (Node type stripping, default-on ≥22.18 — Scott hit `env: tsx: No such file or directory`). tsx removed from sms example devDeps. Root `.nvmrc` = `22` (even/LTS per Scott).
- Auth token prompt now masked (`questionHidden`: raw mode BEFORE prompt — echo race found via expect test; strips bracketed-paste/CSI escapes; warns when input isn't 32 hex chars).
- Twilio 401 debugging: error 20003 is deliberately generic — same code for bad creds AND **suspended account (out of funds)**. Scott's account was suspended; notice appears ONLY at https://www.twilio.com/console/projects/summary. After recharge same creds worked. Hint baked into script 401 path + adapter README.
- Carrier filtering: API accepts message, carriers filter silently; only visible in delivery log https://console.twilio.com/us1/monitor/logs/sms (Scott's test text: warning 30034 = unregistered A2P 10DLC). Link now in 6 places: transport error output (+ exported `TWILIO_DELIVERY_LOG_URL`), adapter README, setup script checklist, example startup log, `.env.example`, example README.
- Scott completed A2P 10DLC registration in console (2026-08-01), but campaign review "may take 2-3 weeks". Decision: merge without waiting. Verified end of our chain: delivery log shows the expected message body (form → provider → TwilioTransport → API accepted) — only the carrier hop is pending campaign approval.
- Scott's secondary auth token appeared in transcript/screenshot during debugging — REMIND HIM to rotate/delete it after testing.
- Noted for future: managed verification APIs (Twilio Verify, Prelude) skip 10DLC entirely but generate/check codes themselves — would be a separate provider package (delegated verification), not an SmsTransport. Possible post-Phase-3 addition.

Planned commit series (per scope, in order): 1) feat(auth) provider utils; 2) fix(auth-provider-email) shared helpers + peer bump; 3) fix(auth-adapter-react-router) peer bump; 4) feat(auth-provider-sms) incl. commitlint/release.ts/workspaces; 5) feat(auth-sms-twilio); 6) feat(auth-sms-aws); 7) feat(examples) sms example + ci job; 8) docs root readme. New packages start at version 0.0.0 — VERIFY first release bumps them to 0.1.0 (simple-release behavior for tag-less packages).

## Current state

**Phase 1 MERGED AND RELEASED (2026-07-31).** PR #32 merged to main (merge commit `afe3238`, no squash); release run 30654867216 published `@activescott/auth@1.0.0`, `@activescott/auth-provider-email@1.0.0`, `@activescott/auth-adapter-react-router@1.0.0` to npm (breaking commits bumped all three 0.x → 1.0.0). Local main synced to `f36371d`, feature branch deleted. Next up: Phase 2 (SMS) on Scott's go-ahead.

Late Phase-1 additions (after v2): env-driven SMTP in the example (`SMTP_HOST` set → real send, unset → console dev mode; dotenv loaded in vite.config.ts, dev-server only — `npm start`/e2e never load .env), `.env.example` + `.env.example.mailpit` + `.env.example.smtp` templates, root README "Try the example" section (Mailpit workflow).

Scott tested v1 locally, approved, then drove three follow-on decisions: required challengeStore, challenge-backed links + confirm interstitial, forms-post-to-auth-routes.

Key v2 commits (after the original v1 series `ce8c5e2`..`4f4aa9d`):

- `1eeffff` feat(auth)!: require challengeStore; verify may return Response
- `c83eaa5` feat(auth-provider-email)!: challenge-backed single-use links + confirm page; no more magicLinkSecret/jsonwebtoken; codes always on
- `d4bad63` feat(auth-adapter-react-router)!: Response passthrough; sendMagicLink removed
- `934e80a` feat(examples): forms post to auth routes; confirm/scanner/single-use e2e
- `103c841` / `5368762` docs: OAuth removed from comments; README scope principle ("direct auth only, not OAuth-federation") + scanner-proof-links feature section

Validation: 93 unit tests green (51 auth / 24 email / 18 adapter), 10/10 e2e, lint clean. PR body carries the no-squash warning and the ramblefeed/tinkerbell migration checklist.

## Quick commands to resume/test

```bash
git checkout feat/auth-challenge-store-otp
npm ci && npm run build && npm run typecheck && npm test
npm run e2e -w examples/react-router/tests   # 10 specs
npm run dev --workspace=examples/react-router # then http://localhost:5173/login
```

Manual test script: login page → enter email → submit → code form appears; code + magic link printed in the terminal running dev server; enter code → /dashboard. Wrong code → redirected to /login?error=INVALID_CREDENTIALS. Magic link from console still works.

## Key implementation facts (v2)

- One challenge per send: `{type: "email", identifier, hashedCode (OTP), data.hashedKey (link key), data.redirectTo?, maxAttempts, expiresAt}`. Both link and code redeem it; single-use delete on either.
- Link: `/auth/email/verify?challenge=<uuid>&key=<base64url 256-bit>`. GET → confirm page (validates, does NOT consume); POST {challenge, key} → redeem. Key attempts don't count vs maxAttempts (256-bit).
- Code: POST {code} + `auth_challenge` cookie (`Path=/auth; HttpOnly; SameSite=Lax; Max-Age=<expiry>`; no `__Host-` — needs Path=/). incrementAttempts BEFORE compare; cap → RATE_LIMITED.
- Hash: `SHA-256("${challengeId}:${secret}")` hex (both code and link key; challenge id is salt); constant-time compare.
- Initiate browser-form detection: urlencoded content-type + Accept contains text/html → 302 to Referer w/ ?sent=1 or ?error=<code> + cookie; else AuthInitResult JSON + setCookies.
- User/identity upsert in `EmailProvider.authenticateEmail()` — identity-merge link-mode branches there later; SMS mirrors this shape.
- Adapter `redirect()` bug (Object.fromEntries collapsed duplicate Set-Cookie) fixed in c92f851.
- e2e readback: `GET /e2e/otp-code?email=...` + `x-e2e-secret` header, gated on `E2E_TEST_MODE=true` (playwright.config). Capture keyed per-recipient (parallel-safe). `tests/helpers/auth.ts#loginAs` drives link+confirm UI flow.
- Confirm-page HTML rendered inline by the provider (template appName/primaryColor); scanner rationale documented in root README + plan.md v2 section.

## Gotchas discovered

- commitlint: subject must not be sentence-case — "OTP code entry" rejected; use lowercase ("add otp code entry").
- Multi-scope branch must NOT be squash-merged — release tooling derives per-package bumps from per-scope commits. Merge with merge commit or rebase-merge.
- `scripts/release.ts` tag-prefix map + commitlint scope-enum are hardcoded; MUST be extended for every new package in Phases 2-3 or publishing silently skips them.
- vitest resolves workspace deps via built `dist/` — build `packages/auth` before running provider tests after core changes.

## Next steps

1. ~~Phase 1 (email magic links + OTP)~~ DONE, released.
2. ~~Phase 2 (SMS)~~ DONE, released (see recovery notes above).
3. **Phase 3 (passkeys) — NEXT**: see the "PHASE 3 HANDOFF" section at the top of this file and plan.md's Phase 3 section.

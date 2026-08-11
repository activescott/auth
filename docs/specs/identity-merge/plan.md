# Plan: Identity linking + account merge (issue #70)

Implements [activescott/auth#70](https://github.com/activescott/auth/issues/70)
following the design already sketched in [spec.md](./spec.md): a link mode on
the OTP providers' existing initiate/verify flows, a typed conflict when the
identifier belongs to another user, and `Auth.mergeUsers` to resolve the
conflict after possession is proven.

## Decisions (resolving the spec's open points)

- **Link mode is a request flag, not new endpoints.** `mode: "link"` in the
  initiate body rides the existing `/auth/{provider}/initiate` +
  `/auth/{provider}/verify` routes, so the core abuse guard and per-identifier
  rate limits apply unchanged (the issue requires parity with sign-in
  initiate). At verify time the mode comes from the stored challenge
  (`data.linkUserId`), never from the client, so a sign-in challenge cannot be
  replayed as a link or vice versa. The issue's suggested
  `/auth/:provider/link/*` adapter routes are unnecessary: session gating
  lives in the provider via `context.getSession`, exactly how passkey
  registration is gated today.
- **Conflict → merge is two-phase with a server-side ticket.** The OTP is
  consumed proving possession, so the conflict response mints a short-lived
  single-use "merge ticket" challenge (type `account-merge`, 10 minutes)
  bound to the browser with an HttpOnly cookie, and returns error code
  `IDENTITY_CONFLICT` (HTTP 409). The app prompts the user; confirming POSTs
  `/auth/{provider}/link-merge`, which redeems the ticket, re-checks the
  session, and calls `Auth.mergeUsers`. No silent takeover: merge requires an
  authenticated session for user A **and** fresh OTP possession proof of
  user B's identifier in the same browser.
- **No identifier enumeration.** Initiate in link mode behaves exactly like
  sign-in initiate; whether the identifier belongs to another account is only
  revealed after the OTP round trip proves possession.
- **Unlinking is out of scope.** Tracked in a follow-up issue (with the
  last-identity guard noted).

## Changes by package

### `packages/auth` (core)

- `types.ts`
  - `IdentityStore.reassignByUserId?(fromUserId, toUserId)` — optional, bulk
    reassignment; merge is unavailable (configuration error) without it.
  - `UserStore.onMerge?(fromUser, intoUser)` — optional hook where the app
    migrates/deletes its own data keyed by the absorbed user id. The library
    never deletes user rows.
  - `AuthFailure.setCookies?` — failures can now carry cookies (the merge
    ticket rides the conflict response).
  - `MergeResult` — `{ fromUserId, intoUserId, movedIdentities }`.
  - New error code `IDENTITY_CONFLICT`.
- `errors.ts` — `AuthErrors.identityConflict`, message, 409 mapping in
  `Auth.errorToResponse`.
- `provider-util.ts` — `completeLinkVerification(providerId, identifier,
linkUserId, request, context)`: shared post-OTP link path for both
  providers. Re-checks the session (must match `linkUserId`), then:
  - no existing identity → create it for the session user → success;
  - identity already on the session user → touch `verifiedAt` → success
    (idempotent);
  - identity on another user → mint merge ticket + `IDENTITY_CONFLICT`.
- `auth.ts`
  - `mergeUsers(fromUserId, intoUserId)` — public API per spec: snapshot the
    absorbed user's identities, `reassignByUserId`, then `onMerge`.
  - `handleRequest` handles action `link-merge` generically for any provider:
    validate ticket (type, expiry, attempts, single-use) + session must be
    the ticket's `intoUserId`, then `mergeUsers`. Browser form posts get a
    302 back to the submitting page with `?merged=1`; fetch callers get JSON.
  - Failure responses append `setCookies`.

### `packages/auth-provider-email`, `packages/auth-provider-sms`

- `initiate`: `mode: "link"` requires a session (401-style failure without
  one) and stamps `linkUserId` into the challenge `data`. Everything else —
  abuse checks, challenge cookie, message content — is identical to sign-in.
- `verify`: after the existing challenge redemption succeeds, a challenge
  carrying `linkUserId` routes to `completeLinkVerification` instead of
  `authenticateWithIdentifier`. Applies to both email redemption paths
  (magic link and code) and both SMS transports (own-code and vendor
  verification).
- Email confirm page says "link" instead of "sign in" when the challenge is a
  link challenge.

### `packages/auth-adapter-react-router`

- `handleAuth`: append `result.setCookies` on the failure redirect (carries
  the merge ticket cookie). Success path unchanged — a successful link
  re-issues the session cookie against the newly linked identity and follows
  the normal `redirectTo`/`successRedirect` logic, so apps steer the return
  page by passing `redirectTo` at initiate.
- `link-merge` needs no adapter code: it is not a verify action, so the
  catch-all already forwards it to `auth.handleRequest`.

### `examples/react-router`

- Stores: implement `reassignByUserId`; `onMerge` deletes the absorbed user
  row.
- Dashboard: "Sign-in methods" section listing the user's identities with
  add-email / add-phone forms (`mode=link` hidden field), a code entry step,
  and a merge-confirmation prompt when the flow returns
  `?error=IDENTITY_CONFLICT`.

### Tests

- Core: `completeLinkVerification` (link / idempotent / conflict / session
  mismatch), `mergeUsers` (happy path, missing `reassignByUserId`, missing
  users, `onMerge` invocation), `link-merge` action (ticket validation,
  session binding, single use, form-post redirect vs JSON).
- Email + SMS providers: link initiate without session, challenge stamping,
  link verify happy path, conflict path sets ticket cookie, sign-in flows
  unaffected.
- Adapter: failure redirect carries `setCookies`.
- E2e (Playwright, example app): signed-in user links the other identifier;
  conflict path merges two accounts and signing in with either identifier
  lands on the surviving user.

### Docs & follow-ups

- README: document linking + merge (flows, `mode: "link"`, conflict/merge
  ticket, `reassignByUserId`/`onMerge` contracts, session-death-after-merge
  semantics: the JWT re-checks `userStore.findById` per request, so deleting
  the absorbed user in `onMerge` kills its outstanding sessions).
- Update spec.md status (implemented by #70); write summary.md when done.
- File the unlink follow-up issue (last-identity guard).

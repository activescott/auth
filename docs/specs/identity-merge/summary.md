# Summary: Identity linking + account merge (issue #70)

Implemented on branch `feat/70-identity-linking`. Fixes
[activescott/auth#70](https://github.com/activescott/auth/issues/70); unlink
follow-up filed as
[#71](https://github.com/activescott/auth/issues/71).

## What shipped

- **Link mode on the OTP providers** — `mode: "link"` in the initiate body of
  `/auth/email/initiate` and `/auth/sms/initiate` attaches the verified
  identifier to the signed-in user instead of signing in as it. Session
  required at initiate AND at verify; the link intent lives in the stored
  challenge (`data.linkUserId`), never in client input at verify time. Both
  email redemption paths (magic link, code) and both SMS transports
  (own-code, hosted verification) support it. Abuse guards apply unchanged
  because link rides the normal initiate action.
- **Conflict → merge** — identifier owned by a different user answers
  `IDENTITY_CONFLICT` (409) plus a 10-minute single-use merge-ticket
  challenge (`type: "account-merge"`) bound by HttpOnly cookie
  (`auth_merge_ticket`). `POST /auth/{provider}/link-merge` (handled
  generically in `Auth.handleRequest`) redeems it: ticket + session for the
  surviving user → `Auth.mergeUsers`.
- **`Auth.mergeUsers(fromUserId, intoUserId)`** — public; snapshots the
  absorbed user's identities, calls the new optional
  `IdentityStore.reassignByUserId`, then the new optional
  `UserStore.onMerge(fromUser, intoUser)` where the app migrates its data and
  deletes the absorbed user row (which naturally kills that user's sessions).
- **Plumbing** — `AuthFailure.setCookies` (merge ticket rides the failure);
  react-router adapter forwards failure cookies on the error redirect; new
  error code `IDENTITY_CONFLICT` throughout.
- **Example app** — dashboard "Sign-in methods" section: list, add-email /
  add-phone forms (`?link=email|sms` selects the open form, mirroring the
  login page's `?via=`), merge prompt on conflict, success banners
  (`?linked=1`, `?merged=1`). Stores implement `reassignByUserId`/`onMerge`.
  `CodeForm` gained a `submitLabel` prop; the example `errorRedirect` honors
  `?redirectTo=` on the verify URL so magic-link-confirm errors land on the
  dashboard rather than the confirm page URL.

## Key decisions (vs. the issue's sketch)

- No `/auth/:provider/link/*` adapter routes: link mode is a request flag on
  the existing endpoints, so core abuse guards apply for free and session
  gating lives in the provider via `context.getSession` — the same way
  passkey registration is gated. Rationale in [plan.md](./plan.md).
- Merge confirmation is two-phase (conflict response mints a ticket; a
  second explicit POST redeems it) because the OTP is consumed proving
  possession. One redemption attempt per ticket, success or not.
- The `link-merge` browser-redirect strips the stale `?error=` from the
  return URL so the outcome reads as resolved.

## Verification

- Unit: `npm test` — all workspaces green (core 143, email 34, sms 47,
  adapter 76, others unchanged).
- E2e: `npm run e2e -w examples/react-router/tests` — 32 passed, including
  new `linking.spec.ts` (add phone to email account; conflict → merge
  unifies accounts and either identifier signs in to the survivor; merge
  ticket single-use). Four pre-existing specs needed `.first()` because the
  dashboard now shows the identifier twice (header + methods list).
- If port 3200 is busy (anything already listening makes Playwright reuse
  it), run with `E2E_PORT=<port>`.

## Gotchas for future work

- `IdentityStore.update` cannot change `userId`; merging requires the bulk
  `reassignByUserId`. Without it `mergeUsers` throws CONFIGURATION_ERROR.
- The session cache in `Auth` may serve a pre-merge identity for up to its
  2-minute TTL after a merge; accepted by the spec.
- The merge ticket's `data.provider` must match the `/auth/{provider}/`
  segment it is posted to.

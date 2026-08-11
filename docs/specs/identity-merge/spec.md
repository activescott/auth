# Spec: Merging authenticators/identities into a single user

Status: **implemented** by [issue #70](https://github.com/activescott/auth/issues/70) — see [plan.md](./plan.md) for the decisions made and [summary.md](./summary.md) for what shipped. Originally written ahead of time so the OTP/SMS/passkeys implementation (see `../otp-sms-passkeys/plan.md`) would stay compatible with it; the design below is essentially what landed, with the conflict surfaced as error code `IDENTITY_CONFLICT` plus a single-use merge-ticket cookie rather than a `LinkResult` object, and `reassignByUserId` returning `void` (the moved identities are reported by `Auth.mergeUsers` instead).

## Problem

A person can end up with two separate users in an app: they signed in with their phone number once (user A, identity `sms:+1415...`) and with their email another time (user B, identity `email:alex@...`). They are one person and want one account.

Terminology per the data model (`packages/auth/src/types.ts`): one `AuthUser` has many `Identity` rows. "Merging authenticators" = moving all identities from one user onto another and retiring the emptied user. The identities themselves are not merged; their `userId` changes.

## Requirement

An app can offer: while signed in as user A, the person proves control of another authenticator (email, phone, passkey). If that authenticator's identity belongs to an existing user B, the app may merge B into A — after which signing in with either authenticator lands on user A.

Proof requirement: both authenticators verified in the SAME session. Session already proves the first (it was created by a verified authenticator); the merge flow verifies the second, fresh — no relying on a stale prior verification.

## Design (planned shape, subject to revision when scheduled)

### Two distinct cases at second-authenticator verification time

While a session for user A exists and a second authenticator is verified:

1. **Identity does not exist** → **link**: create identity with `userId = A.id`. No merge needed. (This is the "add email to phone-only account" and "add passkey" case — already planned in the OTP/SMS/passkeys work.)
2. **Identity exists, owned by user B ≠ A** → **merge candidate**: the library must NOT silently log the person into B (current behavior) or silently merge. It should surface the conflict to the app, which decides (typically: prompt "merge these accounts?" then call the merge API).

### New core API (future)

```ts
// on Auth
mergeUsers(fromUserId: string, intoUserId: string): Promise<MergeResult>
```

- Reassigns every identity of `fromUserId` to `intoUserId` (via new optional `IdentityStore.reassignByUserId(fromUserId, toUserId)` — bulk, atomic where the backing store allows).
- Calls new optional `UserStore.onMerge?(from, into)` so the app migrates/deletes its own user row + app data. The library does not delete users; user records are app-owned.
- Existing sessions for `fromUserId`: the JWT carries `userId`; `verifySession` re-checks `userStore.findById` on each request, so once the app deletes/disables user B, B's outstanding sessions die naturally. Document this; no token revocation machinery needed.

### Verification-flow hook (future)

A "link mode" for provider verification: when a session exists and the app requests linking, verify attaches to the session user (case 1) or returns a typed conflict (case 2) instead of creating/logging-in:

```ts
type LinkResult =
  | { status: "linked"; identity: Identity }
  | { status: "conflict"; existingUserId: string; identity: Identity }
```

Likely delivered as an option on verify (e.g. `?mode=link` or context flag) rather than a separate endpoint, so every provider (email, sms, passkey) gets it uniformly.

## Accommodations required in the CURRENT implementation plan

These keep the door open; none add scope now:

1. **`AuthContext.getSession`** (planned for Phase 3/passkeys) is the primitive link/merge needs. Keep it optional on `AuthContext`; do not couple providers to session-less operation in a way that breaks adding it.
2. **Provider verify paths must keep user-lookup/create logic in ONE shared place per provider** (Phase 1 already extracts `authenticateEmail(email, context)` in the email provider; SMS mirrors it). Link-mode later = one branch in that shared function, not N scattered edits.
3. **`IdentityStore` stays additive**: `reassignByUserId` will be a new OPTIONAL method, like `update`/`delete` today. Do not design anything that assumes the identity→user mapping is immutable (e.g., no caching identity.userId beyond the existing 2-minute SessionCache TTL).
4. **Passkey identities must be reassignable like any other**: passkey `CredentialStore` rows reference `userId` too — when merge lands, passkey credentials follow their identity. Keep `userId` (not embedded user data) as the only user linkage in `StoredCredential`.
5. **Docs**: the "require email in addition to phone" pattern (Phase 2 docs) is case 1 (link). Write it so case 2 (conflict) is explicitly called out as "not yet supported — coming as account merge" rather than implying silent behavior.

## Open questions (resolve when scheduled)

- Should `mergeUsers` also merge `Identity.metadata` or leave conflicts to the app? (Lean: app's problem via `onMerge`.)
- Direction UX: always merge newer-into-older, or app chooses? (Lean: app chooses; library is mechanism only.)
- Audit trail: emit a callback/event for compliance logging?

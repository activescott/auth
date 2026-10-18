# Unlinking a sign-in identity: summary

Issue #71, the follow-up to identity linking (#70). A signed-in user can now remove one of their own identities: an email address, a phone number, or a passkey.

## What shipped

- **`Auth.unlinkIdentity(userId, { provider, identifier }, { currentIdentity })`** in core: looks the identity up among the user's own (so another user's identity reads as `IDENTITY_NOT_FOUND`, never as "not yours"), applies the guards below, then `IdentityStore.delete`.
- **`POST /auth/{provider}/unlink`**, served for every provider the way `link-merge` is. Session required; the body carries `identifier`; the provider comes from the path, so a form for one provider cannot remove another's identity. Browser form posts redirect back with `?removed={provider}` or `?removeError={code}&provider={provider}`; JSON callers get `{ success: true }` or the error. Through the react-router adapter's `handleAuth` it sits behind the same Origin check as every other auth route.
- **Two error codes**, both HTTP 409: `LAST_SIGN_IN_METHOD` and `IDENTITY_IN_USE`.
- **Adapter**: `profileAuthLoader` returns `removal`, parsed from those query parameters; `allowRemove` on `ProfilePage`, `SignInMethods` and `Passkeys` adds a Remove button per row (new `removeButton` slot), and each block reports only its own provider's outcome.
- **Example app**: Remove buttons on the dashboard's sign-in methods and passkeys, covered by `unlinking.spec.ts`.

## Decisions

- **Passkeys do not count as a way back in.** The account must keep at least one identity of a configured provider, and if the identity being removed is not a passkey, at least one of the remaining identities must not be a passkey either. A passkey lives on one authenticator; an account whose only identities are passkeys is stranded when the device is lost. Passkeys themselves can always be removed while an email address or phone number remains, and an account that is already passkey-only may remove all but its last passkey. Identities of providers that are no longer configured do not count, since nothing can sign in with them.
- **The session's own identity cannot be removed** (`IDENTITY_IN_USE`). Removing it would end the session in the middle of the request, and it means the remaining set always contains at least the identity the user just proved.
- **No re-verification.** Linking needs a fresh possession proof because it grants access; removal grants none. With the two guards above, the worst a stolen session can do is remove the victim's other methods, never the one the attacker is using or the last recoverable one.
- **Concurrent removals.** Two sessions of one user could each remove the other's identity, each passing the check against a row the other is deleting. After deleting, the check runs again against the store; a removal that now strands the account recreates its identity (same provider, identifier and provider state, new id; sessions bind by provider and identifier, so they keep working) and refuses.
- **Other sessions end on their next request.** Session verification looks the session's identity up on every uncached request; unlinking clears the session cache so sessions that signed in with the removed identity do not survive for the cache TTL.
- **`allowRemove` is off by default**, like `allowMerge`, so upgrading the adapter alone never shows a button that posts to an endpoint an older core does not serve.

## Not included

- The browser's copy of a removed passkey stays in the device's password manager; the confirmation tells the user to delete it there. WebAuthn's `signalUnknownCredential` could do this automatically and is left for later.
- `auth-store-prisma` needed no change: `IdentityStore.delete` was already part of the contract.

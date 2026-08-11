# Plan: v5 breaking cleanup

With few consumers, a major bump is at its cheapest — this release fixes the
design warts identified while implementing identity linking (#70) rather
than carrying them forward. Decisions and rationale:

1. **`IdentityStore.delete`, `IdentityStore.reassignByUserId`, and
   `UserStore.onMerge` become required.** Each is a few lines to implement.
   Optional capability methods are reserved for operations with real cost or
   policy weight (`listUsers` — user enumeration a store may refuse;
   `findByUserIds` — pure optimization with a fallback). Cheap mechanics as
   optional methods just convert compile-time type errors into runtime
   `CONFIGURATION_ERROR`s discovered mid-flow. `onMerge` required also means
   disposing of the absorbed user is an explicit decision, not silent
   orphaning.
2. **`Identity.metadata` → `Identity.providerState`.** Same name as
   `AuthUser.metadata` but the opposite contract (provider-owned, opaque,
   sensitive vs. app-facing display grab-bag) — the docs spent paragraphs
   compensating. Only possible in a major.
3. **Route-table dispatch.** `getRoutes()` already declared handler kinds
   but `handleRequest` string-matched action names (`initiate|send`,
   `verify|callback`), which is why the `send`/`callback` aliases existed
   and why the abuse guard keyed off action names. Now dispatch and the
   abuse-guard decision come from the declared table; a new `"action"`
   handler kind covers `handleAction` routes (the passkey ceremonies, which
   must not hit the form-token bot check). Method mismatches are 405,
   undeclared paths 404. `canHandle`/`findProvider` deleted — routing is the
   path segment plus the table.
4. **Verify responders.** The react-router adapter used to regex the action
   name, bypass `Auth.handleRequest`, and call `provider.verify` itself to
   inject session-cookie-plus-redirect handling — two dispatch paths to keep
   in sync (the `link-merge` action only worked because its name doesn't
   equal "verify"). `handleRequest(request, { onSuccess, onFailure })` moves
   the hook into core; the adapter is now a thin wrapper.

Out of scope, deliberately unchanged: `AuthResult | Response` union returns
(the confirm-page escape hatch), the challenge model, session JWT design,
package split, `onLogin`/`listUsers`/`findByUserIds` staying optional.

Migration guide: [migration.md](./migration.md) (also the release notes of
the PR). Validation: the guide was executed against ramblefeed (the
library's production consumer) before release.

# Migrating to @activescott/auth v5

v5 is a breaking release of the whole package family. Upgrade every
`@activescott/auth*` package together:

| Package                                  | v4-era version | v5-era version |
| ---------------------------------------- | -------------- | -------------- |
| `@activescott/auth`                      | 4.x            | 5.x            |
| `@activescott/auth-provider-email`       | 2.x            | 3.x            |
| `@activescott/auth-provider-sms`         | 1.x            | 2.x            |
| `@activescott/auth-provider-passkey`     | 1.x            | 2.x            |
| `@activescott/auth-adapter-react-router` | 1.x            | 2.x            |
| `@activescott/auth-sms-twilio`           | unchanged      | unchanged      |
| `@activescott/auth-botcheck-turnstile`   | unchanged      | unchanged      |

No data migration is required — every change is in the TypeScript API.
Your database schema, cookie formats, session JWTs, and challenge rows are
all unaffected; outstanding sessions survive the upgrade.

## 1. Rename `Identity.metadata` → `Identity.providerState`

The field always held provider-owned state (passkey public keys, signature
counters) and was frequently confused with the app-facing
`AuthUser.metadata`, which keeps its name and meaning.

In your `IdentityStore` implementation:

- the `Identity` objects you return: `metadata` → `providerState`
- `create(data)`: reads `data.providerState` instead of `data.metadata`
- `update(id, data)`: may receive `providerState` instead of `metadata`

Your **database column can keep its name** — map it in the store:

```ts
// before                              // after
return {                               return {
  ...row,                               ...row,
  metadata: row.metadata,               providerState: row.metadata, // column unchanged
}                                      }
```

If you passed `Identity` values elsewhere in your app (rare — the field is
documented as opaque), rename those reads too. The passkey helper
`parsePasskeyCredentialMetadata` keeps its name; feed it
`identity.providerState` now.

## 2. Implement three newly-required store methods

All three were optional in 4.x. Each is a few lines; making them required
turns a runtime `CONFIGURATION_ERROR` (or silently missing behavior) into a
compile-time type error.

```ts
const identityStore: IdentityStore = {
  // ...existing methods...

  // NEW REQUIRED: delete one identity
  async delete(id) {
    await sql`DELETE FROM identities WHERE id = ${id}`
  },

  // NEW REQUIRED: bulk-move identities between users (account merge)
  async reassignByUserId(fromUserId, toUserId) {
    await sql`UPDATE identities SET user_id = ${toUserId} WHERE user_id = ${fromUserId}`
  },
}

const userStore: UserStore = {
  // ...existing methods...

  // NEW REQUIRED: called by Auth.mergeUsers after identities move.
  // Migrate app data keyed by the absorbed user id, then dispose of the
  // user record — the library never deletes user rows. An empty body is a
  // valid choice if your app will never enable merging; the requirement
  // exists so that's an explicit decision, not an accident.
  async onMerge(fromUser, intoUser) {
    await moveAppDataOwnedBy(fromUser.id, intoUser.id)
    await sql`DELETE FROM users WHERE id = ${fromUser.id}`
  },
}
```

`StoresDescription.capabilities` no longer reports `deleteIdentity`
(it is always available now); the admin config page row is gone.

## 3. Route dispatch is now strict (URL surface changes)

`Auth.handleRequest` dispatches only method+path pairs each provider
declares in `getRoutes()`. Consequences:

- **Removed alias endpoints answer 404** — update anything that posts to
  them:
  - `POST /auth/email/send` → use `POST /auth/email/initiate`
  - `GET /auth/email/callback` → use `GET /auth/email/verify`
- **Method mismatches answer 405** instead of being served (e.g. `GET
/auth/sms/initiate` was previously dispatched; it is now 405).
- **Custom providers**: your `getRoutes()` table must be complete and
  accurate — an undeclared path is unreachable. The route's `handler` kind
  picks the entry point: `"initiate"` (abuse guard runs first, then
  `initiate`), `"verify"` (feeds the adapter's session/redirect flow), or
  the new `"action"` (calls `handleAction`; no abuse guard). Declare
  anything that sends mail/SMS to a user-supplied address as `"initiate"`.
- `AuthProvider.canHandle` and `Auth.findProvider` are removed — routing is
  by the `/auth/{providerId}/...` path segment plus the route table. Delete
  your `canHandle` implementation.

## 4. Adapter authors: verify handling moved into core

`Auth.handleRequest(request, responders?)` accepts optional
`{ onSuccess, onFailure }` hooks that turn a verify outcome into your
response (session cookie + redirect, error redirect). The react-router
adapter now works this way; if you wrote a custom adapter that re-implements
provider lookup and calls `provider.verify` itself, replace that with:

```ts
return auth.handleRequest(request, {
  onSuccess: async (result, request) => {
    const cookie = await auth.createSessionCookie(result.user, result.identity)
    // append result.setCookies, redirect wherever your app goes next
  },
  onFailure: async (failure, request) => {
    // append failure.setCookies (e.g. the IDENTITY_CONFLICT merge ticket)
    // and redirect to your error page
  },
})
```

Providers that answer with a `Response` directly (the email confirm page,
passkey JSON) bypass the responders, as do initiate results.

Users of `createAuthHandlers` (the shipped react-router adapter) need **no
code change** for this item — its behavior is unchanged.

## 5. Passkey endpoints: no behavior change, one declaration change

The four passkey actions are now declared `handler: "action"` routes. URLs,
request/response shapes, and (lack of) abuse-guard behavior are identical to
4.x — this only matters if you had tooling reading `getRoutes()`.

## Checklist

1. Bump all `@activescott/auth*` packages to the v5-era majors together.
2. In `IdentityStore`: rename the `metadata` field/params to
   `providerState`; add `delete` and `reassignByUserId`.
3. In `UserStore`: add `onMerge`.
4. Grep your app for `/auth/email/send` and `/auth/email/callback`; point
   them at `initiate`/`verify`.
5. Custom providers only: delete `canHandle`, audit `getRoutes()` for
   completeness, declare extra actions with `handler: "action"`.
6. Custom adapters only: switch to `handleRequest` responders.
7. Run your type checker — items 2–3 and most of 1 surface as type errors,
   which is the point.

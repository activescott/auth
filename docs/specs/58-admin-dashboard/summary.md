# Admin dashboard — implementation summary

Issue #58. See [plan.md](./plan.md) for the task breakdown and
[spec.md](./spec.md) for why each decision went the way it did.

## What shipped

Two read-only pages — **Users** and **Configuration** — split across a
framework-agnostic data layer in core and React components in the React Router
adapter.

### `packages/auth` (breaking → `feat(auth)!`)

- `UserStore.listUsers?(options)` and `IdentityStore.findByUserIds?(userIds)` —
  both optional, so existing store implementations keep compiling.
- `AuthProvider.describe(): ProviderDescription` — **required**. This is the
  breaking change: every `AuthProvider`, including any third-party one, must
  add it.
- `Auth.getStores()` and `Auth.describeConfig()`. The latter is built field by
  field so a field added to `AuthConfig` later cannot leak by default.
- `AbuseGuard.describe()` — resolves the defaults that `AbuseConfig` leaves
  undefined, so the page can show the limits actually in force.
- New `src/admin/admin-data.ts`, exported at the `@activescott/auth/admin`
  subpath: `createAdminData(auth)` → `{ listUsers, describeConfig }`, plus
  `AdminUserRow` / `AdminIdentityRow` / `AdminNotSupportedError`.

### Providers (breaking → `feat(auth-provider-*)!`)

`describe()` on email, SMS, and passkey. Each omits its own secrets — SMTP
password and user, Twilio credentials (only the transport's class name is
reported), passkey `challengeSecret` — and each has a test asserting those
values do not appear in the output.

### `packages/auth-adapter-react-router` (`feat`)

New `./admin` subpath so the main entry stays React-free; `react` is an
**optional** peer dependency. `tsconfig` gained `jsx: react-jsx` and `DOM`.

- `createAdminHandlers(auth, options)` → `{ requireAdmin, adminUsersLoader, adminConfigLoader }`
- `AdminUsersPage`, `AdminConfigPage`, `AdminLayout`
- Allowlist gate reading `AUTH_ADMIN_IDENTIFIERS` by default, matching against
  every identity a user owns, failing closed, answering 404.
- Still imports nothing from `react-router` — links go through an optional
  `linkComponent` prop — so one build serves v7 and v8.

### `examples/react-router` (`feat(examples)`)

In-memory `listUsers`/`findByUserIds`, `createAdminHandlers`, two ~15-line
route files, `AUTH_ADMIN_IDENTIFIERS` in `.env.example`, and
`tests/admin.spec.ts`.

### ramblefeed (separate repository, separate PR)

`admin.users.tsx` went from 231 lines to 46. All nine existing columns are
preserved by mapping the existing `listAllWithStats` aggregate into each user's
`metadata`; `noteCount desc` is still the default sort; Bootstrap classes are
supplied through `classNames` with `includeDefaultStyles={false}`. New: an
Identities column and a `/admin/config` page. `routes/admin.tsx`,
`api.admin.backfill-og.ts`, and `auth-utils.ts:requireAdmin` are unchanged.

## Verification

```bash
# repo root
npm run build && npm run typecheck && npm test && npm run lint

# e2e (packages must be built first). E2E_PORT is new: Playwright's
# reuseExistingServer will otherwise drive whatever else owns port 3200,
# and the failures look like application bugs.
E2E_PORT=3277 npm run e2e -w examples/react-router/tests
```

Result at time of writing: 304 unit tests and 28 Playwright tests pass, lint
and typecheck clean.

Two failures worth remembering, because both looked like product bugs:

- **Port 3200 reuse.** A container serving a different app was listening;
  Playwright reused it and 27 tests failed with confusing assertions (a
  redirect to `/start`, which is not a route in this app). Hence `E2E_PORT`.
- **Per-identifier abuse limit.** Five admin tests signing in as the same
  address hit the 3-per-hour limit; a blocked initiate is deliberately
  indistinguishable from a sent one, so it surfaced as a missing magic link.
  The suite now uses one allowlisted address per test that signs in.

## Where ramblefeed stands

Typecheck, build, and lint pass **against locally built copies of the packages
copied into `node_modules`**. Its e2e suite and Docker build cannot run until
the auth packages are published: `packages/web-app/package.json` now requires
`@activescott/auth@^4.0.0`, `@activescott/auth-adapter-react-router@^2.0.0`,
and `@activescott/auth-provider-email@^2.0.0`, none of which exist on npm yet.
Its `tests/e2e/tests/admin-users-sort.spec.ts` was extended but has not been
executed.

Sequence: land and publish commits 1–4 in this repository together (core alone
leaves the providers failing typecheck, since `describe()` is required), then
the adapter and example, then open the ramblefeed PR.

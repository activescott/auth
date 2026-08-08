# Issue #58 — Admin dashboard for `@activescott/auth`

## Context

Every app built on this library re-implements the same admin page: "who are my
users, how did they sign in, when did they last log in, and what is my auth
config actually set to?" ramblefeed wrote 231 lines of `admin.users.tsx` plus a
`requireAdmin` helper to get that. The goal of #58 is that any consuming app
gets a useful, read-only `/admin/users` page essentially for free.

Two facts shape the whole design:

1. **The library owns no database.** `UserStore` today is `findById` + `create`;
   there is no enumerate/list/count anywhere (`packages/auth/src/types.ts:167`).
   So the library cannot produce user rows on its own — it needs a new _optional_
   store method the app implements, and it must degrade gracefully when absent.
2. **Only `Identity` carries timestamps.** `AuthUser` is `{ id, metadata? }`.
   `Identity` has `createdAt` and `verifiedAt`, and `verifiedAt` is rewritten on
   every successful auth (`packages/auth/src/provider-util.ts:209`), so it is a
   genuine "last used" value. There is no session store, so there is no active-
   sessions view to build — identities are the data we actually have.

Scope for v1 is read-only, per the issue. Two pages: **Users** and **Config**.

## Design decisions (settled)

- **Data layer in core**, exposed at a new `@activescott/auth/admin` subpath —
  framework-agnostic, still zero runtime deps. **React UI + authorization in
  `auth-adapter-react-router`**, at a new `./admin` subpath so apps that don't
  use admin never load React-dependent code. No new package, so no
  `commitlint.config.js` / `scripts/release.ts` plumbing.
- **React is fine in the adapter.** `react-router@8` peers `react >=19.2.7`
  (v7 peers `>=18`), so every consuming app already has React. Preserve the
  adapter's current "imports nothing from `react-router`" property (that is why
  one build serves v7 and v8): components emit plain `<a href>` and accept an
  optional `linkComponent` prop so apps can pass `Link` for client-side nav.
- **App-specific columns ride on `AuthUser.metadata`** — no `extraColumns` data
  API. `sortBy` passes through to the store as an opaque string, so the store
  owns the sort whitelist.
- **Styling:** components ship a prefixed default `<style>` block so the page
  looks decent with zero config, plus a `classNames` override map so ramblefeed
  can pass Bootstrap classes.
- **Non-admins get 404**, not 403 — matches ramblefeed's existing behavior
  (`packages/web-app/app/lib/auth-utils.ts`), hides the area's existence.

---

## 1. Core — `packages/auth`

### `src/types.ts` — optional store methods (non-breaking, `feat(auth)`)

```ts
export interface ListUsersOptions {
  limit: number
  offset: number
  /** Opaque to the library; the store owns the whitelist of accepted fields. */
  sortBy?: string
  sortOrder?: "asc" | "desc"
}
export interface ListUsersResult {
  users: AuthUser[]
  total: number
}
```

- `UserStore.listUsers?(options: ListUsersOptions): Promise<ListUsersResult>`
- `IdentityStore.findByUserIds?(userIds: string[]): Promise<Identity[]>` —
  batched, so the users page is 2 queries not N+1. Fall back to looping the
  existing `findByUserId` when absent.

### `src/types.ts` — provider introspection (**breaking**)

```ts
export interface ProviderDescription {
  settings: Record<string, string | number | boolean | null>
}
```

`AuthProvider.describe(): ProviderDescription` — **required**, not optional. This
is a breaking change to the library's documented extension point (README's "how
to implement a custom `AuthProvider`"), so:

- core releases as `feat(auth)!` → major bump (3.x → 4.0)
- all three provider packages must implement it in the same cycle, and their
  `@activescott/auth` peer range bumps to `^4` → each is also `feat(...)!`
- ramblefeed's upgrade becomes a major-version bump, not a patch
- any third-party `AuthProvider` fails to typecheck until it adds `describe()`

Document the migration in each package's release notes: it is a one-method add
returning `{ settings: {} }` at minimum.

### `src/auth.ts` — accessors

- `getStores(): { userStore, identityStore, challengeStore }`. `createContext()`
  (`auth.ts:305`) already exposes both stores, but requires a `Request`.
- `describeConfig(): AuthConfigDescription` — a redacted, serializable snapshot.
  **Do not** build it from `getSessionConfig()` (`auth.ts:297`), which returns the
  raw secret. Emits: cookie name/`maxAge`/`issuer`/`audience`/cookie flags,
  `secret: "<redacted>"` + `additionalSecretCount`, resolved `abuse` settings
  (defaults live in `abuse/abuse-guard.ts:19-28`, not on the config object when
  unset), bot-check ids, and store class names.

### New `src/admin/admin-data.ts` → `@activescott/auth/admin`

```ts
export interface AdminIdentityRow {
  id: string
  provider: string
  identifier: string
  createdAt: string // ISO — crosses the loader JSON boundary
  verifiedAt?: string // last successful auth for this identity
  lastUsedAt?: string // passkey providers write this into metadata
}
export interface AdminUserRow {
  id: string
  metadata: Record<string, unknown>
  identities: AdminIdentityRow[]
  createdAt?: string // min(identity.createdAt)
  lastLoginAt?: string // max(identity.verifiedAt)
}
export function createAdminData(auth: Auth): {
  listUsers(
    opts: ListUsersOptions,
  ): Promise<{ users: AdminUserRow[]; total: number }>
  describeConfig(): AuthConfigDescription
}
```

`listUsers` throws a message naming `UserStore.listUsers` and linking the docs
when the store doesn't implement it. **Never** copy raw `Identity.metadata` into
`AdminIdentityRow` — it is documented as possibly sensitive
(`types.ts:30-39`; passkey public keys live there). Only derive `lastUsedAt`
(see `packages/auth-provider-passkey/src/credential-metadata.ts:34`).

Add `"./admin"` to the `exports` map in `packages/auth/package.json:5`, matching
the `./testing` / `./browser` precedent in sibling packages.

## 2. Providers — implement `describe()` (required)

Each keeps its own `private readonly config` and decides what it reveals:

- `packages/auth-provider-email/src/email-provider.ts` — `from`, `expiry`,
  `otp.length`, `otp.maxAttempts`, `template.appName`, `smtp.host`, `smtp.port`.
  **Never `smtp.pass` or `smtp.user`.**
- `packages/auth-provider-sms/src/sms-provider.ts` — `appName`, `expiry`,
  `webOtpDomain`, `otp.*`, plus transport kind via the already-exported
  `isVerificationTransport` (`src/types.ts`). No account SIDs or auth tokens.
- `packages/auth-provider-passkey/src/passkey-provider.ts` — `rpName`, `rpID`,
  `expectedOrigin`, `challengeExpiry`. **Never `challengeSecret`.**

Add a unit test per provider asserting the secret-bearing keys are absent from
`describe().settings`.

## 3. Adapter — `packages/auth-adapter-react-router`

**Package config:** `react` peer dep `>=18`; dev deps `react`, `react-dom`,
`@types/react`, `@types/react-dom`. `tsconfig.json` gains `"jsx": "react-jsx"`
and `"DOM"` in `lib` (currently `["ES2022"]` only, line 5). Add a `"./admin"`
entry to `exports` so `handlers.js` stays React-free.

**New files under `src/admin/`** (a barrel `index.ts` here is fine — 5+ modules):

| File                    | Contents                                                                                       |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| `admin-handlers.ts`     | `createAdminHandlers(auth, options)` → `{ requireAdmin, adminUsersLoader, adminConfigLoader }` |
| `require-admin.ts`      | allowlist matching + forbidden response                                                        |
| `admin-users-page.tsx`  | `<AdminUsersPage>` — table, sortable headers, pagination                                       |
| `admin-config-page.tsx` | `<AdminConfigPage>` — session/abuse/provider sections                                          |
| `admin-layout.tsx`      | shell + Users/Config nav + `<meta robots noindex>` guidance                                    |
| `class-names.ts`        | `AdminClassNames` type + defaults                                                              |
| `admin-styles.ts`       | default `<style>` string, `.auth-admin-*` prefixed                                             |

**Options:**

```ts
export interface AdminOptions {
  /** Delimited allowlist of emails/phones; defaults to process.env.AUTH_ADMIN_IDENTIFIERS */
  admins?:
    | string
    | string[]
    | ((user: AuthUser, identities: Identity[]) => boolean | Promise<boolean>)
  basePath?: string // default "/admin" — used to build sort/page links
  pageSize?: number // default 20, hard max 100
  defaultSort?: { sortBy: string; sortOrder: "asc" | "desc" }
  onForbidden?: "notFound" | "forbidden" | ((request: Request) => Response) // default "notFound"
}
```

`requireAdmin`: signed out → reuse the existing `requireAuth` redirect
(`handlers.ts:194`). Signed in but not allowlisted → throw the `onForbidden`
response. Match against every identity's `identifier` (not just the session one),
splitting the allowlist on `[,\s]+`, case-insensitive for anything containing
`@`, exact for E.164.

**Column config is a component prop, not loader data** — `render`/`href` are
functions and can't cross the JSON boundary:

```ts
export interface AdminMetadataColumn {
  key: string // key in AuthUser.metadata
  label?: string // default: humanized key
  sortable?: boolean // header becomes a sort link
  align?: "start" | "end"
  render?: "text" | "badge" | "code" | "boolean" | "date" | "link"
  href?: (value: unknown, row: AdminUserRow) => string
}
```

Query params reuse ramblefeed's existing scheme — `page`, `limit`, `sortBy`,
`sortOrder` — and the ▼/▲ active-sort glyphs, so its e2e spec changes minimally.
Identities render as a stacked cell: provider badge + identifier + relative last-
used. Truncate passkey identifiers (they're long base64url credential IDs).

Component tests via `react-dom/server.renderToStaticMarkup` — no jsdom needed,
consistent with the package's existing dependency-light vitest setup.

## 4. Example app — `examples/react-router`

- `app/lib/auth.server.ts`: add `listUsers` to the in-memory `userStore`
  (`:48-62`) — sort/slice over the `users` Map — and `findByUserIds` to
  `identityStore` (`:65-99`). Have `create` stamp a little metadata (e.g.
  `firstProvider`) so the metadata-column feature is visible.
- Wire `createAdminHandlers(auth, { admins: process.env.ADMIN_IDENTIFIERS })`.
- Three routes in `app/routes.ts`: `admin`, `admin/users`, `admin/config`.
- `ADMIN_IDENTIFIERS` in `.env.example` and `.env.example.mailpit`.
- New Playwright spec `tests/admin.spec.ts`: non-admin gets 404; admin sees their
  own row with the email identity; config page shows `<redacted>` and no SMTP
  password.

## 5. ramblefeed — `packages/web-app`

- `app/lib/auth.server.ts`: `userStore.listUsers` delegates to the existing
  `userRepository.listAllWithStats` (`app/lib/repositories/user.ts:219`) and maps
  each row into `{ id, metadata: { email, handle, defaultPublic, customDomain,
maxNoteCount, noteCount, tagCount } }`. Its `AdminUserSortField` whitelist
  (`user.ts:42-52`) already covers every sortable column, so `sortBy` passes
  straight through and the `noteCount desc` default is preserved.
  Add `identityRepository.findByUserIds` and wire `identityStore.findByUserIds`.
- Upgrade `@activescott/auth` `^3.1.0` → `^4` (and the provider/adapter packages
  to their matching majors) in `packages/web-app/package.json`. No code change
  falls out of the `describe()` requirement — ramblefeed implements no custom
  `AuthProvider`, only the store interfaces.
- Configure `createAdminHandlers` with `admins: env().ADMIN_EMAILS` and a
  Bootstrap `classNames` map for parity with today's look.
- Rewrite `app/routes/admin.users.tsx`: 231 lines → ~25.
- **Keep** `email` as a metadata column even though identities also show it —
  the existing e2e spec sorts by Email.
- **Unchanged:** `routes/admin.tsx`, `routes/api.admin.backfill-og.ts`, and
  `app/lib/auth-utils.ts:requireAdmin` (those routes need a typed
  `RamblefeedUser`; both read the same `ADMIN_EMAILS`).
- Update `tests/e2e/tests/admin-users-sort.spec.ts` for the new markup. Net gain
  over today's page: an Identities column showing phone/passkey sign-ins and per-
  identity last-used, which ramblefeed has never displayed.

## 6. Docs & commits

`docs/specs/58-admin-dashboard/{plan.md,spec.md,summary.md}` — committed, per
`AGENTS.md`; scrub local paths first. Update the root README features table, the
README's custom-`AuthProvider` section (it must now show `describe()` as a
required member), and the adapter README.

Scoped conventional commits, one PR per scope (never squash a multi-package PR):

1. `feat(auth)!: user listing and config introspection for admin dashboard`
   — `describe()` is now required on `AuthProvider`; major bump.
2. `feat(auth-provider-email)!: describe() for the admin config page`
3. `feat(auth-provider-sms)!: describe() for the admin config page`
4. `feat(auth-provider-passkey)!: describe() for the admin config page`
5. `feat(auth-adapter-react-router): admin users and config pages`
6. `feat(examples): admin dashboard in the example app`
7. ramblefeed: its own PR in that repo, after the packages publish.

Because `describe()` is required, commits 1–4 must land together — core alone on
`main` leaves the providers failing typecheck. In-repo workspaces resolve
locally, so CI is green regardless of ordering; the peer ranges only bite
published consumers. Every package's `@activescott/auth` peer range moves to
`^4`, and the adapter additionally needs the version that ships `./admin`.

## Verification

```bash
# repo root
npm run build && npm run typecheck && npm test && npm run lint

# e2e (packages must be built first)
npm run build --workspace=@activescott/auth \
  --workspace=@activescott/auth-provider-email \
  --workspace=@activescott/auth-provider-sms \
  --workspace=@activescott/auth-provider-passkey \
  --workspace=@activescott/auth-adapter-react-router
npm run e2e -w examples/react-router/tests

# manual
npm run dev   # sign in at /login, then visit /admin/users and /admin/config
```

Checks that matter:

- Signed out → `/admin/users` redirects to `/login?redirectTo=...`.
- Signed in, not in `ADMIN_IDENTIFIERS` → 404.
- Config page: no `JWT_SECRET`, no `smtp.pass`, no Twilio `authToken`, no
  Turnstile `secretKey`, no passkey `challengeSecret`. Grep the rendered HTML for
  the actual `.env` values as the test assertion.
- Users page: sort links round-trip, pagination round-trips, identity last-used
  reflects a fresh sign-in.
- An app whose `UserStore` lacks `listUsers` gets the explanatory error, not a
  crash.
- ramblefeed: all 9 existing columns present, `noteCount desc` still the default
  sort, its e2e spec green.

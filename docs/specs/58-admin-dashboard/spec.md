# Admin dashboard — design notes

Issue #58. Companion to [plan.md](./plan.md); this records the decisions and
the constraints that forced them, rather than the task list.

## The two facts that shaped everything

**The library owns no database.** `UserStore` was `findById` + `create`;
`IdentityStore` had no enumerate. There is no table the library can query on
its own. So the users page cannot exist without the application opting in, and
the opt-in has to be optional — every existing store implementation must keep
compiling.

**Only `Identity` carries timestamps.** `AuthUser` is `{ id, metadata? }`.
`Identity` has `createdAt` and `verifiedAt`, and `verifiedAt` is rewritten on
every successful authentication (`provider-util.ts`, `authenticateWithIdentifier`),
which makes it a real "last used" value. There is no session store, so an
active-sessions view is not possible; identities are the richest thing
available, and they are also the thing no application was displaying.

## Decisions

### Data layer in core, UI in the adapter

`@activescott/auth/admin` gathers the data as plain serializable objects and
knows nothing about React or React Router. `@activescott/auth-adapter-react-router/admin`
renders it. A future Hono or SvelteKit adapter reuses the whole data layer.

Both are subpath exports, following the existing `auth-provider-email/testing`
and `auth-provider-passkey/browser` precedent. The adapter's `.` entry stays
React-free, so apps that never open the dashboard do not pull React through it,
and `react` is declared as an **optional** peer dependency for the same reason.

### Application columns ride on `AuthUser.metadata`

The alternative was a parallel `extraColumns` data API. `metadata` already
exists, is already `Record<string, unknown>`, and is already the place an app
puts its own fields — so `listUsers` returns users whose `metadata` holds
whatever the app wants shown, and `metadataColumns` (a component prop) says how
to display each key. No new data channel.

`sortBy` is a plain string handed to `listUsers` untouched. The library has no
idea which fields a store can sort by, and pretending otherwise would mean
either a registry to keep in sync or a lowest-common-denominator sort. The
store owns the whitelist.

### `AuthProvider.describe()` is required, not optional

Provider configs are `private readonly`, so the config page could otherwise
show only id, name, and routes. Making `describe()` optional would have been
non-breaking, but a provider that silently shows nothing is a worse default
than a compile error telling the author to write one line. It is a breaking
change to the documented extension point and releases as `feat(auth)!`.

Redaction is the provider's job, not the dashboard's. Only the provider knows
that `smtp.host` is fine and `smtp.pass` is not. Each provider omits its
secrets rather than masking them, and each has a test asserting the secret
values do not appear in `describe().settings`.

### Redaction is opt-in, field by field

`Auth.describeConfig()` builds its result field by field instead of copying
`AuthConfig` and deleting the sensitive parts. A field added to `AuthConfig`
later therefore does not appear on the page until someone adds it here — the
failure mode is a missing row, not a leaked secret. (`getSessionConfig()`
returns the raw secret and is deliberately not used.)

`Identity.metadata` never reaches the dashboard at all. It is documented as
possibly sensitive and holds passkey credential public keys; only a
`lastUsedAt` timestamp is derived from it.

### 404, not 403

A signed-in non-admin gets 404. A 403 confirms the admin area exists, which is
exactly what an attacker enumerating URLs wants to learn. This matches what
ramblefeed already did by hand. `onForbidden: "forbidden"` opts into 403.

The allowlist **fails closed**: unset or empty admits nobody. The opposite
default turns a forgotten environment variable into a data leak. Matching runs
against every identity a user owns, not just the session one, so an
allowlisted email still works after signing in by SMS.

### Timestamps are fixed-format UTC

Not `toLocaleString`. These pages are server-rendered and then hydrated; a
locale- or timezone-dependent format produces different text on the server than
in the browser, which React reports as a hydration mismatch. Same reason there
are no relative times ("3 days ago") — they depend on `now()`.

### Styling: inline `CSSProperties`, no stylesheet

The pages have to look presentable with zero configuration ("basically free"),
and they cannot inherit the host application's design system — the example app
is Tailwind, ramblefeed is Bootstrap.

The first attempt injected a `<style>` element holding a CSS string. That was
rejected in review: this is a React package, and a CSS blob in a `.ts` file is
neither typed nor lintable. The built-in look is now
`Record<AdminSlot, CSSProperties>` in `admin-styles.ts`, applied as
`style={...}`.

Two rules a stylesheet gave for free had to be re-expressed:

- **Dark mode.** An inline style cannot hold `@media (prefers-color-scheme)`.
  Solved with the CSS system palette — `Canvas`, `CanvasText`, `GrayText`,
  `LinkText`, `ButtonBorder` — plus `colorScheme: "light dark"` on the
  container. These resolve to the reader's active scheme with no query at all,
  which is what they exist for.
- **Zebra striping.** `tbody tr:nth-child(even)` became `index % 2` in the
  `users.map`, which is the same thing the selector was matching on. The stripe
  color is `color-mix(in srgb, CanvasText 4%, Canvas)` so it adapts too.

What was given up: `:hover`. Sortable headers no longer change color on hover.
Adding it back would mean either a stylesheet or `onMouseEnter` state, and
neither is worth it for an admin page.

`classNames` and the built-in styles are **mutually exclusive per slot**: a slot
the application names gets the class and no inline style. An inline style
outranks any class, so emitting both would silently defeat the app's own rules.
`includeDefaultStyles={false}` drops the built-in look everywhere.

### Identifiers are elided by kind, not by length

Email addresses and E.164 numbers are never shortened however long — they are
what an operator scans the table for, and half an address is useless. Only
opaque identifiers (passkey credential ids, 40+ base64url characters) are
elided, with the full value in the `title`.

## Things deliberately not built

- **Any write action.** v1 is read-only, per the issue. `IdentityStore.delete`
  exists and revoking a lost passkey is the obvious first candidate, but it
  needs a confirm step and CSRF handling the library has no pattern for yet.
- **Search or filtering.** Sorting and paging cover the common case; a search
  box would need another store method and a query contract.
- **An admin index page.** Two pages navigate to each other directly; a landing
  page with counts would need a `countUsers` the stores do not have.
- **A configurable mount path in core.** `/auth/...` stays hardcoded. The admin
  pages are ordinary application routes, so `basePath` is only used to build
  sort and pagination links.

## Verification

Unit: `packages/auth/src/__tests__/admin-data.test.ts` (join, derived
timestamps, metadata never exposed, batch fallback, missing-`listUsers` error,
redaction), per-provider `describe` tests, and
`packages/auth-adapter-react-router/src/__tests__/admin-{handlers,pages}.test.ts`
(allowlist behavior, paging/sort parsing, rendering via
`renderToStaticMarkup` — no jsdom).

E2E: `examples/react-router/tests/admin.spec.ts` — signed-out redirect,
signed-in non-admin 404 asserted on the response status, the users table with
identities, sort links round-tripping, and a config page assertion that the
actual session secret does not appear in the HTML.

One environment note: the e2e port is now `E2E_PORT` (default 3200) because
Playwright's `reuseExistingServer` will happily drive whatever else is
listening on 3200, and the resulting failures look like application bugs.

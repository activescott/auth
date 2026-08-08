import type { AdminMetadataColumn } from "@activescott/auth-adapter-react-router/admin"

/**
 * Columns the admin users page renders from each user's `metadata` — the keys
 * written by `userStore.create` in auth.server.ts.
 *
 * This lives outside `auth.server.ts` because the admin page component reads
 * it, and the component runs in the browser too. Anything a `.server` module
 * exports is server-only, so column configuration has to be its own module.
 *
 * `sortable` only makes the heading a link; whether the sort actually works is
 * up to `UserStore.listUsers`, which receives the key as `sortBy`.
 */
export const adminMetadataColumns: AdminMetadataColumn[] = [
  { key: "identifier", label: "Signed up as", sortable: true },
  { key: "signedUpWith", label: "Via", render: "badge", sortable: true },
  { key: "signedUpAt", label: "Signed up", render: "date", sortable: true },
]

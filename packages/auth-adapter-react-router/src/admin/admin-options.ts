import type { ReactNode } from "react"
import type { AuthUser, Identity } from "@activescott/auth"
import type { AdminUserRow } from "@activescott/auth/admin"

/** Default users per page when the request does not ask for a size */
export const DEFAULT_PAGE_SIZE = 20

/**
 * Largest page a request may ask for. Caps `?limit=` so a caller cannot turn
 * the users page into a full table dump.
 */
export const MAX_PAGE_SIZE = 100

/** Where the admin pages are mounted when `basePath` is not given */
export const DEFAULT_BASE_PATH = "/admin"

/**
 * Decides whether the signed-in user may see the admin pages. Receives every
 * identity the user owns, not just the one they signed in with, so a user
 * allowlisted by email still gets in after signing in by SMS.
 */
export type AdminPredicate = (
  user: AuthUser,
  identities: Identity[],
) => boolean | Promise<boolean>

/**
 * What a signed-in user who is not an admin receives.
 *
 * "notFound" is the default because a 403 confirms the admin area exists;
 * a 404 is indistinguishable from a route that was never there.
 */
export type AdminForbiddenBehavior =
  "notFound" | "forbidden" | ((request: Request) => Response)

/**
 * Options for {@link createAdminHandlers}.
 */
export interface AdminOptions {
  /**
   * Who may view the admin pages. Either a delimited allowlist of identifiers
   * (email addresses and/or E.164 phone numbers, separated by commas or
   * whitespace), an array of them, or a predicate.
   *
   * Defaults to `process.env.AUTH_ADMIN_IDENTIFIERS`. An empty or missing
   * allowlist denies everyone — the pages fail closed, so forgetting to set
   * the variable locks the dashboard rather than opening it.
   */
  admins?: string | string[] | AdminPredicate

  /** Where the pages are mounted; used to build sort and pagination links */
  basePath?: string

  /** Users per page (default 20, capped at 100) */
  pageSize?: number

  /** Sort applied when the request does not specify one */
  defaultSort?: { sortBy?: string; sortOrder?: "asc" | "desc" }

  /** What a non-admin gets (default "notFound") */
  onForbidden?: AdminForbiddenBehavior
}

/**
 * How to render one key of `AuthUser.metadata` as a column.
 *
 * This is how an application puts its own data on the users page: whatever
 * `UserStore.listUsers` writes into each user's `metadata` can be displayed
 * here, without the store interface having to know about it.
 */
export interface AdminMetadataColumn {
  /** Key within `AuthUser.metadata` */
  key: string
  /** Column heading (default: the key, split on camelCase and capitalized) */
  label?: string
  /**
   * Whether the heading links to a sort. The value is passed to
   * `UserStore.listUsers` as `sortBy` verbatim, so the store decides whether
   * it is actually supported.
   */
  sortable?: boolean
  /** Cell alignment; use "end" for numbers (default "start") */
  align?: "start" | "end"
  /** How to display the value (default "text") */
  render?: "text" | "badge" | "code" | "boolean" | "date" | "link"
  /** Destination for `render: "link"` */
  href?: (value: unknown, row: AdminUserRow) => string
  /**
   * Render the cell yourself, for anything the `render` shorthands do not
   * cover. Takes precedence over `render` when both are set.
   *
   * Presentation only — the library still never writes. Put a form here and
   * the mutation is your route's action, not ours.
   */
  renderCell?: (value: unknown, row: AdminUserRow) => ReactNode
}

/**
 * Which of the built-in columns to show. All are on by default; turn one off
 * when the application already supplies an equivalent metadata column — e.g.
 * an app whose own `users` table has a `createdAt` will prefer that over the
 * value derived from identity timestamps.
 */
export interface AdminShowColumns {
  identities?: boolean
  createdAt?: boolean
  lastLoginAt?: boolean
  id?: boolean
}

/**
 * Per-slot class name overrides. A value here replaces the built-in class for
 * that slot rather than adding to it, so an application can dress the pages in
 * its own framework's classes (Bootstrap, Tailwind, ...) with no leftovers.
 *
 * Pair with `includeDefaultStyles={false}` so the built-in stylesheet is not
 * emitted at all.
 */
export interface AdminClassNames {
  container?: string
  header?: string
  title?: string
  nav?: string
  navLink?: string
  tableWrapper?: string
  table?: string
  th?: string
  td?: string
  sortLink?: string
  badge?: string
  code?: string
  muted?: string
  empty?: string
  pagination?: string
  paginationLink?: string
  card?: string
  cardTitle?: string
  definitionList?: string
  definitionTerm?: string
  definitionValue?: string
}

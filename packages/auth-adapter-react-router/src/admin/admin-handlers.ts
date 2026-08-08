import type { Auth, AuthConfigDescription, AuthUser } from "@activescott/auth"
import type { AdminUserRow } from "@activescott/auth/admin"
import { createAdminData } from "@activescott/auth/admin"
import type { AdminOptions } from "./admin-options.js"
import {
  DEFAULT_BASE_PATH,
  DEFAULT_PAGE_SIZE,
  MAX_PAGE_SIZE,
} from "./admin-options.js"
import {
  createAdminPredicate,
  forbiddenResponse,
  loadUserIdentities,
} from "./require-admin.js"

/** Data the users page needs; the shape `adminUsersLoader` returns */
export interface AdminUsersLoaderData {
  users: AdminUserRow[]
  pagination: {
    /** 1-based */
    page: number
    limit: number
    total: number
  }
  sort: {
    sortBy?: string
    sortOrder: "asc" | "desc"
  }
  /** Active filter, parsed from `?filter.<key>=` and passed to the store */
  filter: Record<string, string>
  /**
   * The request's query string, so sort and pagination links can be built by
   * changing only what they own and carrying everything else through. Without
   * it, the first sort click would silently drop an application's own
   * parameters — its status tabs, say.
   */
  searchParams: string
  basePath: string
}

/** Data the config page needs; the shape `adminConfigLoader` returns */
export interface AdminConfigLoaderData {
  config: AuthConfigDescription
  basePath: string
}

/**
 * Loaders and the authorization gate for the admin pages.
 */
export interface AdminHandlers<TUser = AuthUser> {
  /**
   * Throw-or-return gate for admin routes. Throws a redirect to the login page
   * when signed out and the configured forbidden response otherwise.
   *
   * The allowlist check reads the session through `Auth.verifySession`, which
   * caches for two minutes — so removing someone from the allowlist, or
   * deleting the identity that matched it, can take that long to shut them
   * out. Anything needing immediate revocation should enforce it in the
   * `requireAuth` you pass in, which runs first and is yours to make
   * uncached.
   */
  requireAdmin: (request: Request) => Promise<TUser>
  adminUsersLoader: (context: {
    request: Request
  }) => Promise<AdminUsersLoaderData>
  adminConfigLoader: (context: {
    request: Request
  }) => Promise<AdminConfigLoaderData>
}

/**
 * Create the admin dashboard's loaders for a React Router app.
 *
 * The loaders gate themselves, so a route only has to call one:
 *
 * @example
 * ```tsx
 * // app/lib/auth.server.ts
 * export const { requireAdmin, adminUsersLoader } = createAdminHandlers(auth, {
 *   requireAuth,
 *   admins: process.env.ADMIN_EMAILS,
 * })
 *
 * // app/routes/admin.users.tsx
 * export const loader = ({ request }: Route.LoaderArgs) =>
 *   adminUsersLoader({ request })
 *
 * export default function AdminUsers({ loaderData }: Route.ComponentProps) {
 *   return <AdminUsersPage data={loaderData} />
 * }
 * ```
 *
 * @param auth - The configured Auth instance
 * @param options - Authorization and paging options, plus the app's
 *   `requireAuth` so signed-out visitors are redirected exactly as they are
 *   everywhere else in the app
 */
export function createAdminHandlers<TUser = AuthUser>(
  auth: Auth,
  options: AdminOptions & {
    /** The app's `requireAuth` from `createAuthHandlers` */
    requireAuth: (request: Request) => Promise<TUser>
  },
): AdminHandlers<TUser> {
  const {
    requireAuth,
    basePath = DEFAULT_BASE_PATH,
    pageSize = DEFAULT_PAGE_SIZE,
    defaultSort,
    onForbidden = "notFound",
  } = options

  const isAdmin = createAdminPredicate(options.admins)
  const adminData = createAdminData(auth)

  async function requireAdmin(request: Request): Promise<TUser> {
    // Signed-out visitors are redirected by requireAuth (which throws), so
    // only signed-in-but-unauthorized reaches the check below.
    const user = await requireAuth(request)
    const authUser = await currentAuthUser(auth, request)
    if (!authUser) throw forbiddenResponse(onForbidden, request)

    const identities = await loadUserIdentities(auth, authUser)
    if (!(await isAdmin(authUser, identities))) {
      throw forbiddenResponse(onForbidden, request)
    }
    return user
  }

  return {
    requireAdmin,

    async adminUsersLoader({ request }): Promise<AdminUsersLoaderData> {
      await requireAdmin(request)

      const url = new URL(request.url)
      const limit = readLimit(url.searchParams.get("limit"), pageSize)
      const page = readPage(url.searchParams.get("page"))
      const sortBy = url.searchParams.get("sortBy") ?? defaultSort?.sortBy
      const sortOrder = readSortOrder(
        url.searchParams.get("sortOrder"),
        defaultSort?.sortOrder,
      )

      const filter = readFilter(url.searchParams)

      const { users, total } = await adminData.listUsers({
        limit,
        offset: (page - 1) * limit,
        sortBy: sortBy ?? undefined,
        sortOrder,
        // Omitted rather than passed as an empty object, so a store can treat
        // "no filter" as `filter === undefined`
        ...(Object.keys(filter).length > 0 ? { filter } : {}),
      })

      return {
        users,
        pagination: { page, limit, total },
        sort: { sortBy: sortBy ?? undefined, sortOrder },
        filter,
        searchParams: url.searchParams.toString(),
        basePath,
      }
    },

    async adminConfigLoader({ request }): Promise<AdminConfigLoaderData> {
      await requireAdmin(request)
      return { config: adminData.describeConfig(), basePath }
    },
  }
}

/**
 * The unmapped `AuthUser` for the request. `requireAuth` returns the
 * application's own user type, which may not carry the fields the allowlist
 * check needs, so read the session again for the library's own record.
 */
async function currentAuthUser(
  auth: Auth,
  request: Request,
): Promise<AuthUser | null> {
  const session = await auth.verifySession(request)
  return session?.user ?? null
}

function readPage(value: string | null): number {
  const page = Number(value)
  return Number.isInteger(page) && page > 0 ? page : 1
}

function readLimit(value: string | null, fallback: number): number {
  const limit = Number(value)
  const requested = Number.isInteger(limit) && limit > 0 ? limit : fallback
  return Math.min(requested, MAX_PAGE_SIZE)
}

function readSortOrder(
  value: string | null,
  fallback: "asc" | "desc" | undefined,
): "asc" | "desc" {
  if (value === "asc" || value === "desc") return value
  return fallback ?? "desc"
}

/** Prefix marking a query parameter as filter criteria for the store */
const FILTER_PREFIX = "filter."

/**
 * Collect `?filter.<key>=<value>` parameters into the object handed to
 * `listUsers`. The prefix keeps application filter keys from colliding with
 * `page`, `limit`, `sortBy`, and `sortOrder`, and means no key has to be
 * registered anywhere — which key names mean anything is the store's business,
 * exactly as it is for `sortBy`.
 */
function readFilter(searchParams: URLSearchParams): Record<string, string> {
  const filter: Record<string, string> = {}
  for (const [key, value] of searchParams) {
    if (!key.startsWith(FILTER_PREFIX)) continue
    const name = key.slice(FILTER_PREFIX.length)
    if (name.length > 0) filter[name] = value
  }
  return filter
}

import type { CSSProperties, ReactNode } from "react"
import type { AdminIdentityRow, AdminUserRow } from "@activescott/auth/admin"
import type { AdminUsersLoaderData } from "./admin-handlers.js"
import type { AdminMetadataColumn, AdminShowColumns } from "./admin-options.js"
import type {
  AdminLinkComponent,
  AdminPresentationProps,
} from "./admin-layout.js"
import { AdminLayout, AdminLink } from "./admin-layout.js"
import type { AdminStyler } from "./admin-styles.js"
import {
  createStyler,
  IDENTITY_STYLE,
  STRIPED_ROW_STYLE,
} from "./admin-styles.js"
import {
  elideIdentifier,
  formatTimestamp,
  formatValue,
  humanizeKey,
} from "./format.js"

/** Sort keys for the built-in columns, passed to the store as `sortBy` */
export const SORT_CREATED_AT = "createdAt"
export const SORT_LAST_LOGIN_AT = "lastLoginAt"

const ASCENDING_GLYPH = "▲"
const DESCENDING_GLYPH = "▼"
const EMPTY_CELL = "—"

const ALIGN_END: CSSProperties = { textAlign: "right" }
const NOWRAP: CSSProperties = { whiteSpace: "nowrap" }

export interface AdminUsersPageProps extends AdminPresentationProps {
  /** Whatever `adminUsersLoader` returned */
  data: AdminUsersLoaderData
  /**
   * Columns rendered from each user's `metadata`, in display order. They come
   * before the built-in columns.
   */
  metadataColumns?: AdminMetadataColumn[]
  /** Built-in columns to show; all are on by default */
  showColumns?: AdminShowColumns
  /**
   * Render a trailing actions column. Supply it and each row gets your
   * content — typically a `<Form method="post">` posting to your own route's
   * action.
   *
   * This is presentation only: the page stays read-only, and the mutation is
   * your action, your validation, your audit trail. The library never writes.
   */
  rowActions?: (row: AdminUserRow) => ReactNode
  /** Heading for the `rowActions` column (default "Actions") */
  rowActionsLabel?: string
  /** Page heading (default "Users") */
  title?: string
}

/**
 * The admin users table: every user, the identities they can sign in with,
 * when they joined, and when they last authenticated — plus any columns the
 * application supplies through `metadata`.
 *
 * Sorting and paging are links, not client state, so the page works with
 * JavaScript disabled and every view is a shareable URL. Sort keys are handed
 * to `UserStore.listUsers` verbatim; a store that does not recognize one
 * decides for itself what to do.
 */
export function AdminUsersPage({
  data,
  metadataColumns = [],
  showColumns,
  rowActions,
  rowActionsLabel = "Actions",
  title = "Users",
  classNames,
  includeDefaultStyles = true,
  linkComponent,
  navExtra,
}: AdminUsersPageProps) {
  const ui = createStyler(classNames, includeDefaultStyles)
  const show = {
    identities: showColumns?.identities ?? true,
    createdAt: showColumns?.createdAt ?? true,
    lastLoginAt: showColumns?.lastLoginAt ?? true,
    id: showColumns?.id ?? true,
  }
  const { users, pagination, sort, basePath } = data
  // Striping is part of the built-in look, so it goes away with it.
  const striped = ui.style("table") !== undefined

  return (
    <AdminLayout
      title={title}
      basePath={basePath}
      current="users"
      classNames={classNames}
      includeDefaultStyles={includeDefaultStyles}
      linkComponent={linkComponent}
      navExtra={navExtra}
    >
      <p className={ui.className("muted")} style={ui.style("muted")}>
        {pagination.total} {pagination.total === 1 ? "user" : "users"}
      </p>

      {users.length === 0 ? (
        <div className={ui.className("empty")} style={ui.style("empty")}>
          No users found.
        </div>
      ) : (
        <div
          className={ui.className("tableWrapper")}
          style={ui.style("tableWrapper")}
        >
          <table className={ui.className("table")} style={ui.style("table")}>
            <thead>
              <tr>
                {metadataColumns.map((column) => (
                  <Header
                    key={column.key}
                    label={column.label ?? humanizeKey(column.key)}
                    sortBy={column.sortable ? column.key : undefined}
                    align={column.align}
                    data={data}
                    ui={ui}
                    linkComponent={linkComponent}
                  />
                ))}
                {show.identities ? (
                  <Header
                    label="Identities"
                    data={data}
                    ui={ui}
                    linkComponent={linkComponent}
                  />
                ) : null}
                {show.createdAt ? (
                  <Header
                    label="Created"
                    sortBy={SORT_CREATED_AT}
                    data={data}
                    ui={ui}
                    linkComponent={linkComponent}
                  />
                ) : null}
                {show.lastLoginAt ? (
                  <Header
                    label="Last login"
                    sortBy={SORT_LAST_LOGIN_AT}
                    data={data}
                    ui={ui}
                    linkComponent={linkComponent}
                  />
                ) : null}
                {show.id ? (
                  <Header
                    label="User ID"
                    data={data}
                    ui={ui}
                    linkComponent={linkComponent}
                  />
                ) : null}
                {rowActions ? (
                  <Header
                    label={rowActionsLabel}
                    data={data}
                    ui={ui}
                    linkComponent={linkComponent}
                  />
                ) : null}
              </tr>
            </thead>
            <tbody>
              {users.map((user, index) => (
                <tr
                  key={user.id}
                  // Zebra striping without a `:nth-child` rule. `index` is the
                  // row's position on the rendered page, which is exactly what
                  // the CSS selector would have matched on.
                  style={
                    striped && index % 2 === 1 ? STRIPED_ROW_STYLE : undefined
                  }
                >
                  {metadataColumns.map((column) => (
                    <Cell key={column.key} ui={ui} align={column.align}>
                      <MetadataCell
                        column={column}
                        row={user}
                        ui={ui}
                        linkComponent={linkComponent}
                      />
                    </Cell>
                  ))}
                  {show.identities ? (
                    <Cell ui={ui}>
                      <IdentityList identities={user.identities} ui={ui} />
                    </Cell>
                  ) : null}
                  {show.createdAt ? (
                    <Cell ui={ui}>
                      <Timestamp value={user.createdAt} ui={ui} />
                    </Cell>
                  ) : null}
                  {show.lastLoginAt ? (
                    <Cell ui={ui}>
                      <Timestamp value={user.lastLoginAt} ui={ui} />
                    </Cell>
                  ) : null}
                  {show.id ? (
                    <Cell ui={ui}>
                      <code
                        className={ui.className("code")}
                        style={ui.style("code")}
                        title={user.id}
                      >
                        {elideIdentifier(user.id)}
                      </code>
                    </Cell>
                  ) : null}
                  {rowActions ? <Cell ui={ui}>{rowActions(user)}</Cell> : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Pagination data={data} ui={ui} linkComponent={linkComponent} />
    </AdminLayout>
  )
}

interface CellProps {
  ui: AdminStyler
  align?: "start" | "end"
  children: ReactNode
}

/**
 * A table cell. Alignment applies whether or not the built-in look is in use —
 * it is layout the column asked for, not decoration.
 */
function Cell({ ui, align, children }: CellProps) {
  return (
    <td
      className={ui.className("td")}
      style={
        align === "end" ? { ...ui.style("td"), ...ALIGN_END } : ui.style("td")
      }
    >
      {children}
    </td>
  )
}

interface HeaderProps {
  label: string
  /** Omit to render a plain, unsortable heading */
  sortBy?: string
  align?: "start" | "end"
  data: AdminUsersLoaderData
  ui: AdminStyler
  linkComponent?: AdminLinkComponent
}

/**
 * A column heading. Sortable headings link to the same page with `sortBy` set;
 * clicking the active column flips the direction.
 */
function Header({
  label,
  sortBy,
  align,
  data,
  ui,
  linkComponent,
}: HeaderProps) {
  const style =
    align === "end" ? { ...ui.style("th"), ...ALIGN_END } : ui.style("th")

  if (!sortBy) {
    return (
      <th className={ui.className("th")} style={style}>
        {label}
      </th>
    )
  }

  const isActive = data.sort.sortBy === sortBy
  const nextOrder = isActive && data.sort.sortOrder === "desc" ? "asc" : "desc"

  return (
    <th
      className={ui.className("th")}
      style={style}
      aria-sort={
        isActive
          ? data.sort.sortOrder === "asc"
            ? "ascending"
            : "descending"
          : undefined
      }
    >
      <AdminLink
        to={sortHref(data, sortBy, nextOrder)}
        slot="sortLink"
        ui={ui}
        linkComponent={linkComponent}
      >
        {label}
        {isActive ? (
          // Decorative: `aria-sort` on the header already states the
          // direction, so the glyph would only repeat it to a screen reader —
          // and it would land inside the header's accessible name.
          <span aria-hidden="true">
            {" "}
            {data.sort.sortOrder === "asc" ? ASCENDING_GLYPH : DESCENDING_GLYPH}
          </span>
        ) : null}
      </AdminLink>
    </th>
  )
}

/**
 * Both link builders start from the request's own query string and change only
 * what they own, so anything else the application put there — status tabs, a
 * `filter.*` key, a return path — survives the click. Rebuilding the query
 * from scratch would drop those silently, which is the kind of bug that only
 * shows up after someone adds a tab.
 */
function linkParams(data: AdminUsersLoaderData): URLSearchParams {
  return new URLSearchParams(data.searchParams)
}

/**
 * Sorting returns to page 1: the row that was on page 3 under the old order is
 * almost never on page 3 under the new one, so keeping the page number would
 * land the reader somewhere arbitrary.
 */
function sortHref(
  data: AdminUsersLoaderData,
  sortBy: string,
  sortOrder: "asc" | "desc",
): string {
  const params = linkParams(data)
  params.set("sortBy", sortBy)
  params.set("sortOrder", sortOrder)
  params.delete("page")
  return `${data.basePath}/users?${params.toString()}`
}

function pageHref(data: AdminUsersLoaderData, page: number): string {
  const params = linkParams(data)
  params.set("page", String(page))
  return `${data.basePath}/users?${params.toString()}`
}

interface PaginationProps {
  data: AdminUsersLoaderData
  ui: AdminStyler
  linkComponent?: AdminLinkComponent
}

function Pagination({ data, ui, linkComponent }: PaginationProps) {
  const { page, limit, total } = data.pagination
  const lastPage = Math.max(1, Math.ceil(total / limit))
  if (lastPage === 1) return null

  return (
    <nav className={ui.className("pagination")} style={ui.style("pagination")}>
      {page > 1 ? (
        <AdminLink
          to={pageHref(data, page - 1)}
          slot="paginationLink"
          ui={ui}
          linkComponent={linkComponent}
        >
          ← Previous
        </AdminLink>
      ) : null}
      <span className={ui.className("muted")} style={ui.style("muted")}>
        Page {page} of {lastPage}
      </span>
      {page < lastPage ? (
        <AdminLink
          to={pageHref(data, page + 1)}
          slot="paginationLink"
          ui={ui}
          linkComponent={linkComponent}
        >
          Next →
        </AdminLink>
      ) : null}
    </nav>
  )
}

interface IdentityListProps {
  identities: AdminIdentityRow[]
  ui: AdminStyler
}

/**
 * Every way a user can sign in, one per line: the provider, the identifier,
 * and when that identity was last used.
 */
function IdentityList({ identities, ui }: IdentityListProps) {
  if (identities.length === 0) {
    return (
      <span className={ui.className("muted")} style={ui.style("muted")}>
        {EMPTY_CELL}
      </span>
    )
  }

  return (
    <>
      {identities.map((identity) => {
        const lastUsed = formatTimestamp(
          identity.lastUsedAt ?? identity.verifiedAt,
        )
        return (
          <div style={IDENTITY_STYLE} key={identity.id}>
            <span className={ui.className("badge")} style={ui.style("badge")}>
              {identity.provider}
            </span>{" "}
            <span title={identity.identifier}>
              {elideIdentifier(identity.identifier)}
            </span>
            {lastUsed ? (
              <>
                {" "}
                <span
                  className={ui.className("muted")}
                  style={{ ...ui.style("muted"), ...NOWRAP }}
                >
                  last used {lastUsed}
                </span>
              </>
            ) : null}
          </div>
        )
      })}
    </>
  )
}

interface TimestampProps {
  value: string | undefined
  ui: AdminStyler
}

function Timestamp({ value, ui }: TimestampProps) {
  const formatted = formatTimestamp(value)
  if (!formatted) {
    return (
      <span className={ui.className("muted")} style={ui.style("muted")}>
        {EMPTY_CELL}
      </span>
    )
  }
  return (
    <span style={NOWRAP} title={value}>
      {formatted}
    </span>
  )
}

interface MetadataCellProps {
  column: AdminMetadataColumn
  row: AdminUserRow
  ui: AdminStyler
  linkComponent?: AdminLinkComponent
}

/**
 * One application-supplied value, displayed according to the column's
 * `render`. Unset values become a muted placeholder rather than "undefined".
 */
function MetadataCell({
  column,
  row,
  ui,
  linkComponent,
}: MetadataCellProps): ReactNode {
  const value = row.metadata[column.key]

  // The application's own renderer wins: it was given the value and the row,
  // and anything it returns is more specific than a shorthand.
  if (column.renderCell) return column.renderCell(value, row)

  if (column.render === "date") {
    return (
      <Timestamp
        value={typeof value === "string" ? value : undefined}
        ui={ui}
      />
    )
  }

  const text = formatValue(value)
  if (text === null || text === "") {
    return (
      <span className={ui.className("muted")} style={ui.style("muted")}>
        {EMPTY_CELL}
      </span>
    )
  }

  switch (column.render) {
    case "badge":
      return (
        <span className={ui.className("badge")} style={ui.style("badge")}>
          {text}
        </span>
      )
    case "code":
      return (
        <code className={ui.className("code")} style={ui.style("code")}>
          {text}
        </code>
      )
    case "boolean":
      return (
        <span className={ui.className("badge")} style={ui.style("badge")}>
          {value ? "Yes" : "No"}
        </span>
      )
    case "link":
      return column.href ? (
        <AdminLink
          to={column.href(value, row)}
          slot="navLink"
          ui={ui}
          linkComponent={linkComponent}
        >
          {text}
        </AdminLink>
      ) : (
        text
      )
    default:
      return text
  }
}

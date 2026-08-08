import type { ComponentType, CSSProperties, ReactNode } from "react"
import type { AdminClassNames } from "./admin-options.js"
import type { AdminStyler } from "./admin-styles.js"
import { createStyler } from "./admin-styles.js"

/**
 * A router-aware link component, e.g. React Router's `Link`. Pass one to get
 * client-side navigation for sort and pagination links; omit it and the pages
 * use plain anchors, which navigate the whole document.
 *
 * Typed structurally rather than imported from `react-router` on purpose: this
 * package imports nothing from the router, which is why one build serves both
 * v7 and v8.
 */
export type AdminLinkComponent = ComponentType<{
  to: string
  className?: string
  style?: CSSProperties
  children: ReactNode
}>

/** Props every admin page accepts for appearance and navigation */
export interface AdminPresentationProps {
  /**
   * Your own class for any slot you name. A slot you give a class to gets no
   * built-in styling, so your design system's rules are not competing with an
   * inline style they cannot outrank.
   */
  classNames?: AdminClassNames
  /**
   * Apply the built-in look to slots you have not overridden (default true).
   * Set false to render structural markup only.
   */
  includeDefaultStyles?: boolean
  /** Router link component for client-side navigation */
  linkComponent?: AdminLinkComponent
  /**
   * Extra nav content, rendered after the built-in Users/Configuration links.
   * For applications that mount these pages inside an admin area of their own
   * and want a way back to it.
   */
  navExtra?: ReactNode
}

export interface AdminLayoutProps extends AdminPresentationProps {
  title: string
  /** Where the admin pages are mounted, for the nav links */
  basePath: string
  /** Which nav entry is the current page */
  current: "users" | "config"
  children: ReactNode
}

/**
 * Shell shared by the admin pages: heading and nav between Users and Config.
 *
 * It renders no `<head>` content — a React Router app owns the document — so
 * add `<meta name="robots" content="noindex, nofollow">` in your route's
 * `meta()` export if the pages are reachable without authentication errors
 * being obvious to a crawler.
 */
export function AdminLayout({
  title,
  basePath,
  current,
  classNames,
  includeDefaultStyles = true,
  linkComponent,
  navExtra,
  children,
}: AdminLayoutProps) {
  const ui = createStyler(classNames, includeDefaultStyles)

  return (
    <div className={ui.className("container")} style={ui.style("container")}>
      <header className={ui.className("header")} style={ui.style("header")}>
        <h1 className={ui.className("title")} style={ui.style("title")}>
          {title}
        </h1>
        <nav className={ui.className("nav")} style={ui.style("nav")}>
          {current === "users" ? null : (
            <AdminLink
              to={`${basePath}/users`}
              ui={ui}
              slot="navLink"
              linkComponent={linkComponent}
            >
              Users
            </AdminLink>
          )}
          {current === "config" ? null : (
            <AdminLink
              to={`${basePath}/config`}
              ui={ui}
              slot="navLink"
              linkComponent={linkComponent}
            >
              Configuration
            </AdminLink>
          )}
          {navExtra}
        </nav>
      </header>
      {children}
    </div>
  )
}

export interface AdminLinkProps {
  to: string
  /** Styling slot to draw the class/style from; omit for an unstyled link */
  slot?: "navLink" | "paginationLink" | "sortLink"
  ui: AdminStyler
  linkComponent?: AdminLinkComponent
  children: ReactNode
}

/**
 * Render a link through the supplied router component, or a plain anchor when
 * there is none.
 */
export function AdminLink({
  to,
  slot,
  ui,
  linkComponent: Link,
  children,
}: AdminLinkProps) {
  const className = slot ? ui.className(slot) : undefined
  const style = slot ? ui.style(slot) : undefined

  if (Link) {
    return (
      <Link to={to} className={className} style={style}>
        {children}
      </Link>
    )
  }
  return (
    <a href={to} className={className} style={style}>
      {children}
    </a>
  )
}

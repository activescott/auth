import { Link } from "react-router"

/**
 * A tab in a link-based tab bar. Tabs are plain links (`/login`,
 * `/login?via=sms`) rather than client state so the active tab survives
 * the full-page round trip through the auth routes.
 */
export function TabLink({
  to,
  active,
  children,
}: {
  to: string
  active: boolean
  children: string
}) {
  return (
    <Link
      to={to}
      className={
        active
          ? "pb-2 border-b-2 border-blue-600 font-semibold text-blue-600"
          : "pb-2 text-gray-500 hover:text-gray-800"
      }
    >
      {children}
    </Link>
  )
}

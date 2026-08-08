/**
 * The admin users page, in full. Everything visible — the table, sorting,
 * paging, the identity column — comes from the adapter; this file wires the
 * loader to the component and adds two app-owned touches:
 *
 * - tabs that filter by sign-in method, using `?filter.signedUpWith=`. The
 *   library passes that straight to `userStore.listUsers`, so the count and
 *   the pager describe the filtered set rather than one fetched page.
 * - `Link` as `linkComponent`, so sort and pagination links navigate
 *   client-side. Leave it out and the page still works with plain anchors.
 */
import { Link } from "react-router"
import { adminUsersLoader } from "~/lib/auth.server"
import { adminMetadataColumns } from "~/lib/admin-columns"
import { AdminUsersPage } from "@activescott/auth-adapter-react-router/admin"
import type { Route } from "./+types/admin.users"

export function meta() {
  return [
    { title: "Users · Admin" },
    { name: "robots", content: "noindex, nofollow" },
  ]
}

export function loader({ request }: Route.LoaderArgs) {
  return adminUsersLoader({ request })
}

const TABS = [
  { label: "All", provider: undefined },
  { label: "Email", provider: "email" },
  { label: "SMS", provider: "sms" },
]

export default function AdminUsers({ loaderData }: Route.ComponentProps) {
  const active = loaderData.filter.signedUpWith

  return (
    <AdminUsersPage
      data={loaderData}
      metadataColumns={adminMetadataColumns}
      linkComponent={Link}
      navExtra={TABS.map((tab) => (
        <Link
          key={tab.label}
          to={
            tab.provider
              ? `/admin/users?filter.signedUpWith=${tab.provider}`
              : "/admin/users"
          }
          style={{ fontWeight: active === tab.provider ? 700 : 400 }}
        >
          {tab.label}
        </Link>
      ))}
    />
  )
}

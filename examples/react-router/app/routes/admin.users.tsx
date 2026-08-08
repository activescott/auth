/**
 * The admin users page, in full. Everything visible — the table, sorting,
 * paging, the identity column — comes from the adapter; this file only wires
 * the loader to the component.
 *
 * `Link` is passed through so sort and pagination links navigate client-side.
 * Leave it out and the page still works, using plain anchors.
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

export default function AdminUsers({ loaderData }: Route.ComponentProps) {
  return (
    <AdminUsersPage
      data={loaderData}
      metadataColumns={adminMetadataColumns}
      linkComponent={Link}
    />
  )
}
